package dom

import (
	"DORM/sitemapper"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// ==============================================================================
// DOM-Crawler Engine — SPA-Aware BFS Browser Crawler
// ==============================================================================
//
// Design Contract (Race-Free):
//   - DOMCrawler NEVER writes to sitemapper.SiteMap during execution.
//   - All output goes to an isolated DOMResult (its own memory region).
//   - MergeInto(sm) is called AFTER both crawlers finish (in handlers.go),
//     under a single mutex — zero concurrent writes to shared state.
//
// Concurrency Model:
//   - BFS queue is processed sequentially (one page at a time) to keep a single
//     browser tab alive per page — chromedp tabs are not goroutine-safe.
//   - XHR interception and DOM snapshot happen inside the same tab context.
//   - DOMResult fields are protected by DOMResult.mu for future goroutine use.
// ==============================================================================

// spaRouteInjectScript is injected into every page to intercept client-side
// navigation events from React Router, Vue Router, Angular Router, etc.
const spaRouteInjectScript = `
(function() {
  if (window.__dormRoutesInstalled) return;
  window.__dormRoutesInstalled = true;
  window.__dormRoutes = [];
  window.__dormXHR = [];

  // Intercept history.pushState
  var _push = history.pushState.bind(history);
  history.pushState = function(state, title, url) {
    _push(state, title, url);
    if (url) window.__dormRoutes.push(String(url));
  };

  // Intercept history.replaceState
  var _replace = history.replaceState.bind(history);
  history.replaceState = function(state, title, url) {
    _replace(state, title, url);
    if (url) window.__dormRoutes.push(String(url));
  };

  // Intercept hash changes
  window.addEventListener('hashchange', function() {
    window.__dormRoutes.push(window.location.href);
  });
})();
`

// clickSelectors defines the ordered priority list of CSS selectors for
// interactive elements the crawler will click. Most-significant-first.
var clickSelectors = []string{
	"nav a[href]",            // navigation links
	"[role='navigation'] a",  // ARIA navigation
	"button:not([disabled])", // active buttons
	"[role='button']",        // ARIA buttons
	"[data-action]",          // data attribute actions
	"[data-route]",           // data route attributes
	"[aria-expanded='false']",// collapsed accordions / dropdowns
	".tab:not(.active)",      // tab components
	".nav-item a",            // Bootstrap-style nav items
	"[data-toggle]",          // Bootstrap toggles
}

// DOMCrawler performs SPA-aware BFS crawling using a real browser (chromedp).
type DOMCrawler struct {
	baseURL *url.URL
	cfg     DOMConfig
	session *Session
	visited sync.Map // map[string]bool — visited URLs/routes
	result  *DOMResult

	// xhrMu protects the XHR listener map (chromedp event listeners are not
	// goroutine-safe when the tab context is shared)
	xhrMu sync.Mutex
}

// queueItem is a BFS work unit.
type queueItem struct {
	rawURL string
	depth  int
}

// Crawl runs the full DOM-Crawler pipeline and returns an isolated DOMResult.
// It is safe to call concurrently with sitemapper.Run() because it writes
// only to DOMResult, never to a shared SiteMap.
//
// ctx should carry a deadline matching DOMConfig.BrowserTimeout.
func Crawl(ctx context.Context, targetURL string, cfg DOMConfig) (*DOMResult, error) {
	result := &DOMResult{}

	// Normalise URL
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}
	base, err := url.Parse(targetURL)
	if err != nil {
		return result, fmt.Errorf("dom.Crawl: invalid URL %q: %w", targetURL, err)
	}

	// Apply BrowserTimeout as the outer deadline
	crawlCtx, crawlCancel := context.WithTimeout(ctx, cfg.BrowserTimeout)
	defer crawlCancel()

	// Start browser session — graceful fallback if Chrome not available
	session, err := NewSession(crawlCtx, cfg)
	if err != nil {
		return result, fmt.Errorf("dom.Crawl: browser unavailable: %w", err)
	}
	defer session.Close()

	c := &DOMCrawler{
		baseURL: base,
		cfg:     cfg,
		session: session,
		result:  result,
	}

	// Seed BFS queue
	queue := []queueItem{{rawURL: targetURL, depth: 0}}

	fmt.Printf("[DOM-Crawler] Starting BFS for %s (maxDepth=%d, maxPages=%d)\n",
		targetURL, cfg.MaxDepth, cfg.MaxPages)

	for len(queue) > 0 {
		// Respect context cancellation (outer scan stop signal)
		select {
		case <-crawlCtx.Done():
			fmt.Printf("[DOM-Crawler] Context cancelled — stopping early\n")
			return result, nil
		default:
		}

		// Page cap
		if cfg.MaxPages > 0 && result.pageCount() >= cfg.MaxPages {
			fmt.Printf("[DOM-Crawler] Page cap (%d) reached\n", cfg.MaxPages)
			break
		}

		// Dequeue
		item := queue[0]
		queue = queue[1:]

		// Depth check
		if item.depth >= cfg.MaxDepth {
			continue
		}

		// Visited check (atomic LoadOrStore)
		normalized := normalizeURL(item.rawURL)
		if _, loaded := c.visited.LoadOrStore(normalized, true); loaded {
			continue
		}

		// Crawl the page and collect new links
		newLinks, err := c.visitPage(crawlCtx, item.rawURL, item.depth)
		if err != nil {
			c.emit(EventError, item.rawURL, "", "", err.Error(), item.depth)
			result.logError(fmt.Sprintf("[DOM-Crawler] %s: %v", item.rawURL, err))
			continue
		}

		// Enqueue discovered links
		for _, link := range newLinks {
			if c.inScope(link) {
				queue = append(queue, queueItem{rawURL: link, depth: item.depth + 1})
			}
		}
	}

	fmt.Printf("[DOM-Crawler] Done — pages=%d endpoints=%d xhr=%d routes=%d\n",
		len(result.Pages), len(result.Endpoints), len(result.XHREndpoints), len(result.JSRoutes))

	c.emit(EventDone, "", "", "", "Crawl completed", 0)
	return result, nil
}

// visitPage navigates to a single URL, injects monitoring scripts, waits for
// the SPA to render, clicks interactive elements, and extracts all discovered data.
// Returns a deduplicated list of new in-scope URLs to enqueue.
func (c *DOMCrawler) visitPage(ctx context.Context, rawURL string, depth int) ([]string, error) {
	pageCtx, pageCancel := context.WithTimeout(c.session.AllocContext(), c.cfg.PageTimeout)
	defer pageCancel()

	tabCtx, tabCancel := c.session.NewTab(pageCtx)
	defer tabCancel()

	// ── XHR / Network Interception ────────────────────────────────────────────
	// Listen for network requests initiated by the page BEFORE navigation.
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		if req, ok := ev.(*network.EventRequestWillBeSent); ok {
			reqURL := req.Request.URL
			if c.isCapturableRequest(reqURL) {
				// Parse payload parameters if it's a POST/PUT
				var params []string
				if req.Request.HasPostData {
					// We just record that there's a payload. DORM's plugin engine
					// will fuzz this endpoint heavily since it's an API.
					params = append(params, "raw_payload")
				}
				
				// Add as a full Endpoint so engine plugins get the CORRECT Method (not just GET)
				c.result.addEndpoint(sitemapper.Endpoint{
					URL:    reqURL,
					Method: req.Request.Method,
					Params: params,
					Source: "dom_xhr",
				})

				// Emit for the live feed (label = Method, detail = network intercept)
				c.emit(EventXHR, reqURL, "", req.Request.Method, fmt.Sprintf("network intercept (%s)", req.Request.Method), depth)
			}
		}
	})

	// ── Navigate ────────────────────────────────────────────────────────────
	c.emit(EventNavigate, rawURL, "", "", fmt.Sprintf("depth=%d", depth), depth)
	actions := chromedp.Tasks{
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(spaRouteInjectScript).Do(ctx)
			return err
		}),
		chromedp.Navigate(rawURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
	}

	if err := chromedp.Run(tabCtx, actions); err != nil {
		return nil, fmt.Errorf("navigate %s: %w", rawURL, err)
	}

	// Wait for network to settle (SPA data fetches)
	if c.cfg.WaitForNetworkIdle {
		// Simple heuristic: wait a fixed interval for XHR activity
		select {
		case <-time.After(c.cfg.NetworkIdleTimeout):
		case <-tabCtx.Done():
		}
	}

	// ── Inject Extra Headers (reflected in future tab requests) ──────────────
	// (Headers set via CDP apply to the current navigation context)

	// ── DOM Snapshot ──────────────────────────────────────────────────────────
	var outerHTML string
	if err := chromedp.Run(tabCtx,
		chromedp.OuterHTML("html", &outerHTML, chromedp.ByQuery),
	); err != nil {
		outerHTML = ""
	}

	// Get final URL (may differ from rawURL after SPA redirects)
	var currentURL string
	if err := chromedp.Run(tabCtx,
		chromedp.Location(&currentURL),
	); err != nil {
		currentURL = rawURL
	}

	// ── Collect SPA Routes from injected script ───────────────────────────────
	var routesJSON string
	_ = chromedp.Run(tabCtx,
		chromedp.Evaluate(`JSON.stringify(window.__dormRoutes || [])`, &routesJSON),
	)
	if routesJSON != "" {
		var routes []string
		if err := json.Unmarshal([]byte(routesJSON), &routes); err == nil {
			for _, r := range routes {
				if abs := c.resolveURL(r); abs != "" {
					c.result.addJSRoute(r)
					c.emit(EventSPARoute, abs, "", r, "history.pushState", depth)
				}
			}
		}
	}

	// ── Click Interactive Elements ───────────────────────────────────────────────
	var clickDiscoveredLinks []string
	if c.cfg.ClickInteractiveElements {
		clickDiscoveredLinks = c.clickAndCollect(tabCtx, currentURL)
	}

	// ── Parse DOM via existing sitemapper HTML parser ─────────────────────────
	// Reuse the battle-tested sitemapper parseHTML logic by creating a temporary
	// Crawler instance — this avoids duplicating HTML parsing logic.
	var discoveredLinks []string
	if outerHTML != "" {
		// Build a minimal sitemapper Crawler just for HTML parsing (no HTTP calls)
		tmpCrawler := sitemapper.NewCrawlerForDOM(c.baseURL, outerHTML, currentURL)
		if tmpCrawler != nil {
			links, forms, endpoints := tmpCrawler.ExtractAll()
			discoveredLinks = links
			for _, f := range forms {
				c.result.addForm(f)
				c.emit(EventFormFound, f.Action, "", f.Method, "form discovered", depth)
			}
			for _, e := range endpoints {
				c.result.addEndpoint(e)
			}
		}
	}

	// ── Record Page ───────────────────────────────────────────────────────────
	c.result.addPage(sitemapper.Page{
		URL:          currentURL,
		StatusCode:   200, // chromedp doesn't expose status codes directly; assume 200 for navigated pages
		ContentType:  "text/html",
		Depth:        depth,
		Links:        discoveredLinks,
		DiscoveredAt: time.Now(),
		Tech:         []string{"dom_crawled"},
	})

	// Merge all link sources
	allLinks := append(discoveredLinks, clickDiscoveredLinks...)
	return deduplicateStrings(allLinks), nil
}

// clickAndCollect iterates through clickSelectors and clicks each matching
// element, collecting any new URLs or route changes that result.
func (c *DOMCrawler) clickAndCollect(tabCtx context.Context, pageURL string) []string {
	var discovered []string
	clickCount := 0

	for _, selector := range clickSelectors {
		if clickCount >= c.cfg.MaxClicksPerPage {
			break
		}

		select {
		case <-tabCtx.Done():
			return discovered
		default:
		}

		// Find all matching elements
		// The JS returns a JSON string like "[0,1,2]"
		var nodeIDsJSON string
		err := chromedp.Run(tabCtx,
			chromedp.Evaluate(fmt.Sprintf(`
				(function() {
					var els = document.querySelectorAll(%q);
					var results = [];
					for (var i = 0; i < Math.min(els.length, 5); i++) {
						results.push(i);
					}
					return JSON.stringify(results);
				})()
			`, selector), &nodeIDsJSON),
		)
		if err != nil || nodeIDsJSON == "" || nodeIDsJSON == "[]" {
			continue
		}

		// Parse indices
		var indices []int
		if err := json.Unmarshal([]byte(nodeIDsJSON), &indices); err != nil {
			continue
		}

		for _, idx := range indices {
			if clickCount >= c.cfg.MaxClicksPerPage {
				break
			}

			// Record URL before click
			var urlBefore string
			_ = chromedp.Run(tabCtx, chromedp.Location(&urlBefore))

			// Click element by index
			clickErr := chromedp.Run(tabCtx,
				chromedp.Evaluate(fmt.Sprintf(`
					(function() {
						var els = document.querySelectorAll(%q);
						if (els[%d]) { els[%d].click(); return true; }
						return false;
					})()
				`, selector, idx, idx), nil),
			)
			if clickErr != nil {
				continue
			}

			// Brief wait for DOM/navigation to settle
			select {
			case <-time.After(500 * time.Millisecond):
			case <-tabCtx.Done():
				return discovered
			}

			// Collect URL after click
			var urlAfter string
			_ = chromedp.Run(tabCtx, chromedp.Location(&urlAfter))

			// Collect newly pushed routes
			var routesJSON string
			_ = chromedp.Run(tabCtx,
				chromedp.Evaluate(`JSON.stringify(window.__dormRoutes || [])`, &routesJSON),
			)
			var newRoutes []string
			if routesJSON != "" {
				_ = json.Unmarshal([]byte(routesJSON), &newRoutes)
			}

			c.result.addClickEvent(ClickEvent{
				Selector:  selector,
				PageURL:   pageURL,
				NewURL:    urlAfter,
				NewRoutes: newRoutes,
				ClickedAt: time.Now(),
			})
			c.emit(EventClick, urlAfter, selector, "", fmt.Sprintf("→ %s", urlAfter), 0)
			clickCount++

			if urlAfter != urlBefore && c.inScope(urlAfter) {
				discovered = append(discovered, urlAfter)
			}
			for _, r := range newRoutes {
				if abs := c.resolveURL(r); abs != "" && c.inScope(abs) {
					discovered = append(discovered, abs)
					c.result.addJSRoute(r)
					c.emit(EventSPARoute, abs, "", r, "click-triggered route", 0)
				}
			}
		}
	}

	return deduplicateStrings(discovered)
}

// isCapturableRequest returns true if the URL is a dynamic endpoint we should 
// pass to the engine (AJAX, forms, unknown paths), ignoring only static assets.
func (c *DOMCrawler) isCapturableRequest(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Must be same host
	if !strings.EqualFold(u.Hostname(), c.baseURL.Hostname()) {
		return false
	}

	path := strings.ToLower(u.Path)

	// Ignore purely static assets
	for _, ext := range []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".ico", ".woff", ".woff2", ".ttf", ".map", ".webp",
		".mp4", ".mp3", ".webm",
	} {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}

	// If it's not a static asset, it's a potential target (PHP, AJAX, custom path)
	return true
}

// inScope returns true if the URL belongs to the same hostname as the base URL.
func (c *DOMCrawler) inScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), c.baseURL.Hostname())
}

// resolveURL resolves href/route strings against the base URL.
func (c *DOMCrawler) resolveURL(href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "javascript") ||
		strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "data:") {
		return ""
	}
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return c.baseURL.ResolveReference(u).String()
}

// normalizeURL strips query params and fragments for visited deduplication.
func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// deduplicateStrings returns a deduplicated copy of the input slice.
func deduplicateStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
