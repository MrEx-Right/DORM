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

	scopeMu    sync.RWMutex
	extraHosts map[string]bool // hosts the site root redirected to

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
		if err != nil && crawlCtx.Err() != nil {
			// The crawl budget ran out mid-page: that's the end of the crawl,
			// not an error on the page.
			fmt.Printf("[DOM-Crawler] Budget reached — stopping\n")
			break
		}
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

// spaRenderWait caps how long a loaded page may take to render its first
// link or button (client-rendered apps).
const spaRenderWait = 6 * time.Second

// waitForEval polls a boolean JS expression until it is true or ctx ends.
func waitForEval(expr string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		for {
			var ok bool
			if err := chromedp.Evaluate(expr, &ok).Do(ctx); err == nil && ok {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	})
}

// pageWorkBudget is the time a page gets after navigation for the network-idle
// wait, the DOM snapshot and up to MaxClicksPerPage clicks (~0.5-0.8s each).
const pageWorkBudget = 18 * time.Second // incl. spaRenderWait

// visitPage navigates to a single URL, injects monitoring scripts, waits for
// the SPA to render, clicks interactive elements, and extracts all discovered data.
// Returns a deduplicated list of new in-scope URLs to enqueue.
func (c *DOMCrawler) visitPage(ctx context.Context, rawURL string, depth int) ([]string, error) {
	// PageTimeout bounds the navigation; the snapshot, network-idle wait and
	// clicks get their own budget on top. Sharing one 12s deadline meant a page
	// slow to load left nothing for the rest.
	pageCtx, pageCancel := context.WithTimeout(c.session.AllocContext(), c.cfg.PageTimeout+pageWorkBudget)
	defer pageCancel()

	tabCtx, tabCancel := c.session.NewTab(pageCtx)
	defer tabCancel()

	// ── XHR / Network Interception ────────────────────────────────────────────
	// Listen for network requests initiated by the page BEFORE navigation.
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		if req, ok := ev.(*network.EventRequestWillBeSent); ok {
			reqURL := req.Request.URL
			// The start page's document request after a redirect shows where
			// the site lives (puma.com → tr.puma.com): adopt it now, before
			// that page's own XHRs arrive and get judged out of scope.
			if depth == 0 && req.Type == network.ResourceTypeDocument {
				if u, err := url.Parse(reqURL); err == nil {
					c.adoptRedirectHost(u.Hostname())
				}
			}
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
	// Wait for the load event, but only up to PageTimeout: chromedp.Navigate
	// waits for it unbounded within the page deadline, and real storefronts
	// (third-party tags, long-polling) often never fire it in time — the page
	// was then dropped with no HTML, no links and no clicks, ending the crawl
	// at the first page. On timeout, use whatever has rendered so far.
	// chromedp ties a tab to the context of the first Run on it: open it on
	// tabCtx, or cancelling the navigation context below closes the tab.
	if err := chromedp.Run(tabCtx); err != nil {
		return nil, fmt.Errorf("open tab for %s: %w", rawURL, err)
	}
	var navErrText string
	navCtx, navCancel := context.WithTimeout(tabCtx, c.cfg.PageTimeout)
	navErr := chromedp.Run(navCtx,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(spaRouteInjectScript).Do(ctx)
			return err
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, _, errText, _, err := page.Navigate(rawURL).Do(ctx)
			navErrText = errText
			return err
		}),
		chromedp.WaitReady("body", chromedp.ByQuery),
		waitForEval(`document.readyState === "complete"`),
	)
	navCancel()
	if navErrText != "" { // DNS failure, connection refused, blocked...
		return nil, fmt.Errorf("navigate %s: %s", rawURL, navErrText)
	}
	if navErr != nil {
		var hasBody bool
		probeCtx, probeCancel := context.WithTimeout(tabCtx, 3*time.Second)
		probeErr := chromedp.Run(probeCtx, chromedp.Evaluate(`!!document.body && document.body.children.length > 0`, &hasBody))
		probeCancel()
		if probeErr != nil || !hasBody {
			return nil, fmt.Errorf("navigate %s: %w", rawURL, navErr)
		}
		c.emit(EventNavigate, rawURL, "", "", "slow page: continuing with partially loaded DOM", depth)
	}

	// Client-rendered apps (React/Vue <div id="root">) serve an empty shell:
	// give them a moment to draw something clickable before the snapshot.
	renderCtx, renderCancel := context.WithTimeout(tabCtx, spaRenderWait)
	_ = chromedp.Run(renderCtx, waitForEval(`document.querySelectorAll("a[href],button,[role='button']").length > 0`))
	renderCancel()

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
				if abs := c.resolveFrom(currentURL, r); abs != "" {
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
				if abs := c.resolveFrom(urlAfter, r); abs != "" && c.inScope(abs) {
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

	// Must be same host (or the host the site root redirected to)
	if !c.hostInScope(u.Hostname()) {
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

// inScope returns true if the URL belongs to the same hostname as the base URL,
// or to a host the site root redirected to.
func (c *DOMCrawler) inScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return c.hostInScope(u.Hostname())
}

func (c *DOMCrawler) hostInScope(host string) bool {
	if strings.EqualFold(host, c.baseURL.Hostname()) {
		return true
	}
	c.scopeMu.RLock()
	defer c.scopeMu.RUnlock()
	return c.extraHosts[strings.ToLower(host)]
}

// adoptRedirectHost widens the scope to the host the start page redirected
// to, when it is the same site (sitemapper.RelatedHost) — never a foreign one.
func (c *DOMCrawler) adoptRedirectHost(host string) {
	if strings.EqualFold(host, c.baseURL.Hostname()) || !sitemapper.RelatedHost(c.baseURL.Hostname(), host) {
		return
	}
	c.scopeMu.Lock()
	if c.extraHosts == nil {
		c.extraHosts = map[string]bool{}
	}
	c.extraHosts[strings.ToLower(host)] = true
	c.scopeMu.Unlock()
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

// resolveFrom resolves a route/href against the page it came from (after a
// redirect that is another host than baseURL), falling back to baseURL.
func (c *DOMCrawler) resolveFrom(pageURL, href string) string {
	abs := c.resolveURL(href)
	if abs == "" {
		return ""
	}
	base, err := url.Parse(pageURL)
	if err != nil || base.Host == "" {
		return abs
	}
	u, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return abs
	}
	return base.ResolveReference(u).String()
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
