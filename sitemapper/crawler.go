package sitemapper

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// newTimeoutContext creates a context with a deadline.
// The cancel function is stored internally and called after the deadline fires
// (Go's runtime cleans it up). Callers should not need to cancel manually
// because the timeout is the only lifecycle event we care about.
func newTimeoutContext(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// titleRegex extracts the page <title> as a fallback if HTML parsing is unavailable.
var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,200})</title>`)

// inlineJSPathRegex extracts short path strings from inline <script> blocks (fast pass).
var inlineJSPathRegex = regexp.MustCompile(`(?i)['"]([/][a-zA-Z0-9_\-/]{2,}(?:\.[a-zA-Z]{2,4})?)['"]`)

// crawlResult is the structured output of crawling a single URL.
type crawlResult struct {
	page      Page
	links     []string
	jsFileURLs []string
	forms     []Form
	endpoints []Endpoint
}

// Crawler performs HTTP crawling within the scope of a single host.
type Crawler struct {
	BaseURL   *url.URL
	Config    Config
	Client    *http.Client
	visited   sync.Map
	sm        *SiteMap
}

// NewCrawler creates a Crawler for the given base URL and config.
func NewCrawler(baseURL *url.URL, cfg Config, client *http.Client, sm *SiteMap) *Crawler {
	return &Crawler{
		BaseURL: baseURL,
		Config:  cfg,
		Client:  client,
		sm:      sm,
	}
}


// Run starts the BFS crawl and returns collected jsURLs. SiteMap is updated live.
// Uses a slice-based queue (no channel) to avoid send-on-closed-channel panics.
// HTTP fetches are concurrent (bounded by semaphore), but queue mutations are mutex-protected.
func (c *Crawler) Run() (jsURLs []string) {
	type queueItem struct {
		u     string
		depth int
	}

	// Seed the BFS queue with the start URL
	queue := []queueItem{{c.BaseURL.String(), 0}}

	// Semaphore limits concurrent HTTP in-flight requests
	sem := make(chan struct{}, c.Config.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex // protects queue and c.pages/forms/etc inside goroutines

	for {
		mu.Lock()
		if len(queue) == 0 {
			mu.Unlock()
			// Wait for all in-flight requests to finish, then check queue again
			wg.Wait()
			mu.Lock()
			if len(queue) == 0 {
				mu.Unlock()
				break // truly empty — done
			}
		}

		// Check page cap
		if c.Config.MaxPages > 0 && len(c.sm.Pages) >= c.Config.MaxPages {
			mu.Unlock()
			break
		}

		// Dequeue next item
		item := queue[0]
		queue = queue[1:]
		mu.Unlock()

		if item.depth >= c.Config.MaxDepth {
			continue
		}

		// Skip already visited (atomic compare-and-store)
		if _, loaded := c.visited.LoadOrStore(item.u, true); loaded {
			continue
		}

		if c.Config.RateLimit > 0 {
			time.Sleep(c.Config.RateLimit)
		}

		// Fetch concurrently
		wg.Add(1)
		sem <- struct{}{}
		go func(u string, depth int) {
			defer wg.Done()
			defer func() { <-sem }()

			result := c.fetchAndParse(u, depth)
			if result == nil {
				return
			}

			mu.Lock()
			c.sm.Pages = append(c.sm.Pages, result.page)
			c.sm.Forms = append(c.sm.Forms, result.forms...)
			c.sm.Endpoints = append(c.sm.Endpoints, result.endpoints...)
			jsURLs = append(jsURLs, result.jsFileURLs...)
			
			// Live Stats Update
			c.sm.Stats.TotalPages = len(c.sm.Pages)
			c.sm.Stats.TotalForms = len(c.sm.Forms)
			c.sm.Stats.TotalEndpoints = len(c.sm.Endpoints)
			if result.page.Depth > c.sm.Stats.MaxDepth {
				c.sm.Stats.MaxDepth = result.page.Depth
			}
			for _, tech := range result.page.Tech {
				c.sm.Stats.Technologies[tech]++
			}

			// Enqueue newly discovered links (safe: mu is held)
			for _, link := range result.links {
				queue = append(queue, queueItem{link, depth + 1})
			}
			
			// Live DB / Memory Sync
			StoreSiteMap(c.sm)
			mu.Unlock()
		}(item.u, item.depth)
	}

	// Final wait to ensure all goroutines finish writing
	wg.Wait()

	return jsURLs
}

// fetchAndParse performs an HTTP GET on a URL and extracts all page data.
func (c *Crawler) fetchAndParse(rawURL string, depth int) *crawlResult {
	ctx, cancel := newTimeoutContext(c.Config.ReqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "DORM-Sitemapper/1.19.0")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Collect headers (subset only)
	headers := map[string]string{}
	for _, h := range []string{"Server", "X-Powered-By", "X-Generator", "Content-Type",
		"X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options",
		"Access-Control-Allow-Origin", "Set-Cookie"} {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}

	contentType := resp.Header.Get("Content-Type")

	// Track 403/401/400 for forbidden paths (backward compat with existing plugins)
	page := Page{
		URL:          rawURL,
		StatusCode:   resp.StatusCode,
		ContentType:  contentType,
		Depth:        depth,
		Headers:      headers,
		DiscoveredAt: time.Now(),
	}

	// Only parse HTML bodies
	if !strings.Contains(strings.ToLower(contentType), "html") {
		return &crawlResult{page: page}
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return &crawlResult{page: page}
	}
	body := string(bodyBytes)

	// Fingerprint technologies
	page.Tech = FingerprintPage(resp, body)

	// Parse HTML
	result := c.parseHTML(body, rawURL, &page)
	result.page = page

	return result
}

// parseHTML walks the HTML DOM to extract links, forms, JS files, and inline JS paths.
func (c *Crawler) parseHTML(body, currentURL string, page *Page) *crawlResult {
	result := &crawlResult{}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		// Fallback: extract inline JS paths via regex
		for _, path := range inlineJSPathRegex.FindAllStringSubmatch(body, -1) {
			if len(path) > 1 {
				if abs := c.resolveURL(path[1]); abs != "" {
					result.links = append(result.links, abs)
				}
			}
		}
		// Try to grab title via regex
		if m := titleRegex.FindStringSubmatch(body); len(m) > 1 {
			page.Title = strings.TrimSpace(m[1])
		}
		return result
	}

	var currentForm *Form
	seenLinks := make(map[string]bool)

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					page.Title = strings.TrimSpace(n.FirstChild.Data)
				}

			case "a":
				for _, attr := range n.Attr {
					if attr.Key == "href" && attr.Val != "" {
						if abs := c.resolveURL(attr.Val); abs != "" && !seenLinks[abs] {
							seenLinks[abs] = true
							if c.inScope(abs) {
								result.links = append(result.links, abs)
								page.Links = append(page.Links, abs)
							}
							// Register as GET endpoint if it has query params
							if u, err := url.Parse(abs); err == nil && len(u.Query()) > 0 {
								var params []string
								for k := range u.Query() {
									params = append(params, k)
								}
								result.endpoints = append(result.endpoints, Endpoint{
									URL:    abs,
									Method: "GET",
									Params: params,
									Source: "html_link",
								})
							}
						}
					}
				}

			case "form":
				f := Form{
					PageURL: currentURL,
					Action:  currentURL,
					Method:  "GET",
				}
				for _, attr := range n.Attr {
					switch attr.Key {
					case "action":
						if attr.Val != "" {
							if abs := c.resolveURL(attr.Val); abs != "" {
								f.Action = abs
							} else {
								f.Action = attr.Val
							}
						}
					case "method":
						f.Method = strings.ToUpper(attr.Val)
						if f.Method == "" {
							f.Method = "GET"
						}
					}
				}
				result.forms = append(result.forms, f)
				currentForm = &result.forms[len(result.forms)-1]

			case "input", "select", "textarea", "button":
				if currentForm != nil {
					fi := FormInput{}
					for _, attr := range n.Attr {
						switch attr.Key {
						case "name":
							fi.Name = attr.Val
						case "type":
							fi.Type = attr.Val
						case "required":
							fi.Required = true
						}
					}
					if fi.Type == "" {
						fi.Type = "text"
					}
					if fi.Name != "" {
						currentForm.Inputs = append(currentForm.Inputs, fi)
					}
				}

			case "script":
				// Collect external JS file references
				src := ""
				for _, attr := range n.Attr {
					if attr.Key == "src" {
						src = attr.Val
					}
				}
				if src != "" {
					if abs := c.resolveURL(src); abs != "" && c.sameHost(abs) {
						result.jsFileURLs = append(result.jsFileURLs, abs)
						page.JSFiles = append(page.JSFiles, abs)
					}
				} else if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					// Inline script: extract paths
					paths := ExtractPathsFromJS(n.FirstChild.Data)
					for _, p := range paths {
						if abs := c.resolveURL(p); abs != "" && c.inScope(abs) && !seenLinks[abs] {
							seenLinks[abs] = true
							result.links = append(result.links, abs)
						}
					}
				}

			case "meta":
				// Check generator meta
				var name, content string
				for _, attr := range n.Attr {
					if attr.Key == "name" {
						name = strings.ToLower(attr.Val)
					}
					if attr.Key == "content" {
						content = attr.Val
					}
				}
				if name == "generator" && content != "" {
					page.Tech = append(page.Tech, "CMS: "+content)
				}

			// Non-standard link attributes used by some frameworks
			case "link":
				// Skip <link> stylesheets — not navigation targets
			}

			// Also check data-href, data-url on any element
			for _, attr := range n.Attr {
				if (attr.Key == "data-href" || attr.Key == "data-url") && attr.Val != "" {
					if abs := c.resolveURL(attr.Val); abs != "" && c.inScope(abs) && !seenLinks[abs] {
						seenLinks[abs] = true
						result.links = append(result.links, abs)
					}
				}
			}
		}

		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}

	walk(doc)

	// Register forms as endpoints
	for i := range result.forms {
		f := &result.forms[i]
		if f.Action != "" {
			var params []string
			for _, inp := range f.Inputs {
				if inp.Name != "" {
					params = append(params, inp.Name)
				}
			}
			result.endpoints = append(result.endpoints, Endpoint{
				URL:    f.Action,
				Method: f.Method,
				Params: params,
				Source: "html_form",
			})
		}
	}

	return result
}

// resolveURL resolves a potentially relative URL against the base URL.
func (c *Crawler) resolveURL(href string) string {
	href = strings.TrimSpace(href)
	if href == "" ||
		strings.HasPrefix(href, "javascript") ||
		strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "tel:") ||
		strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "data:") {
		return ""
	}

	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return c.BaseURL.ResolveReference(u).String()
}

// inScope returns true if the absolute URL belongs to the same host as the target.
func (c *Crawler) inScope(absURL string) bool {
	u, err := url.Parse(absURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), c.BaseURL.Hostname())
}

// sameHost is an alias for inScope for clarity in JS file filtering.
func (c *Crawler) sameHost(absURL string) bool {
	return c.inScope(absURL)
}

// formatURL ensures a URL has a scheme prefix.
func formatURL(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return fmt.Sprintf("http://%s", rawURL)
	}
	return rawURL
}
