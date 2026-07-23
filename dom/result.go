package dom

import (
	"DORM/sitemapper"
	"net/url"
	"sync"
	"time"
)

// ClickEvent records a single interactive element click and its outcome.
type ClickEvent struct {
	Selector  string // CSS selector of the clicked element
	PageURL   string // URL of the page the element was on
	NewURL    string // URL after click (may be same if only DOM changed)
	NewRoutes []string
	ClickedAt time.Time
}

// DOMResult is the output of a single DOM-Crawler run.
// It is intentionally isolated from sitemapper.SiteMap so the two crawlers
// can run concurrently in separate memory regions without any shared state.
type DOMResult struct {
	mu sync.Mutex // protects all fields during concurrent BFS writes

	Pages        []sitemapper.Page
	Endpoints    []sitemapper.Endpoint
	Forms        []sitemapper.Form
	JSRoutes     []string     // client-side routes discovered via history.pushState intercept
	XHREndpoints []string     // API calls captured via Network event interception
	ClickMap     []ClickEvent // audit trail of every click action

	Errors []string // non-fatal errors encountered during crawl
}

// addPage appends a page under the lock (called from concurrent goroutines).
func (r *DOMResult) addPage(p sitemapper.Page) {
	r.mu.Lock()
	r.Pages = append(r.Pages, p)
	r.mu.Unlock()
}

// addEndpoint appends an endpoint under the lock.
func (r *DOMResult) addEndpoint(e sitemapper.Endpoint) {
	r.mu.Lock()
	r.Endpoints = append(r.Endpoints, e)
	r.mu.Unlock()
}

// addForm appends a form under the lock.
func (r *DOMResult) addForm(f sitemapper.Form) {
	r.mu.Lock()
	r.Forms = append(r.Forms, f)
	r.mu.Unlock()
}

// addXHR records a dynamically discovered API endpoint under the lock.
// Deduplication is performed here to avoid noisy results.
func (r *DOMResult) addXHR(rawURL string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.XHREndpoints {
		if x == rawURL {
			return
		}
	}
	r.XHREndpoints = append(r.XHREndpoints, rawURL)
}

// addJSRoute records a client-side route discovered via pushState intercept.
func (r *DOMResult) addJSRoute(route string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range r.JSRoutes {
		if rt == route {
			return
		}
	}
	r.JSRoutes = append(r.JSRoutes, route)
}

// addClickEvent records a click action result.
func (r *DOMResult) addClickEvent(ev ClickEvent) {
	r.mu.Lock()
	r.ClickMap = append(r.ClickMap, ev)
	r.mu.Unlock()
}

// logError records a non-fatal crawl error.
func (r *DOMResult) logError(msg string) {
	r.mu.Lock()
	r.Errors = append(r.Errors, msg)
	r.mu.Unlock()
}

// pageCount returns the current number of crawled pages (safe for concurrent use).
func (r *DOMResult) pageCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Pages)
}

// MergeInto merges this DOMResult into an existing sitemapper.SiteMap.
// The merge is additive and deduplicates endpoints by URL+Method.
// This is the ONLY point where DOM Crawler output touches the shared SiteMap —
// called after both crawlers have finished, preventing any concurrent writes.
func (r *DOMResult) MergeInto(sm *sitemapper.SiteMap) {
	if sm == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// ── Pages ─────────────────────────────────────────────────────────
	existingPageURLs := make(map[string]bool, len(sm.Pages))
	for _, p := range sm.Pages {
		existingPageURLs[p.URL] = true
	}
	for _, p := range r.Pages {
		if !existingPageURLs[p.URL] {
			sm.Pages = append(sm.Pages, p)
		}
	}

	// ── Forms ─────────────────────────────────────────────────────────
	sm.Forms = append(sm.Forms, r.Forms...)

	// ── Endpoints (dedup by Method+URL) ───────────────────────────────
	existingEPs := make(map[string]bool, len(sm.Endpoints))
	for _, e := range sm.Endpoints {
		existingEPs[e.Method+"::"+e.URL] = true
	}

	for _, e := range r.Endpoints {
		k := e.Method + "::" + e.URL
		if !existingEPs[k] {
			existingEPs[k] = true
			sm.Endpoints = append(sm.Endpoints, e)
		}
	}

	// ── XHR endpoints as GET endpoints ────────────────────────────────
	for _, xhrURL := range r.XHREndpoints {
		k := "GET::" + xhrURL
		if !existingEPs[k] {
			existingEPs[k] = true
			sm.Endpoints = append(sm.Endpoints, sitemapper.Endpoint{
				URL:    xhrURL,
				Method: "GET",
				Params: []string{},
				Source: "dom_xhr",
			})
		}
	}

	// ── JS Routes as GET endpoints ────────────────────────────────────
	if len(sm.Pages) > 0 {
		// Build base URL from the first page for route resolution
		if baseURL, err := url.Parse(sm.BaseURL); err == nil {
			for _, route := range r.JSRoutes {
				resolved := baseURL.ResolveReference(&url.URL{Path: route}).String()
				k := "GET::" + resolved
				if !existingEPs[k] {
					existingEPs[k] = true
					sm.Endpoints = append(sm.Endpoints, sitemapper.Endpoint{
						URL:    resolved,
						Method: "GET",
						Params: []string{},
						Source: "dom_spa_route",
					})
				}
			}
		}
	}

	// ── Update stats ──────────────────────────────────────────────────
	sm.Stats.TotalPages = len(sm.Pages)
	sm.Stats.TotalForms = len(sm.Forms)
	sm.Stats.TotalEndpoints = len(sm.Endpoints)
}
