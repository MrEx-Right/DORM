package dom

import "time"

// DOMConfig controls the behavior of the DOM-Crawler (chromedp-based SPA crawler).
// It is deliberately independent from sitemapper.Config to avoid coupling.
type DOMConfig struct {
	// MaxDepth controls how many levels of SPA navigation/clicks are followed.
	MaxDepth int

	// MaxPages limits the total number of pages (URL + route states) captured.
	// 0 means unlimited.
	MaxPages int

	// BrowserTimeout is the wall-clock deadline for the entire crawl session.
	// After this duration the crawler stops gracefully and returns what it has.
	BrowserTimeout time.Duration

	// PageTimeout is the per-page deadline: navigate + wait + click cycle.
	PageTimeout time.Duration

	// NetworkIdleTimeout is how long the crawler waits after page load for
	// XHR/fetch activity to settle before taking a DOM snapshot.
	NetworkIdleTimeout time.Duration

	// Headless runs Chrome in headless mode (no visible window).
	// Should always be true in production; false only for debugging.
	Headless bool

	// ClickInteractiveElements enables the smart button/tab clicking strategy.
	// Disabling this speeds up the crawl but misses lazy-loaded content.
	ClickInteractiveElements bool

	// WaitForNetworkIdle makes the crawler wait for fetch/XHR activity to
	// settle before capturing the DOM snapshot on each page.
	WaitForNetworkIdle bool

	// MaxClicksPerPage caps how many buttons/tabs are clicked on a single page
	// to prevent infinite loops on deeply interactive UIs.
	MaxClicksPerPage int

	// UserAgent overrides the browser's default user-agent string.
	UserAgent string

	// ExtraHeaders are injected into every browser request (e.g. auth tokens).
	ExtraHeaders map[string]string
}

// DefaultDOMConfig returns a safe, balanced configuration for production use.
func DefaultDOMConfig() DOMConfig {
	return DOMConfig{
		MaxDepth:                 3,
		MaxPages:                 200,
		BrowserTimeout:           3 * time.Minute,
		PageTimeout:              20 * time.Second,
		NetworkIdleTimeout:       2 * time.Second,
		Headless:                 true,
		ClickInteractiveElements: true,
		WaitForNetworkIdle:       true,
		MaxClicksPerPage:         20,
		UserAgent:                "DORM-DOMCrawler/1.0 (chromedp; SPA scanner)",
		ExtraHeaders:             map[string]string{},
	}
}

// FastDOMConfig returns a lighter config for use inside the automated scan pipeline.
// Lower limits keep total scan time reasonable even on slow targets.
func FastDOMConfig() DOMConfig {
	return DOMConfig{
		MaxDepth:                 2,
		MaxPages:                 100,
		BrowserTimeout:           90 * time.Second,
		PageTimeout:              12 * time.Second,
		NetworkIdleTimeout:       1500 * time.Millisecond,
		Headless:                 true,
		ClickInteractiveElements: true,
		WaitForNetworkIdle:       true,
		MaxClicksPerPage:         12,
		UserAgent:                "DORM-DOMCrawler/1.0 (chromedp; SPA scanner)",
		ExtraHeaders:             map[string]string{},
	}
}
