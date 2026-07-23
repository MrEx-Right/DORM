package dom

import (
	"context"
	"fmt"

	"github.com/chromedp/chromedp"
)

// Session wraps a single long-lived Chrome browser instance.
// Multiple Crawl() calls reuse the same browser process, each getting
// its own isolated tab context — avoiding the overhead of browser restarts.
type Session struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	cfg         DOMConfig
}

// NewSession starts a headless Chrome instance using chromedp.
// Returns an error if Chrome/Chromium cannot be found on the system.
//
// Callers MUST call session.Close() to release the browser process.
func NewSession(ctx context.Context, cfg DOMConfig) (*Session, error) {
	opts := chromedp.DefaultExecAllocatorOptions[:]

	if cfg.Headless {
		opts = append(opts,
			chromedp.Headless,
			chromedp.NoSandbox,
			chromedp.DisableGPU,
		)
	}

	opts = append(opts,
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-web-security", true),       // allow CORS from injected scripts
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.UserAgent(cfg.UserAgent),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)

	// Verify the browser can start with a tiny smoke-test context.
	smokeCtx, smokeCancel := chromedp.NewContext(allocCtx)
	defer smokeCancel()
	if err := chromedp.Run(smokeCtx); err != nil {
		allocCancel()
		return nil, fmt.Errorf("dom.NewSession: Chrome failed to start: %w", err)
	}

	return &Session{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		cfg:         cfg,
	}, nil
}

// NewTab creates a new browser tab (child context) derived from the shared allocator.
// Each tab runs in an isolated context — no shared cookies, storage, or JS globals
// between concurrent tabs.
//
// The returned CancelFunc MUST be called to close the tab when done.
func (s *Session) NewTab(pageCtx context.Context) (context.Context, context.CancelFunc) {
	tabCtx, cancel := chromedp.NewContext(pageCtx)
	return tabCtx, cancel
}

// Close shuts down the underlying Chrome browser process.
// Must be called exactly once when the crawl session is done.
func (s *Session) Close() {
	if s.allocCancel != nil {
		s.allocCancel()
	}
}

// AllocContext returns the allocator context so callers can derive tab contexts from it.
func (s *Session) AllocContext() context.Context {
	return s.allocCtx
}
