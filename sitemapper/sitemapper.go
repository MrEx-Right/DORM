package sitemapper

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"crypto/tls"
)

// Config controls the behavior of the Sitemapper engine.
type Config struct {
	MaxDepth      int           // Maximum crawl depth (default: 4)
	MaxPages      int           // Maximum pages to crawl; 0 = unlimited (default: 1000)
	MaxJSFiles    int           // Maximum JS files to analyze (default: 50)
	Concurrency   int           // Concurrent HTTP workers (default: 5)
	ReqTimeout    time.Duration // Per-request timeout (default: 15s)
	ParseSitemaps bool          // Fetch and parse sitemap.xml files (default: true)
	ExtractJS     bool          // Fetch and analyze external JS files (default: true)
	RateLimit     time.Duration // Minimum delay between requests (default: 100ms)
}

// DefaultConfig returns a production-safe Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxDepth:      4,
		MaxPages:      1000,
		MaxJSFiles:    50,
		Concurrency:   5,
		ReqTimeout:    15 * time.Second,
		ParseSitemaps: true,
		ExtractJS:     true,
		RateLimit:     100 * time.Millisecond,
	}
}

// QuickConfig returns a faster Config for use inside the scan pipeline.
func QuickConfig() Config {
	return Config{
		MaxDepth:      3,
		MaxPages:      500,
		MaxJSFiles:    30,
		Concurrency:   5,
		ReqTimeout:    10 * time.Second,
		ParseSitemaps: true,
		ExtractJS:     true,
		RateLimit:     50 * time.Millisecond,
	}
}

// newHTTPClient creates a reusable TLS-bypassing HTTP client for sitemapper.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// Run performs a full site map discovery for the given target URL using the provided Config.
// It orchestrates: robots.txt → sitemap.xml → HTTP crawl → JS analysis → store.
func Run(ctx context.Context, targetURL string, cfg Config, scanID string) (*SiteMap, error) {
	targetURL = formatURL(targetURL)

	base, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	client := newHTTPClient(cfg.ReqTimeout + 5*time.Second)

	sm := &SiteMap{
		Host:      base.Hostname(),
		BaseURL:   targetURL,
		ScanID:    scanID,
		CreatedAt: time.Now(),
		Stats:     MapStats{Technologies: make(map[string]int)},
	}


	// ── PHASE 1: robots.txt ───────────────────────────────────────────
	robots := FetchRobotsTxt(client, base)
	sm.RobotDisallows = robots.Disallows

	// ── PHASE 2: sitemap.xml discovery ───────────────────────────────
	if cfg.ParseSitemaps {
		sitemapURLs := DiscoverSitemaps(client, base, robots.Sitemaps)
		for _, smURL := range sitemapURLs {
			pageURLs := ParseSitemapXML(client, smURL, 0)
			sm.SitemapURLs = append(sm.SitemapURLs, pageURLs...)
		}
	}

	// ── PHASE 3: HTTP Crawl ───────────────────────────────────────────
	crawler := NewCrawler(base, cfg, client, sm)

	// Seed with sitemap URLs so crawler visits them too
	for _, u := range sm.SitemapURLs {
		if strings.Contains(u, base.Hostname()) {
			crawler.visited.LoadOrStore(u, false) // mark as "to visit"
		}
	}

	jsURLs := crawler.Run()

	// ── PHASE 4: robots.txt disallow paths as GET endpoints ──────────
	for _, disallowPath := range sm.RobotDisallows {
		epURL := fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, disallowPath)
		sm.Endpoints = append(sm.Endpoints, Endpoint{
			URL:    epURL,
			Method: "GET",
			Params: []string{},
			Source: "robots",
		})
	}

	// ── PHASE 5: JS file analysis ────────────────────────────────────
	if cfg.ExtractJS && len(jsURLs) > 0 {
		limit := len(jsURLs)
		if cfg.MaxJSFiles > 0 && limit > cfg.MaxJSFiles {
			limit = cfg.MaxJSFiles
		}

		var jsMu sync.Mutex
		var jsWg sync.WaitGroup
		sem := make(chan struct{}, cfg.Concurrency)

		for i := 0; i < limit; i++ {
			jsWg.Add(1)
			sem <- struct{}{}
			go func(jsURL string) {
				defer jsWg.Done()
				defer func() { <-sem }()

				jsFile := FetchAndAnalyzeJS(client, jsURL, base)
				jsMu.Lock()
				sm.JSFiles = append(sm.JSFiles, jsFile)

				// Convert JS-extracted paths to endpoints
				for _, path := range jsFile.Paths {
					epURL := fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, path)
					sm.Endpoints = append(sm.Endpoints, Endpoint{
						URL:    epURL,
						Method: "GET",
						Params: []string{},
						Source: "js_extract",
					})
				}
				
				// Live Stats Update
				sm.Stats.TotalJSFiles = len(sm.JSFiles)
				sm.Stats.TotalEndpoints = len(sm.Endpoints)
				StoreSiteMap(sm)
				
				jsMu.Unlock()
			}(jsURLs[i])
		}
		jsWg.Wait()
	}

	// ── PHASE 6: Deduplicate endpoints ───────────────────────────────
	sm.Endpoints = deduplicateEndpoints(sm.Endpoints)

	// ── PHASE 7: Final DB Sync ──────────────────────────────────
	StoreSiteMap(sm)

	return sm, nil
}

// Quick is a convenience wrapper for Run using QuickConfig and no scanID.
// Used by SpiderPlugin for a fast pre-scan map.
func Quick(targetURL string) (*SiteMap, error) {
	return Run(context.Background(), targetURL, QuickConfig(), "")
}

// QuickWithContext runs Quick with an external context (for cancellation support).
func QuickWithContext(ctx context.Context, targetURL, scanID string) (*SiteMap, error) {
	return Run(ctx, targetURL, QuickConfig(), scanID)
}

// deduplicateEndpoints removes duplicate endpoints based on URL+Method.
func deduplicateEndpoints(eps []Endpoint) []Endpoint {
	seen := make(map[string]bool)
	var out []Endpoint
	for _, e := range eps {
		key := e.Method + "::" + e.URL
		if !seen[key] {
			seen[key] = true
			out = append(out, e)
		}
	}
	return out
}

