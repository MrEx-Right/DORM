package sitemapper

import (
	"net/url"
	"strings"
	"time"
)

// ==============================================================================
// DOM-Crawler Bridge
// ==============================================================================
// This file exposes a thin adapter so the dom/ package can reuse sitemapper's
// battle-tested HTML parser without duplicating code or creating circular imports.
//
// dom/ → sitemapper/dombridge.go (adapter) → sitemapper internals
//
// No sitemapper.SiteMap is touched here; all output is returned as plain slices.
// ==============================================================================

// DOMParseResult holds the output of parsing a single HTML snapshot captured
// by the DOM-Crawler. It mirrors crawlResult but is exported for dom/ to use.
type DOMParseResult struct {
	Links     []string
	Forms     []Form
	Endpoints []Endpoint
}

// domBridgeCrawler is a minimal wrapper around the existing Crawler that
// allows HTML parsing without any HTTP client or SiteMap dependency.
type domBridgeCrawler struct {
	BaseURL *url.URL
}

// NewCrawlerForDOM creates a lightweight HTML parser bound to the given base URL.
// It returns a *DOMBridgeCrawler that exposes ExtractAll for parsing an HTML string.
// Returns nil if the base URL cannot be parsed.
func NewCrawlerForDOM(baseURL *url.URL, html string, currentURL string) *DOMBridge {
	if baseURL == nil {
		return nil
	}
	return &DOMBridge{
		baseURL:    baseURL,
		html:       html,
		currentURL: currentURL,
	}
}

// DOMBridge adapts sitemapper's internal HTML parser for external use.
type DOMBridge struct {
	baseURL    *url.URL
	html       string
	currentURL string
}

// ExtractAll parses the stored HTML and returns links, forms, and endpoints.
// Internally delegates to the same parseHTML logic used by the HTTP crawler.
func (b *DOMBridge) ExtractAll() (links []string, forms []Form, endpoints []Endpoint) {
	// Build a minimal Crawler with no HTTP client (only used for URL resolution
	// and inScope checks — no network calls are made).
	c := &Crawler{
		BaseURL: b.baseURL,
		Config:  DefaultConfig(),
		Client:  nil, // nil is safe: parseHTML never calls HTTP
		sm: &SiteMap{
			Host:    b.baseURL.Hostname(),
			BaseURL: b.baseURL.String(),
			Stats:   MapStats{Technologies: make(map[string]int)},
		},
	}

	fakePage := &Page{
		URL:          b.currentURL,
		DiscoveredAt: time.Now(),
	}

	result := c.parseHTML(b.html, b.currentURL, fakePage)
	if result == nil {
		return nil, nil, nil
	}

	// Filter links to same-host only
	for _, link := range result.links {
		if u, err := url.Parse(link); err == nil &&
			strings.EqualFold(u.Hostname(), b.baseURL.Hostname()) {
			links = append(links, link)
		}
	}

	forms = result.forms
	endpoints = result.endpoints
	return links, forms, endpoints
}
