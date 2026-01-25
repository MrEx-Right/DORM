package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ==========================
// SPIDER ENGINE (OPTIMIZED)
// ==========================

// Global Regex compilation for performance.
// Improved pattern to catch unquoted attributes and handle spaces.
var linkRegex = regexp.MustCompile(`(?i)href\s*=\s*["']?([^"'\s>]+)["']?`)

type Spider struct {
	BaseURL   *url.URL
	MaxDepth  int
	Visited   sync.Map
	FoundURLs []string
	Client    *http.Client // Persistent HTTP Client
	mu        sync.Mutex
}

func NewSpider(targetURL string) (*Spider, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Initialize Client once and reuse (Performance Boost)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
		},
		// Redirect Policy (Stay within domain scope)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			initialHost := via[0].URL.Hostname()
			newHost := req.URL.Hostname()
			if !strings.Contains(newHost, initialHost) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Spider{
		BaseURL:   u,
		MaxDepth:  3, // Increased depth to 3 for better coverage
		FoundURLs: []string{},
		Client:    client,
	}, nil
}

func (s *Spider) Crawl() []string {
	// Add start URL to the queue to begin crawling
	s.crawlRecursive(s.BaseURL.String(), 0)
	return s.FoundURLs
}

func (s *Spider) crawlRecursive(currentURL string, depth int) {
	if depth >= s.MaxDepth {
		return
	}

	// Fast check: Already visited?
	if _, loaded := s.Visited.LoadOrStore(currentURL, true); loaded {
		return
	}

	s.mu.Lock()
	// Hard limit check to prevent memory bloat
	if len(s.FoundURLs) > 100 {
		s.mu.Unlock()
		return
	}
	s.FoundURLs = append(s.FoundURLs, currentURL)
	s.mu.Unlock()

	// Fetch page content
	body, err := s.fetchBody(currentURL)
	if err != nil {
		return
	}

	// Extract and traverse links
	links := s.extractLinks(body)
	for _, link := range links {
		absURL := s.resolveURL(link)

		// Scope check: Stay within the same domain (including subdomains)
		if absURL != "" && strings.Contains(absURL, s.BaseURL.Hostname()) {
			s.crawlRecursive(absURL, depth+1)
		}
	}
}

func (s *Spider) fetchBody(target string) (string, error) {
	// Reuse existing client
	resp, err := s.Client.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Memory Protection: Limit read size to Max 5MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	return string(body), nil
}

func (s *Spider) extractLinks(body string) []string {
	// Use pre-compiled global regex
	matches := linkRegex.FindAllStringSubmatch(body, -1)
	var links []string
	for _, match := range matches {
		if len(match) > 1 {
			links = append(links, match[1])
		}
	}
	return links
}

func (s *Spider) resolveURL(href string) string {
	href = strings.TrimSpace(href)
	// Filter out non-http links (js, mailto, anchors)
	if strings.HasPrefix(href, "javascript") || strings.HasPrefix(href, "mailto") || strings.HasPrefix(href, "#") || href == "" {
		return ""
	}

	// Convert relative URLs to absolute URLs
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return s.BaseURL.ResolveReference(u).String()
}

// ==========================
// DORM INTEGRATION (PLUGIN)
// ==========================

type SpiderPlugin struct{}

func (p *SpiderPlugin) Name() string { return "Web Spider (Crawler)" }

func (p *SpiderPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	startURL := getURL(target, "/")

	// Debug output
	fmt.Printf("[*] Starting Spider on %s\n", startURL)

	spider, err := NewSpider(startURL)
	if err != nil {
		return nil
	}

	urls := spider.Crawl()

	if len(urls) > 0 {
		desc := fmt.Sprintf("Spider crawled the site map and discovered %d pages.\n", len(urls))

		// Show first 15 URLs
		limit := 15
		if len(urls) < 15 {
			limit = len(urls)
		}

		for i := 0; i < limit; i++ {
			desc += fmt.Sprintf("- %s\n", urls[i])
		}

		if len(urls) > limit {
			desc += fmt.Sprintf("...and %d more.", len(urls)-limit)
		}

		return &Vulnerability{
			Target:      target,
			Name:        "Site Map (Spider Crawl)",
			Severity:    "INFO",
			CVSS:        0.0,
			Description: desc,
			Solution:    "Verify that discovered pages are intended to be public.",
			Reference:   "OWASP Spider",
		}
	}

	return nil
}
