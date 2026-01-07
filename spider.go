package main

import (
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
// SPIDER ENGINE (CORE)
// ==========================

type Spider struct {
	BaseURL   *url.URL
	MaxDepth  int
	Visited   sync.Map
	FoundURLs []string
	mu        sync.Mutex
}

func NewSpider(targetURL string) (*Spider, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	return &Spider{BaseURL: u, MaxDepth: 2, FoundURLs: []string{}}, nil
}

func (s *Spider) Crawl() []string {
	s.crawlRecursive(s.BaseURL.String(), 0)
	return s.FoundURLs
}

func (s *Spider) crawlRecursive(currentURL string, depth int) {
	if depth >= s.MaxDepth {
		return
	}

	// Already visited?
	if _, loaded := s.Visited.LoadOrStore(currentURL, true); loaded {
		return
	}

	s.mu.Lock()
	if len(s.FoundURLs) > 50 { // Limit to max 50 links
		s.mu.Unlock()
		return
	}
	s.FoundURLs = append(s.FoundURLs, currentURL)
	s.mu.Unlock()

	body, err := s.fetchBody(currentURL)
	if err != nil {
		return
	}

	links := s.extractLinks(body)
	for _, link := range links {
		absURL := s.resolveURL(link)
		// Stay within the same hostname
		if absURL != "" && strings.Contains(absURL, s.BaseURL.Hostname()) {
			s.crawlRecursive(absURL, depth+1)
		}
	}
}

func (s *Spider) fetchBody(target string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	return string(bytes), nil
}

func (s *Spider) extractLinks(body string) []string {
	re := regexp.MustCompile(`href=["'](.*?)["']`)
	matches := re.FindAllStringSubmatch(body, -1)
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
	if strings.HasPrefix(href, "javascript") || strings.HasPrefix(href, "mailto") || strings.HasPrefix(href, "#") {
		return ""
	}
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

	// Build URL
	startURL := getURL(target, "/")

	// Initialize Spider
	spider, err := NewSpider(startURL)
	if err != nil {
		return nil
	}

	// Run the crawl
	urls := spider.Crawl()

	if len(urls) > 1 { // If found more than just the homepage
		desc := fmt.Sprintf("Spider crawled the site map and discovered %d pages.\n", len(urls))

		// Show first 10
		limit := 10
		if len(urls) < 10 {
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
