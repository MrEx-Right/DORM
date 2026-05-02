package main

import (
	"DORM/models"
	"DORM/plugins"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// ==========================
// SPIDER ENGINE v2
// ==========================

// Global Regex compilation for performance.
var (
	linkRegex     = regexp.MustCompile(`(?i)href\s*=\s*["']?([^"'\s>]+)["']?`)
	formRegex     = regexp.MustCompile(`(?i)<form[^>]*action\s*=\s*["']?([^"'\s>]+)["']?[^>]*>`)
	inputRegex    = regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']?([^"'\s>]+)["']?[^>]*>`)
	jsPathRegex   = regexp.MustCompile(`(?i)["'](\/[a-zA-Z0-9_\-\/\.]+)["']`)
)

type Spider struct {
	BaseURL   *url.URL
	MaxDepth  int
	Visited   sync.Map
	FoundURLs []string
	Endpoints []models.Endpoint
	Client    *http.Client // Persistent HTTP Client (Proxy aware)
	mu        sync.Mutex
}

func NewSpider(targetURL string) (*Spider, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Use the global proxy-aware client
	client := models.GetClient()
	
	// Temporarily update CheckRedirect for spider scope, but standard client doesn't expose it easily.
	// That's fine, we will just handle scope manually during crawling.

	return &Spider{
		BaseURL:   u,
		MaxDepth:  3, // Depth 3 for deep crawling
		FoundURLs: []string{},
		Endpoints: []models.Endpoint{},
		Client:    client,
	}, nil
}

func (s *Spider) Crawl() []string {
	// Add start URL to the queue to begin crawling
	s.crawlRecursive(s.BaseURL.String(), 0)

	// Save the endpoints to SharedData for other plugins (SQLi, XSS) to use
	if len(s.Endpoints) > 0 {
		key := "endpoints_" + s.BaseURL.Hostname()
		existing, ok := models.SharedData.Load(key)
		var eps []models.Endpoint
		if ok {
			eps = existing.([]models.Endpoint)
		}
		eps = append(eps, s.Endpoints...)
		models.SharedData.Store(key, eps)
		fmt.Printf("[*] Spider saved %d endpoints to SharedData for target %s\n", len(eps), s.BaseURL.Hostname())
	}

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
	if len(s.FoundURLs) > 150 {
		s.mu.Unlock()
		return
	}
	s.FoundURLs = append(s.FoundURLs, currentURL)
	s.mu.Unlock()

	// Parse parameters from current URL and add to endpoints
	if u, err := url.Parse(currentURL); err == nil && len(u.Query()) > 0 {
		var params []string
		for k := range u.Query() {
			params = append(params, k)
		}
		s.addEndpoint(currentURL, "GET", params)
	}

	// Fetch page content
	body, err := s.fetchBody(currentURL)
	if err != nil {
		return
	}

	// Extract and traverse links, forms, and JS paths
	links := s.extractLinks(body, currentURL)
	for _, link := range links {
		absURL := s.resolveURL(link)
		if absURL != "" && strings.Contains(absURL, s.BaseURL.Hostname()) {
			s.crawlRecursive(absURL, depth+1)
		}
	}
}

func (s *Spider) addEndpoint(epUrl, method string, params []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Deduplicate endpoints based on URL path and Method
	u, err := url.Parse(epUrl)
	if err != nil {
		return
	}
	basePath := u.Scheme + "://" + u.Host + u.Path
	
	for _, e := range s.Endpoints {
		eu, _ := url.Parse(e.URL)
		if eu != nil && (eu.Scheme + "://" + eu.Host + eu.Path) == basePath && e.Method == method {
			return // Already exists
		}
	}
	
	s.Endpoints = append(s.Endpoints, models.Endpoint{
		URL:    epUrl,
		Method: method,
		Params: params,
	})
}

func (s *Spider) fetchBody(target string) (string, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return "", err
	}
	
	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 400 {
		u, _ := url.Parse(target)
		if u != nil {
			key := "forbidden_" + s.BaseURL.Hostname()
			existing, ok := models.SharedData.Load(key)
			var paths []string
			if ok {
				paths = existing.([]string)
			}
			found := false
			for _, p := range paths {
				if p == u.Path {
					found = true
					break
				}
			}
			if !found {
				paths = append(paths, u.Path)
				models.SharedData.Store(key, paths)
			}
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	return string(body), nil
}

func (s *Spider) extractLinks(body string, currentURL string) []string {
	var links []string
	
	// 1. HREF Links
	matches := linkRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			links = append(links, match[1])
		}
	}

	// 2. JS Paths (API Endpoints)
	jsMatches := jsPathRegex.FindAllStringSubmatch(body, -1)
	for _, match := range jsMatches {
		if len(match) > 1 {
			links = append(links, match[1])
			s.addEndpoint(s.resolveURL(match[1]), "GET", []string{})
		}
	}

	// 3. Form Extraction (POST Endpoints)
	// This splits body by <form> tags roughly
	formBlocks := strings.Split(strings.ToLower(body), "<form")
	for i := 1; i < len(formBlocks); i++ {
		block := "<form" + formBlocks[i]
		
		// Find Action
		action := ""
		actionMatch := formRegex.FindStringSubmatch(block)
		if len(actionMatch) > 1 {
			action = actionMatch[1]
		} else {
			action = currentURL
		}
		
		// Find Inputs
		var inputs []string
		inputMatches := inputRegex.FindAllStringSubmatch(block, -1)
		for _, im := range inputMatches {
			if len(im) > 1 {
				inputs = append(inputs, im[1])
			}
		}

		if len(inputs) > 0 {
			resolvedAction := s.resolveURL(action)
			if resolvedAction != "" {
				s.addEndpoint(resolvedAction, "POST", inputs)
			}
		}
	}

	return links
}

func (s *Spider) resolveURL(href string) string {
	href = strings.TrimSpace(href)
	if strings.HasPrefix(href, "javascript") || strings.HasPrefix(href, "mailto") || strings.HasPrefix(href, "#") || href == "" {
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

func (p *SpiderPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !plugins.IsWebPort(target.Port) {
		return nil
	}

	startURL := plugins.GetURL(target, "/")

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

		return &models.Vulnerability{
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
