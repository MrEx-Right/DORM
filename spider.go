package main

import (
	"DORM/models"
	"DORM/plugins"
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

// ==========================
// SPIDER ENGINE v3
// ==========================

// jsPathRegex is used exclusively to extract path hints from raw JavaScript content
// (paths embedded in JS strings cannot be discovered via HTML parsing alone).
var jsPathRegex = regexp.MustCompile(`(?i)["'](/[a-zA-Z0-9_\-\/\.]+)["']`)

// SpiderConfig holds tunable parameters that control crawler behavior.
type SpiderConfig struct {
	MaxDepth   int
	MaxURLs    int           // Maximum URLs to collect; 0 means unlimited.
	ReqTimeout time.Duration // Per-request HTTP timeout.
}

// DefaultSpiderConfig returns a SpiderConfig with sensible production defaults.
func DefaultSpiderConfig() SpiderConfig {
	return SpiderConfig{
		MaxDepth:   3,
		MaxURLs:    500,
		ReqTimeout: 15 * time.Second,
	}
}

type Spider struct {
	BaseURL   *url.URL
	Config    SpiderConfig
	Visited   sync.Map
	FoundURLs []string
	Endpoints []models.Endpoint
	Client    *http.Client // Proxy-aware persistent client
	mu        sync.Mutex
}

func NewSpider(targetURL string) (*Spider, error) {
	return NewSpiderWithConfig(targetURL, DefaultSpiderConfig())
}

func NewSpiderWithConfig(targetURL string, cfg SpiderConfig) (*Spider, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	client := models.GetClient()

	return &Spider{
		BaseURL:   u,
		Config:    cfg,
		FoundURLs: []string{},
		Endpoints: []models.Endpoint{},
		Client:    client,
	}, nil
}

func (s *Spider) Crawl() []string {
	s.crawlRecursive(s.BaseURL.String(), 0)

	// Persist discovered endpoints to SharedData for downstream plugins (e.g. SQLi, XSS).
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
	// Enforce maximum crawl depth.
	if depth >= s.Config.MaxDepth {
		return
	}

	// Skip already-visited URLs to avoid cycles.
	if _, loaded := s.Visited.LoadOrStore(currentURL, true); loaded {
		return
	}

	// Enforce the URL cap; a value of 0 disables the limit.
	s.mu.Lock()
	if s.Config.MaxURLs > 0 && len(s.FoundURLs) >= s.Config.MaxURLs {
		s.mu.Unlock()
		return
	}
	s.FoundURLs = append(s.FoundURLs, currentURL)
	s.mu.Unlock()

	// Register query parameters found in the current URL as a GET endpoint.
	if u, err := url.Parse(currentURL); err == nil && len(u.Query()) > 0 {
		var params []string
		for k := range u.Query() {
			params = append(params, k)
		}
		s.addEndpoint(currentURL, "GET", params)
	}

	// Fetch the raw HTML body of the current page.
	body, err := s.fetchBody(currentURL)
	if err != nil {
		return
	}

	// Parse the HTML body to extract links, forms, and inline JS paths.
	links, forms := s.extractFromHTML(body, currentURL)

	// Register each discovered form as a POST/GET endpoint.
	for _, f := range forms {
		resolved := s.resolveURL(f.action)
		if resolved != "" {
			s.addEndpoint(resolved, f.method, f.inputs)
		}
	}

	// Recursively follow in-scope links.
	for _, link := range links {
		absURL := s.resolveURL(link)
		if absURL != "" && strings.Contains(absURL, s.BaseURL.Hostname()) {
			s.crawlRecursive(absURL, depth+1)
		}
	}
}

// formData holds the extracted attributes of a single HTML form element.
type formData struct {
	action string
	method string
	inputs []string
}

// extractFromHTML safely parses the HTML body using golang.org/x/net/html.
// It returns all href links and form descriptors without using regular expressions.
func (s *Spider) extractFromHTML(body string, currentURL string) (links []string, forms []formData) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		// Graceful degradation: fall back to JS path extraction on parse failure.
		return s.extractJSPaths(body), nil
	}

	var currentForm *formData

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				for _, attr := range n.Attr {
					if attr.Key == "href" && attr.Val != "" {
						links = append(links, attr.Val)
					}
				}

			case "form":
				f := formData{
					action: currentURL, // default: submit to the current page URL
					method: "GET",
				}
				for _, attr := range n.Attr {
					switch attr.Key {
					case "action":
						if attr.Val != "" {
							f.action = attr.Val
						}
					case "method":
						if strings.ToUpper(attr.Val) == "POST" {
							f.method = "POST"
						}
					}
				}
				forms = append(forms, f)
				currentForm = &forms[len(forms)-1]

			case "input", "select", "textarea":
				if currentForm != nil {
					for _, attr := range n.Attr {
						if attr.Key == "name" && attr.Val != "" {
							currentForm.inputs = append(currentForm.inputs, attr.Val)
						}
					}
				}

			case "link":
				// Intentionally ignored: <link rel="..."> hrefs point to stylesheets, not pages.
			}
		}

		// Scan inline <script> blocks for embedded API path strings.
		if n.Type == html.ElementNode && n.Data == "script" {
			if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				jsPaths := s.extractJSPaths(n.FirstChild.Data)
				links = append(links, jsPaths...)
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)
	return links, forms
}

// extractJSPaths extracts API path hints from raw JavaScript content using regex.
// Regex is acceptable here because the input is plain text, not structured HTML.
func (s *Spider) extractJSPaths(jsContent string) []string {
	var paths []string
	matches := jsPathRegex.FindAllStringSubmatch(jsContent, -1)
	for _, match := range matches {
		if len(match) > 1 {
			resolved := s.resolveURL(match[1])
			if resolved != "" {
				paths = append(paths, match[1])
				s.addEndpoint(resolved, "GET", []string{})
			}
		}
	}
	return paths
}

func (s *Spider) addEndpoint(epUrl, method string, params []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, err := url.Parse(epUrl)
	if err != nil {
		return
	}
	basePath := u.Scheme + "://" + u.Host + u.Path

	for _, e := range s.Endpoints {
		eu, _ := url.Parse(e.URL)
		if eu != nil && (eu.Scheme+"://"+eu.Host+eu.Path) == basePath && e.Method == method {
			return // Duplicate detected — skip.
		}
	}

	s.Endpoints = append(s.Endpoints, models.Endpoint{
		URL:    epUrl,
		Method: method,
		Params: params,
	})
}

// fetchBody performs an HTTP GET request bounded by a context deadline.
// If the target server stalls, the request is cancelled after ReqTimeout.
func (s *Spider) fetchBody(target string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Config.ReqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return "", err
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Record paths that returned access-denied responses for later analysis.
	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 400 {
		if u, _ := url.Parse(target); u != nil {
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
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *Spider) resolveURL(href string) string {
	href = strings.TrimSpace(href)
	if href == "" ||
		strings.HasPrefix(href, "javascript") ||
		strings.HasPrefix(href, "mailto") ||
		strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "data:") {
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
	fmt.Printf("[*] Starting Spider on %s\n", startURL)

	spider, err := NewSpider(startURL)
	if err != nil {
		return nil
	}

	urls := spider.Crawl()

	if len(urls) > 0 {
		desc := fmt.Sprintf("Spider crawled the site map and discovered %d pages.\n", len(urls))

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
