package sitemapper

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// =============================================
// ROBOTS.TXT PARSER
// =============================================

// RobotsResult holds the parsed data from a robots.txt file.
type RobotsResult struct {
	Disallows []string // Paths disallowed for all agents
	Allows    []string // Paths explicitly allowed
	Sitemaps  []string // Sitemap URLs declared in robots.txt
}

// FetchRobotsTxt fetches and parses the robots.txt for the target.
// It collects Disallow/Allow directives for all user agents and Sitemap declarations.
func FetchRobotsTxt(client *http.Client, baseURL *url.URL) RobotsResult {
	result := RobotsResult{}

	robotsURL := fmt.Sprintf("%s://%s/robots.txt", baseURL.Scheme, baseURL.Host)
	ctx, cancel := newTimeoutContext(10 * time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return result
	}

	// Track whether we are inside a wildcard (*) or DORM-agent block.
	inRelevantBlock := false

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 512*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split directive: key: value
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		directive := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch directive {
		case "user-agent":
			// Enter block if wildcard or DORM-specific
			agent := strings.ToLower(value)
			inRelevantBlock = agent == "*" || strings.Contains(agent, "dorm")
		case "disallow":
			if inRelevantBlock && value != "" {
				result.Disallows = append(result.Disallows, value)
			}
		case "allow":
			if inRelevantBlock && value != "" {
				result.Allows = append(result.Allows, value)
			}
		case "sitemap":
			if value != "" {
				result.Sitemaps = append(result.Sitemaps, value)
			}
		}
	}

	return result
}

// =============================================
// SITEMAP.XML PARSER
// =============================================

// xmlURLSet represents a standard sitemap <urlset>
type xmlURLSet struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []xmlURL `xml:"url"`
}

// xmlSitemapIndex represents a sitemap index <sitemapindex>
type xmlSitemapIndex struct {
	XMLName  xml.Name     `xml:"sitemapindex"`
	Sitemaps []xmlSitemap `xml:"sitemap"`
}

type xmlURL struct {
	Loc      string `xml:"loc"`
	LastMod  string `xml:"lastmod"`
	Priority string `xml:"priority"`
}

type xmlSitemap struct {
	Loc string `xml:"loc"`
}

// sitemapMaxFetches and sitemapMaxURLs bound one crawl's sitemap phase. A
// sitemap index that lists itself (or a chain of indexes that list each
// other) used to be followed three levels deep with no total: 10 entries
// were 1,111 requests, 50 entries about 127,000.
const (
	sitemapMaxFetches = 50
	sitemapMaxURLs    = 10000
)

// sitemapBudget is shared by every sitemap fetched in one crawl.
type sitemapBudget struct {
	seen    map[string]bool
	fetches int
	urls    int
}

// ParseSitemaps fetches and parses the given sitemap files, following
// sitemap indexes, and returns a flat list of every page URL they list.
// Each sitemap is fetched at most once, and the whole call stays within
// sitemapMaxFetches requests and sitemapMaxURLs page URLs.
func ParseSitemaps(client *http.Client, sitemapURLs []string) []string {
	b := &sitemapBudget{seen: make(map[string]bool)}
	var urls []string
	for _, u := range sitemapURLs {
		urls = append(urls, parseSitemapXML(client, u, 0, b)...)
	}
	return urls
}

// parseSitemapXML fetches and recursively parses a sitemap XML file.
// It handles both standard sitemaps and sitemap index files.
func parseSitemapXML(client *http.Client, sitemapURL string, depth int, b *sitemapBudget) []string {
	// Limit recursion depth for sitemap indexes
	if depth > 3 || b.seen[sitemapURL] || b.fetches >= sitemapMaxFetches || b.urls >= sitemapMaxURLs {
		return nil
	}
	b.seen[sitemapURL] = true
	b.fetches++

	ctx, cancel := newTimeoutContext(15 * time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil
	}

	var urls []string

	// Try standard urlset first
	var urlSet xmlURLSet
	if err := xml.Unmarshal(body, &urlSet); err == nil && len(urlSet.URLs) > 0 {
		for _, u := range urlSet.URLs {
			if b.urls >= sitemapMaxURLs {
				break
			}
			if u.Loc != "" {
				urls = append(urls, u.Loc)
				b.urls++
			}
		}
		return urls
	}

	// Try sitemap index
	var sitemapIndex xmlSitemapIndex
	if err := xml.Unmarshal(body, &sitemapIndex); err == nil && len(sitemapIndex.Sitemaps) > 0 {
		for _, sm := range sitemapIndex.Sitemaps {
			if sm.Loc != "" {
				childURLs := parseSitemapXML(client, strings.TrimSpace(sm.Loc), depth+1, b)
				urls = append(urls, childURLs...)
			}
		}
		return urls
	}

	return urls
}

// DefaultSitemapPaths lists common sitemap locations to probe if robots.txt has none.
var DefaultSitemapPaths = []string{
	"/sitemap.xml",
	"/sitemap_index.xml",
	"/sitemap-index.xml",
	"/sitemap/sitemap.xml",
}

// DiscoverSitemaps tries to find sitemap.xml files for a target.
// First checks robots.txt Sitemap declarations, then probes common paths.
func DiscoverSitemaps(client *http.Client, baseURL *url.URL, robotsSitemaps []string) []string {
	var found []string
	seen := make(map[string]bool)

	add := func(u string) {
		if !seen[u] {
			seen[u] = true
			found = append(found, u)
		}
	}

	// Declared in robots.txt — these are authoritative
	for _, s := range robotsSitemaps {
		add(s)
	}

	// Probe well-known paths
	for _, path := range DefaultSitemapPaths {
		probe := fmt.Sprintf("%s://%s%s", baseURL.Scheme, baseURL.Host, path)
		add(probe)
	}

	// Filter to only those that actually exist (200 OK)
	var valid []string
	for _, u := range found {
		if sitemapExists(client, u) {
			valid = append(valid, u)
		}
	}

	return valid
}

// sitemapExists sends a HEAD for u; its own function so each probe's
// timeout is released when it returns, not when the whole loop does.
func sitemapExists(client *http.Client, u string) bool {
	ctx, cancel := newTimeoutContext(5 * time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "HEAD", u, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
