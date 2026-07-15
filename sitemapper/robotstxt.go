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
	req.Header.Set("User-Agent", "DORM-Sitemapper/1.19.0")

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

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

// ParseSitemapXML fetches and recursively parses a sitemap XML file.
// It handles both standard sitemaps and sitemap index files.
// Returns a flat list of all discovered page URLs.
func ParseSitemapXML(client *http.Client, sitemapURL string, depth int) []string {
	// Limit recursion depth for sitemap indexes
	if depth > 3 {
		return nil
	}

	ctx, cancel := newTimeoutContext(15 * time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "DORM-Sitemapper/1.19.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

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
			if u.Loc != "" {
				urls = append(urls, u.Loc)
			}
		}
		return urls
	}

	// Try sitemap index
	var sitemapIndex xmlSitemapIndex
	if err := xml.Unmarshal(body, &sitemapIndex); err == nil && len(sitemapIndex.Sitemaps) > 0 {
		for _, sm := range sitemapIndex.Sitemaps {
			if sm.Loc != "" {
				childURLs := ParseSitemapXML(client, sm.Loc, depth+1)
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
		ctx, cancel := newTimeoutContext(5 * time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "HEAD", u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			valid = append(valid, u)
		}
	}

	return valid
}
