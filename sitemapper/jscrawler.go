package sitemapper

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// jsEndpointPatterns is an ordered list of regex patterns to extract API paths from JS source.
// Ordered from most specific (framework-aware) to least specific (generic path string).
var jsEndpointPatterns = []*regexp.Regexp{
	// fetch('/api/...') and axios.get('/api/...')
	regexp.MustCompile(`(?i)(?:fetch|axios\.(?:get|post|put|delete|patch|head))\s*\(\s*['"]([/][^'"?#\s]{2,})['"]`),
	// Express/Koa router: router.get('/path', ...) or app.post('/path', ...)
	regexp.MustCompile(`(?i)(?:router|app)\s*\.\s*(?:get|post|put|delete|patch|use|all)\s*\(\s*['"]([/][^'"?#\s]{2,})['"]`),
	// React Router / Angular: path: '/dashboard'
	regexp.MustCompile(`(?i)(?:path|route)\s*:\s*['"]([/][^'"?#\s]{2,})['"]`),
	// url: '/api/endpoint' or baseURL: '/api'
	regexp.MustCompile(`(?i)(?:url|baseURL|endpoint)\s*(?::|=)\s*['"]([/][^'"?#\s]{2,})['"]`),
	// Generic quoted path strings (minimum 3 chars, starts with /)
	regexp.MustCompile(`['"]([/][a-zA-Z0-9_\-/]{3,}(?:\.[a-zA-Z]{2,4})?)['"]`),
}

// pathBlacklist filters out common non-API paths that generate too much noise.
var pathBlacklist = map[string]bool{
	"/":          true,
	"//":         true,
	"/css/":      true,
	"/js/":       true,
	"/images/":   true,
	"/fonts/":    true,
	"/static/":   true,
	"/assets/":   true,
	"/favicon/":  true,
	"/icon/":     true,
}

// isBlacklisted checks if a path should be excluded from extraction.
func isBlacklisted(path string) bool {
	if len(path) < 3 {
		return true
	}
	// Skip static asset extensions
	lower := strings.ToLower(path)
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
		".pdf", ".zip", ".css", ".map"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	for prefix := range pathBlacklist {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// ExtractPathsFromJS parses raw JavaScript content and extracts API endpoint paths.
// It uses multiple layered regex patterns, deduplicating results.
func ExtractPathsFromJS(jsContent string) []string {
	seen := make(map[string]bool)
	var paths []string

	for _, pattern := range jsEndpointPatterns {
		matches := pattern.FindAllStringSubmatch(jsContent, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			path := match[1]
			if !seen[path] && !isBlacklisted(path) {
				seen[path] = true
				paths = append(paths, path)
			}
		}
	}

	return paths
}

// FetchAndAnalyzeJS fetches a JavaScript file and extracts endpoint paths from its content.
// Returns a JSFile with the URL and all extracted paths.
func FetchAndAnalyzeJS(client *http.Client, jsURL string, baseURL *url.URL) JSFile {
	jsFile := JSFile{URL: jsURL, Paths: []string{}}

	ctx, cancel := newTimeoutContext(10 * time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		return jsFile
	}
	req.Header.Set("User-Agent", "DORM-Sitemapper/1.19.0")

	resp, err := client.Do(req)
	if err != nil {
		return jsFile
	}
	defer resp.Body.Close()

	// Limit JS file size to 2MB to avoid memory issues
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return jsFile
	}

	jsFile.Paths = ExtractPathsFromJS(string(body))
	return jsFile
}
