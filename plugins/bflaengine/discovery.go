package bflaengine

import (
	"DORM/models"
	"net/http"
	"net/url"
	"strings"
)

// DiscoverAdminEndpoints combines spider-discovered endpoints matching
// admin-like path patterns with direct probes of known admin path patterns.
func DiscoverAdminEndpoints(client *http.Client, baseURL string, target models.ScanTarget) []string {
	found := []string{}
	seen := make(map[string]bool)

	// Augment with spider-discovered endpoints that match admin path patterns
	key := "endpoints_" + target.IP
	if existing, ok := models.SharedData.Load(key); ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			lower := strings.ToLower(ep.URL)
			if strings.Contains(lower, "/admin") ||
				strings.Contains(lower, "/management") ||
				strings.Contains(lower, "/internal") {
				// Callers prefix baseURL, so keep only the path: appending the
				// full spider URL produced "http://host:80http://host/admin",
				// which never parsed, so spider endpoints were never tested.
				path := ep.URL
				if u, err := url.Parse(ep.URL); err == nil && u.Path != "" {
					path = u.RequestURI()
				}
				if !seen[baseURL+path] {
					seen[baseURL+path] = true
					found = append(found, path)
				}
			}
		}
	}

	// Probe known admin path patterns
	for _, path := range AdminEndpointPatterns {
		fullURL := baseURL + path
		if seen[fullURL] {
			continue
		}
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		size := len(models.ReadBody(resp, 65536))
		// 401/403 → endpoint exists but access is restricted (record for testing)
		// 200/204 → already accessible (record for method tampering tests),
		// unless a random sibling path answers the same way (catch-all route)
		if resp.StatusCode == 200 || resp.StatusCode == 204 {
			if models.ProbeSibling(client, fullURL, "GET", "", "").SameAs(resp.StatusCode, size) {
				continue
			}
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 ||
			resp.StatusCode == 200 || resp.StatusCode == 204 {
			seen[fullURL] = true
			found = append(found, path)
		}
	}

	return found
}
