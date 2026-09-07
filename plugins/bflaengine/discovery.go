package bflaengine

import (
	"DORM/models"
	"net/http"
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
				if !seen[ep.URL] {
					seen[ep.URL] = true
					found = append(found, ep.URL)
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
		req.Header.Set("User-Agent", "DORM-BFLA-Probe/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		// 401/403 → endpoint exists but access is restricted (record for testing)
		// 200/204 → already accessible (record for method tampering tests)
		if resp.StatusCode == 401 || resp.StatusCode == 403 ||
			resp.StatusCode == 200 || resp.StatusCode == 204 {
			seen[fullURL] = true
			found = append(found, path)
		}
	}

	return found
}
