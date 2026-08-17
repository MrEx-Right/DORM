package idorengine

import (
	"DORM/models"
	"io"
	"net/http"
	"regexp"
)

// ============================================================
//  UUID HARVESTER — Collects UUIDs from API responses
// ============================================================

var uuidRegex = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)

// RunUUIDHarvester tries to collect UUIDs from index endpoints to use in testing.
func RunUUIDHarvester(client *http.Client, baseURL string, target models.ScanTarget) []string {
	harvestEndpoints := []string{"/api/users", "/api/v1/users", "/users", "/api/profiles"}
	var harvested []string
	seen := make(map[string]bool)

	for _, ep := range harvestEndpoints {
		resp, err := client.Get(baseURL + ep)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		bodyStr := string(body)

		matches := uuidRegex.FindAllString(bodyStr, -1)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				harvested = append(harvested, m)
				if len(harvested) >= 5 {
					return harvested
				}
			}
		}
	}
	return harvested
}
