package idorengine

import (
	"DORM/models"
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
)

// ============================================================
//  GRAPHQL IDOR DETECTOR
// ============================================================

// RunGraphQLIDOR tests for IDOR in GraphQL API endpoints.
func RunGraphQLIDOR(client *http.Client, baseURL string, target models.ScanTarget, user1, user2 string, testIDs []string) *models.Vulnerability {
	if user1 == "" || user2 == "" {
		return nil
	}

	gqlEndpoints := []string{"/graphql", "/api/graphql", "/v1/graphql"}

	for _, ep := range gqlEndpoints {
		targetURL := baseURL + ep

		// Check if it's actually a GraphQL endpoint
		req, _ := http.NewRequest("POST", targetURL, strings.NewReader(`{"query":"{__typename}"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}

		// Test queries
		for _, id := range testIDs {
			payloads := []string{
				fmt.Sprintf(`{"query":"query{user(id:\"%s\"){id email phone name}}"}`, id),
				fmt.Sprintf(`{"query":"query{profile(id:\"%s\"){email address}}"}`, id),
			}

			for _, payload := range payloads {
				req1, _ := http.NewRequest("POST", targetURL, bytes.NewReader([]byte(payload)))
				req1.Header.Set("Content-Type", "application/json")
				req1.Header.Set("Authorization", "Bearer "+user1)
				resp1, err := client.Do(req1)
				if err != nil {
					continue
				}
				body1, _ := io.ReadAll(io.LimitReader(resp1.Body, 65536))
				resp1.Body.Close()
				len1 := len(body1)

				if resp1.StatusCode == 200 && !strings.Contains(string(body1), "errors") {
					req2, _ := http.NewRequest("POST", targetURL, bytes.NewReader([]byte(payload)))
					req2.Header.Set("Content-Type", "application/json")
					req2.Header.Set("Authorization", "Bearer "+user2)
					resp2, err := client.Do(req2)
					if err != nil {
						continue
					}
					body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 65536))
					resp2.Body.Close()
					len2 := len(body2)

					diff := math.Abs(float64(len1 - len2))
					if resp2.StatusCode == 200 && !strings.Contains(string(body2), "errors") && diff < 50 && DetectPII(string(body2)) {
						return &models.Vulnerability{
							Target:   target,
							Name:     "GraphQL BOLA / IDOR",
							Severity: "CRITICAL",
							CVSS:     9.1,
							Description: fmt.Sprintf(
								"Cross-user access detected via GraphQL query.\nURL: %s\nPayload: %s\nUser 2 successfully fetched User 1's data.",
								targetURL, payload,
							),
							Solution:  "Implement authorization checks inside GraphQL resolvers.",
							Reference: "OWASP GraphQL Security",
						}
					}
				}
			}
		}
	}
	return nil
}
