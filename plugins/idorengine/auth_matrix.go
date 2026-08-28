package idorengine

import (
	"DORM/models"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
)

// ============================================================
//  DUAL-PROFILE AUTH MATRIX (IDOR Detection)
// ============================================================

// RunAuthMatrix performs the core IDOR check using two distinct user profiles.
func RunAuthMatrix(client *http.Client, baseURL string, target models.ScanTarget, user1Token, user2Token string, endpoints, testIDs []string) *models.Vulnerability {
	for _, ep := range endpoints {
		for _, id := range testIDs {
			targetURL := baseURL + ep + url.PathEscape(id)

			// 1. Request as User 1 (Baseline)
			req1, _ := http.NewRequest("GET", targetURL, nil)
			req1.Header.Set("Authorization", "Bearer "+user1Token)
			resp1, err := client.Do(req1)
			if err != nil {
				continue
			}
			body1, _ := io.ReadAll(io.LimitReader(resp1.Body, 65536))
			_ = resp1.Body.Close()
			len1 := len(body1)
			code1 := resp1.StatusCode

			// Only proceed if User 1 can access this resource
			if code1 != 200 {
				continue
			}

			// 2. Request as User 2 (Attack)
			req2, _ := http.NewRequest("GET", targetURL, nil)
			req2.Header.Set("Authorization", "Bearer "+user2Token)
			resp2, err := client.Do(req2)
			if err != nil {
				continue
			}
			body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 65536))
			_ = resp2.Body.Close()
			len2 := len(body2)
			code2 := resp2.StatusCode

			// 3. Analyze for IDOR
			// If User 2 gets HTTP 200 AND the response size is very similar, it's an IDOR
			if code2 == 200 {
				diff := math.Abs(float64(len1 - len2))
				if diff < 100 && DetectPII(string(body2)) {
					return &models.Vulnerability{
						Target:   target,
						Name:     "Insecure Direct Object Reference (IDOR) / BOLA",
						Severity: "CRITICAL",
						CVSS:     9.1,
						Description: fmt.Sprintf(
							"Cross-user data access detected.\nUser 2 successfully accessed User 1's resource.\n"+
								"Endpoint: %s\nTarget ID: %s\n"+
								"User 1 Response: HTTP %d (%d bytes)\n"+
								"User 2 Response: HTTP %d (%d bytes)\n"+
								"PII Leak: Yes",
							targetURL, id, code1, len1, code2, len2,
						),
						Solution:  "Implement robust authorization checks at the data object level (BOLA). Ensure the requesting user owns the object being accessed.",
						Reference: "OWASP API1:2023 - Broken Object Level Authorization",
					}
				}
			}
		}
	}
	return nil
}
