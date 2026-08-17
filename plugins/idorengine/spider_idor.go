package idorengine

import (
	"DORM/models"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
)

// ============================================================
//  SPIDER IDOR INTEGRATION
// ============================================================

// RunSpiderIDOR tests parameterized endpoints found by the spider for IDOR.
func RunSpiderIDOR(client *http.Client, target models.ScanTarget, user1, user2 string) *models.Vulnerability {
	if user1 == "" || user2 == "" {
		return nil
	}

	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if !ok {
		return nil
	}

	spiderEndpoints := existing.([]models.Endpoint)

	for _, ep := range spiderEndpoints {
		if ep.Method == "GET" && len(ep.Params) > 0 {
			// Find parameters that look like IDs
			hasIDParam := false
			for _, param := range ep.Params {
				if strings.Contains(strings.ToLower(param), "id") || param == "user" || param == "profile" {
					hasIDParam = true
					break
				}
			}

			if hasIDParam {
				req1, _ := http.NewRequest("GET", ep.URL, nil)
				req1.Header.Set("Authorization", "Bearer "+user1)
				resp1, err := client.Do(req1)
				if err != nil {
					continue
				}
				body1, _ := io.ReadAll(io.LimitReader(resp1.Body, 65536))
				resp1.Body.Close()
				len1 := len(body1)

				if resp1.StatusCode == 200 {
					req2, _ := http.NewRequest("GET", ep.URL, nil)
					req2.Header.Set("Authorization", "Bearer "+user2)
					resp2, err := client.Do(req2)
					if err != nil {
						continue
					}
					body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 65536))
					resp2.Body.Close()
					len2 := len(body2)

					diff := math.Abs(float64(len1 - len2))
					if resp2.StatusCode == 200 && diff < 50 && DetectPII(string(body2)) {
						return &models.Vulnerability{
							Target:   target,
							Name:     "IDOR on Spider-Discovered Parameter",
							Severity: "CRITICAL",
							CVSS:     9.1,
							Description: fmt.Sprintf(
								"Cross-user access detected on parameter.\nURL: %s\n"+
									"User 1: %d bytes | User 2: %d bytes",
								ep.URL, len1, len2,
							),
							Solution:  "Implement object-level authorization checks.",
							Reference: "OWASP BOLA",
						}
					}
				}
			}
		}
	}
	return nil
}
