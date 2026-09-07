package bflaengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"strings"
)

// TestRoleEscalation is Phase 2 (BFLA): attempts access to admin endpoints
// using a low-privilege token (B) or unauthenticated requests.
func TestRoleEscalation(client *http.Client, baseURL string, target models.ScanTarget, endpoints []string, tokenA, tokenB string) *models.Vulnerability {
	for _, ep := range endpoints {
		fullURL := baseURL + ep

		// Baseline: unauthenticated request — expect 401/403
		reqBase, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		reqBase.Header.Set("User-Agent", "DORM-BFLA-Probe/1.0")
		respBase, err := client.Do(reqBase)
		if err != nil {
			continue
		}
		baseStatus := respBase.StatusCode
		_ = respBase.Body.Close()

		// If anonymous access already returns 200 and it is not an admin path, skip
		if baseStatus == 200 && !strings.Contains(ep, "admin") {
			continue
		}

		// Test 1: Access with low-privilege Token B
		if tokenB != "" {
			reqB, err := NewBFLARequest("GET", fullURL, tokenB, nil)
			if err == nil {
				respB, err := client.Do(reqB)
				if err == nil {
					bodyB := models.ReadBody(respB, 32768)
					if respB.StatusCode == 200 && len(bodyB) > 20 && !ContainsSoftError(bodyB) {
						return &models.Vulnerability{
							Target:   target,
							Name:     "CRITICAL BFLA — Unauthorized Admin Endpoint Access",
							Severity: "CRITICAL",
							CVSS:     9.8,
							Description: fmt.Sprintf(
								"🔴 CRITICAL: A low-privilege user (Token B) successfully accessed a restricted admin endpoint without proper authorization.\n\n"+
									"Endpoint: %s\n"+
									"Anonymous Baseline Status: %d (expected: 401/403)\n"+
									"Token B Access: HTTP %d — response body received (%d bytes)\n\n"+
									"This confirms a Broken Function Level Authorization (BFLA) vulnerability.\n"+
									"Admin functions are reachable with a regular user token, indicating missing role-based access control on function-level endpoints.",
								fullURL, baseStatus, respB.StatusCode, len(bodyB),
							),
							Solution:  "Enforce role-based access control (RBAC) on every API endpoint. Protect admin functions behind a dedicated authorization middleware that validates the role/permissions carried by the token, not just its presence.",
							Reference: "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
						}
					}
				}
			}
		}

		// Test 2: Direct unauthenticated access (no token)
		reqAnon, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		reqAnon.Header.Set("User-Agent", "Mozilla/5.0")
		respAnon, err := client.Do(reqAnon)
		if err != nil {
			continue
		}
		bodyAnon := models.ReadBody(respAnon, 32768)
		if respAnon.StatusCode == 200 && len(bodyAnon) > 50 &&
			!ContainsSoftError(bodyAnon) && ContainsSensitiveAdminData(bodyAnon) {
			return &models.Vulnerability{
				Target:   target,
				Name:     "HIGH BFLA — Admin Endpoint Publicly Accessible",
				Severity: "HIGH",
				CVSS:     8.6,
				Description: fmt.Sprintf(
					"🟠 HIGH: An admin endpoint is accessible without any authentication.\n\n"+
						"Endpoint: %s\n"+
						"HTTP Status: %d\n"+
						"Response Size: %d bytes\n"+
						"Sensitive admin data keywords detected in response body.\n\n"+
						"This endpoint should be restricted exclusively to authenticated administrators.",
					fullURL, respAnon.StatusCode, len(bodyAnon),
				),
				Solution:  "Place admin endpoints behind mandatory authentication and authorization middleware. Return HTTP 401 for unauthenticated requests and HTTP 403 for authenticated but unauthorized users.",
				Reference: "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
			}
		}
	}

	return nil
}
