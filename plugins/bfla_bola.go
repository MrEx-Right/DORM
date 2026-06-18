package plugins

// ============================================================
//  BFLA / BOLA — Next-Gen (V1.0)
//  Broken Function Level Authorization  (OWASP API5:2023)
//  Broken Object Level Authorization    (OWASP API1:2023)
//
//  Differs from IDOR plugin:
//    - IDOR  → Sequential ID enumeration for data leakage
//    - BFLA  → HTTP method tampering (GET→PUT/DELETE) +
//              role boundary bypass (user→admin endpoint)
// ============================================================

import (
	"DORM/models"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type BFLABOLAPlugin struct{}

func (p *BFLABOLAPlugin) Name() string {
	return "BFLA/BOLA — Broken Function & Object Level Authorization"
}

// ============================================================
// ADMIN ENDPOINT PATTERNS (Function Level)
// ============================================================
var adminEndpointPatterns = []string{
	// REST Admin
	"/api/admin", "/api/admin/users", "/api/admin/user",
	"/api/admin/delete", "/api/admin/config", "/api/admin/settings",
	"/api/admin/reports", "/api/admin/logs", "/api/admin/audit",
	"/api/admin/stats", "/api/admin/metrics", "/api/admin/dashboard",
	"/api/v1/admin", "/api/v1/admin/users", "/api/v1/admin/config",
	"/api/v2/admin", "/api/v2/admin/users",
	// Management
	"/api/management", "/api/management/users",
	"/api/management/config", "/api/management/reports",
	// Privileged ops
	"/api/users/all", "/api/users/list",
	"/api/users/export", "/api/users/bulk",
	"/api/accounts/all", "/api/orders/all",
	"/api/reports/generate", "/api/billing/override",
	// Internal
	"/internal/admin", "/internal/api/users",
	"/internal/config", "/internal/management",
}

// HTTP methods to test for tampering
var dangerousMethods = []string{"PUT", "DELETE", "PATCH"}

// Object patterns to test cross-tenant access via method tampering
var objectPatterns = []string{
	"/api/v1/user/{ID}", "/api/v1/users/{ID}",
	"/api/v1/profile/{ID}", "/api/v1/account/{ID}",
	"/api/v1/order/{ID}", "/api/v1/invoice/{ID}",
	"/api/v1/document/{ID}", "/api/v1/ticket/{ID}",
	"/api/v2/user/{ID}", "/api/v2/users/{ID}",
	"/api/users/{ID}", "/api/orders/{ID}",
	"/api/accounts/{ID}", "/user/{ID}",
}

// Soft-error signals — server returns 200 but operation was denied
var softErrors = []string{
	"permission denied", "access denied", "not authorized",
	"unauthorized", "forbidden", "insufficient", "not allowed",
	"cannot perform", "operation not permitted",
}

// ============================================================
// MAIN RUN
// ============================================================
func (p *BFLABOLAPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	tokenA := getSharedString("idor_token_a")
	tokenB := getSharedString("idor_token_b")

	// ==================================================================
	// PHASE 1: ADMIN ENDPOINT DISCOVERY
	// Combine spider-discovered endpoints with known admin path patterns
	// ==================================================================
	adminEndpoints := discoverAdminEndpoints(client, baseURL, target)

	// ==================================================================
	// PHASE 2: UNAUTHORIZED ROLE ESCALATION (BFLA)
	// Attempt access to admin endpoints using a low-privilege token (B)
	// or unauthenticated requests
	// ==================================================================
	if result := testRoleEscalation(client, baseURL, target, adminEndpoints, tokenA, tokenB); result != nil {
		return result
	}

	// ==================================================================
	// PHASE 3: HTTP METHOD TAMPERING ON OBJECTS (BOLA via Method Swap)
	// Replay successful GET requests using PUT/DELETE/PATCH to test
	// whether write/delete authorization is enforced separately
	// ==================================================================
	if result := testMethodTampering(client, baseURL, target, tokenA, tokenB); result != nil {
		return result
	}

	// ==================================================================
	// PHASE 4: CROSS-TENANT OBJECT ACCESS VIA METHOD CHANGE
	// Use Token B to perform destructive methods on objects owned by Token A
	// ==================================================================
	if tokenA != "" && tokenB != "" {
		if result := testCrossTenantMethodAccess(client, baseURL, target, tokenA, tokenB); result != nil {
			return result
		}
	}

	return nil
}

// ============================================================
// PHASE 1: ADMIN ENDPOINT DISCOVERY
// ============================================================
func discoverAdminEndpoints(client *http.Client, baseURL string, target models.ScanTarget) []string {
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
	for _, path := range adminEndpointPatterns {
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
		resp.Body.Close()
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

// ============================================================
// PHASE 2: UNAUTHORIZED ROLE ESCALATION (BFLA)
// ============================================================
func testRoleEscalation(client *http.Client, baseURL string, target models.ScanTarget, endpoints []string, tokenA, tokenB string) *models.Vulnerability {
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
		respBase.Body.Close()

		// If anonymous access already returns 200 and it is not an admin path, skip
		if baseStatus == 200 && !strings.Contains(ep, "admin") {
			continue
		}

		// Test 1: Access with low-privilege Token B
		if tokenB != "" {
			reqB, err := newBFLARequest("GET", fullURL, tokenB, nil)
			if err == nil {
				respB, err := client.Do(reqB)
				if err == nil {
					bodyB := readBody(respB, 32768)
					if respB.StatusCode == 200 && len(bodyB) > 20 && !containsSoftError(bodyB) {
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
		bodyAnon := readBody(respAnon, 32768)
		if respAnon.StatusCode == 200 && len(bodyAnon) > 50 &&
			!containsSoftError(bodyAnon) && containsSensitiveAdminData(bodyAnon) {
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

// ============================================================
// PHASE 3: HTTP METHOD TAMPERING ON OBJECT ENDPOINTS (BOLA)
// ============================================================
func testMethodTampering(client *http.Client, baseURL string, target models.ScanTarget, tokenA, tokenB string) *models.Vulnerability {
	testIDs := []string{"1", "2", "3"}

	for _, pattern := range objectPatterns {
		for _, id := range testIDs {
			ep := strings.ReplaceAll(pattern, "{ID}", id)
			fullURL := baseURL + ep

			// Baseline: capture current state via GET
			var getReq *http.Request
			var err error
			if tokenA != "" {
				getReq, err = newBFLARequest("GET", fullURL, tokenA, nil)
			} else {
				getReq, err = http.NewRequest("GET", fullURL, nil)
				if getReq != nil {
					getReq.Header.Set("User-Agent", "DORM-BFLA-Probe/1.0")
				}
			}
			if err != nil {
				continue
			}

			getResp, err := client.Do(getReq)
			if err != nil {
				continue
			}
			getStatus := getResp.StatusCode
			getBody := readBody(getResp, 16384)

			// Only attempt method tampering on endpoints that return 200 via GET
			if getStatus != 200 || len(getBody) < 10 {
				continue
			}

			// Method tampering: attempt PUT / DELETE / PATCH
			for _, method := range dangerousMethods {
				// Minimal JSON body for PUT/PATCH requests
				var bodyReader io.Reader
				if method == "PUT" || method == "PATCH" {
					bodyReader = bytes.NewBufferString(`{"test":"bfla_probe","id":"` + id + `"}`)
				}

				var methodReq *http.Request
				// Use Token B (or anonymous) — lower privilege than the object owner
				if tokenB != "" {
					methodReq, err = newBFLARequest(method, fullURL, tokenB, bodyReader)
				} else {
					methodReq, err = http.NewRequest(method, fullURL, bodyReader)
					if methodReq != nil {
						methodReq.Header.Set("User-Agent", "DORM-BFLA-Probe/1.0")
						methodReq.Header.Set("Content-Type", "application/json")
					}
				}
				if err != nil {
					continue
				}

				methodResp, err := client.Do(methodReq)
				if err != nil {
					continue
				}
				methodBody := readBody(methodResp, 16384)
				methodStatus := methodResp.StatusCode

				// Success criteria:
				// 1. Server returned 200/201/204
				// 2. Response does not contain a soft-error denial message
				isSuccess := (methodStatus == 200 || methodStatus == 201 || methodStatus == 204) &&
					!containsSoftError(methodBody)

				if isSuccess {
					return &models.Vulnerability{
						Target:   target,
						Name:     fmt.Sprintf("CRITICAL BOLA — HTTP Method Tampering (GET → %s)", method),
						Severity: "CRITICAL",
						CVSS:     9.6,
						Description: fmt.Sprintf(
							"🔴 CRITICAL: An unauthorized write/delete operation was performed on an object by changing the HTTP method from GET to %s.\n\n"+
								"Endpoint: %s\n"+
								"Original GET Status: %d (read access confirmed)\n"+
								"Tampered Method: %s → HTTP %d\n"+
								"Response Size: %d bytes\n\n"+
								"The application enforces authorization for GET but fails to apply the same control for %s on the same resource.\n"+
								"This allows unauthorized modification or deletion of objects (BOLA via HTTP Method Tampering).",
							method, fullURL, getStatus, method, methodStatus, len(methodBody), method,
						),
						Solution:  "Apply independent authorization checks for every HTTP method. An endpoint returning 200 for GET must enforce the same ownership validation for PUT/PATCH/DELETE. Explicitly whitelist allowed methods per endpoint and reject all others with HTTP 405.",
						Reference: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
					}
				}
			}

			break // One successful GET match per pattern is sufficient
		}
	}

	return nil
}

// ============================================================
// PHASE 4: CROSS-TENANT OBJECT ACCESS VIA METHOD CHANGE
// ============================================================
func testCrossTenantMethodAccess(client *http.Client, baseURL string, target models.ScanTarget, tokenA, tokenB string) *models.Vulnerability {
	testIDs := []string{"1", "2", "3", "4", "5"}

	for _, pattern := range objectPatterns {
		for _, id := range testIDs {
			ep := strings.ReplaceAll(pattern, "{ID}", id)
			fullURL := baseURL + ep

			// Confirm object existence with Token A (owner)
			reqA, err := newBFLARequest("GET", fullURL, tokenA, nil)
			if err != nil {
				continue
			}
			respA, err := client.Do(reqA)
			if err != nil {
				continue
			}
			bodyA := readBody(respA, 32768)
			if respA.StatusCode != 200 || len(bodyA) < 20 {
				continue
			}

			// Brief delay to avoid triggering rate-limits between requests
			time.Sleep(150 * time.Millisecond)

			// Attempt DELETE/PUT on the same object using Token B (non-owner)
			for _, method := range []string{"DELETE", "PUT"} {
				var bodyReader io.Reader
				if method == "PUT" {
					bodyReader = bytes.NewBufferString(`{"role":"admin","status":"active"}`)
				}

				reqB, err := newBFLARequest(method, fullURL, tokenB, bodyReader)
				if err != nil {
					continue
				}
				respB, err := client.Do(reqB)
				if err != nil {
					continue
				}
				bodyB := readBody(respB, 16384)

				if (respB.StatusCode == 200 || respB.StatusCode == 204) && !containsSoftError(bodyB) {
					return &models.Vulnerability{
						Target:   target,
						Name:     fmt.Sprintf("CRITICAL BOLA — Cross-Tenant %s via Token B", method),
						Severity: "CRITICAL",
						CVSS:     9.7,
						Description: fmt.Sprintf(
							"🔴 CRITICAL: User B (Token B) successfully performed a %s operation on an object owned by User A.\n\n"+
								"Endpoint: %s\n"+
								"Object Owner: Token A\n"+
								"Unauthorized Actor: Token B (separate, lower-privilege user)\n"+
								"HTTP Method: %s → Status: %d\n"+
								"Token A GET Status: %d (object confirmed present)\n\n"+
								"This goes beyond classic IDOR (read-only enumeration) — the attacker can modify or delete\n"+
								"another user's resources, representing a severe cross-tenant data integrity violation.",
							method, fullURL, method, respB.StatusCode, respA.StatusCode,
						),
						Solution:  "Object-level authorization must cover all HTTP methods independently. A user who can read an object does not implicitly have write or delete rights. Perform explicit ownership verification for every mutating operation.",
						Reference: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
					}
				}
			}

			break // One confirmed object per pattern is sufficient
		}
	}

	return nil
}

// ============================================================
// HELPERS
// ============================================================

// newBFLARequest creates an HTTP request with an Authorization header
func newBFLARequest(method, url, token string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DORM-BFLA-Probe/1.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		if strings.HasPrefix(strings.ToLower(token), "bearer ") || strings.HasPrefix(token, "Basic ") {
			req.Header.Set("Authorization", token)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	return req, nil
}

// containsSoftError detects cases where the server returns HTTP 200
// but the response body indicates the operation was actually denied
func containsSoftError(body string) bool {
	lower := strings.ToLower(body)
	for _, se := range softErrors {
		if strings.Contains(lower, se) {
			return true
		}
	}
	return false
}

// containsSensitiveAdminData checks whether a response body contains
// at least two admin-specific data keywords, reducing false positives
func containsSensitiveAdminData(body string) bool {
	lower := strings.ToLower(body)
	adminKeywords := []string{
		"user_list", "users", "\"role\"", "\"admin\"", "\"permissions\"",
		"\"email\"", "\"password\"", "audit_log", "\"config\"",
		"\"settings\"", "system", "\"token\"", "\"secret\"",
	}
	count := 0
	for _, kw := range adminKeywords {
		if strings.Contains(lower, kw) {
			count++
		}
	}
	return count >= 2 // Require at least 2 admin keywords to reduce false positives
}

// parseBFLAJSON attempts to decode a response body as JSON for structural validation
func parseBFLAJSON(body string) bool {
	var m map[string]interface{}
	return json.Unmarshal([]byte(body), &m) == nil
}
