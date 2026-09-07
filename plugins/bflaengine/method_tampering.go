package bflaengine

import (
	"DORM/models"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TestMethodTampering is Phase 3 (BOLA via method swap): replays successful
// GET requests using PUT/DELETE/PATCH to test whether write/delete
// authorization is enforced separately from read authorization.
func TestMethodTampering(client *http.Client, baseURL string, target models.ScanTarget, tokenA, tokenB string) *models.Vulnerability {
	testIDs := []string{"1", "2", "3"}

	for _, pattern := range ObjectPatterns {
		for _, id := range testIDs {
			ep := strings.ReplaceAll(pattern, "{ID}", id)
			fullURL := baseURL + ep

			// Baseline: capture current state via GET
			var getReq *http.Request
			var err error
			if tokenA != "" {
				getReq, err = NewBFLARequest("GET", fullURL, tokenA, nil)
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
			getBody := models.ReadBody(getResp, 16384)

			// Only attempt method tampering on endpoints that return 200 via GET
			if getStatus != 200 || len(getBody) < 10 {
				continue
			}

			// Method tampering: attempt PUT / DELETE / PATCH
			for _, method := range DangerousMethods {
				// Minimal JSON body for PUT/PATCH requests
				var bodyReader io.Reader
				if method == "PUT" || method == "PATCH" {
					bodyReader = bytes.NewBufferString(`{"test":"bfla_probe","id":"` + id + `"}`)
				}

				var methodReq *http.Request
				// Use Token B (or anonymous) — lower privilege than the object owner
				if tokenB != "" {
					methodReq, err = NewBFLARequest(method, fullURL, tokenB, bodyReader)
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
				methodBody := models.ReadBody(methodResp, 16384)
				methodStatus := methodResp.StatusCode

				// Success criteria:
				// 1. Server returned 200/201/204
				// 2. Response does not contain a soft-error denial message
				isSuccess := (methodStatus == 200 || methodStatus == 201 || methodStatus == 204) &&
					!ContainsSoftError(methodBody)

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

// TestCrossTenantMethodAccess is Phase 4: uses Token B to perform destructive
// methods on objects confirmed (via Token A) to belong to a different user.
func TestCrossTenantMethodAccess(client *http.Client, baseURL string, target models.ScanTarget, tokenA, tokenB string) *models.Vulnerability {
	testIDs := []string{"1", "2", "3", "4", "5"}

	for _, pattern := range ObjectPatterns {
		for _, id := range testIDs {
			ep := strings.ReplaceAll(pattern, "{ID}", id)
			fullURL := baseURL + ep

			// Confirm object existence with Token A (owner)
			reqA, err := NewBFLARequest("GET", fullURL, tokenA, nil)
			if err != nil {
				continue
			}
			respA, err := client.Do(reqA)
			if err != nil {
				continue
			}
			bodyA := models.ReadBody(respA, 32768)
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

				reqB, err := NewBFLARequest(method, fullURL, tokenB, bodyReader)
				if err != nil {
					continue
				}
				respB, err := client.Do(reqB)
				if err != nil {
					continue
				}
				bodyB := models.ReadBody(respB, 16384)

				if (respB.StatusCode == 200 || respB.StatusCode == 204) && !ContainsSoftError(bodyB) {
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
