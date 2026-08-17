package idorengine

import (
	"DORM/models"
	"fmt"
	"net/http"
)

// ============================================================
//  IDOR ENGINE — v4.0 "Auth Matrix"
//  Dual-Profile · UUID Harvester · Spider Integration · GraphQL
// ============================================================

type IDORPlugin struct{}

func (p *IDORPlugin) Name() string { return "IDOR (Next-Gen — Auth Matrix & GraphQL)" }

func (p *IDORPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	// Need dual credentials for IDOR testing
	user1 := models.GetSharedString("user1_token")
	user2 := models.GetSharedString("user2_token")

	// If we don't have auth tokens, we can still do unauthenticated IDOR checks
	// but the core Auth Matrix requires them.
	hasAuth := user1 != "" && user2 != ""

	endpoints := []string{
		"/api/user/", "/api/profile/", "/api/account/", "/api/orders/",
		"/api/invoices/", "/api/messages/", "/api/documents/",
		"/user/view/", "/account/details/", "/profile/edit/",
		"/download?file_id=", "/view?doc_id=", "/api/v1/users/",
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 1 — UUID Harvester
	// ══════════════════════════════════════════════════════════════════════
	harvestedIDs := RunUUIDHarvester(client, baseURL, target)

	// Combine standard sequential IDs with harvested IDs
	testIDs := []string{"1", "2", "001", "1000", "admin", "12345"}
	testIDs = append(testIDs, harvestedIDs...)

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 2 — Dual-Profile Auth Matrix (Core IDOR check)
	// ══════════════════════════════════════════════════════════════════════
	if hasAuth {
		matrixResult := RunAuthMatrix(client, baseURL, target, user1, user2, endpoints, testIDs)
		if matrixResult != nil {
			return matrixResult
		}
	} else {
		// Unauthenticated IDOR check (BOLA)
		bolaResult := runUnauthenticatedBOLA(client, baseURL, target, endpoints, testIDs)
		if bolaResult != nil {
			return bolaResult
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 3 — Spider Endpoint Integration
	// ══════════════════════════════════════════════════════════════════════
	spiderResult := RunSpiderIDOR(client, target, user1, user2)
	if spiderResult != nil {
		return spiderResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 4 — GraphQL IDOR Detection
	// ══════════════════════════════════════════════════════════════════════
	graphqlResult := RunGraphQLIDOR(client, baseURL, target, user1, user2, testIDs)
	if graphqlResult != nil {
		return graphqlResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 5 — HTTP Method Tampering IDOR
	// ══════════════════════════════════════════════════════════════════════
	if hasAuth {
		methodResult := runMethodTampering(client, baseURL, target, user1)
		if methodResult != nil {
			return methodResult
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 6 — Batch/Bulk Endpoint IDOR
	// ══════════════════════════════════════════════════════════════════════
	batchResult := runBatchIDOR(client, baseURL, target, user1)
	if batchResult != nil {
		return batchResult
	}

	return nil
}

// runUnauthenticatedBOLA tests for BOLA without credentials.
func runUnauthenticatedBOLA(client *http.Client, baseURL string, target models.ScanTarget, endpoints, ids []string) *models.Vulnerability {
	for _, ep := range endpoints {
		for _, id := range ids {
			targetURL := baseURL + ep + id
			resp, err := client.Get(targetURL)
			if err != nil {
				continue
			}
			body := models.ReadBody(resp, 65536)

			// If unauthenticated request returns 200 and contains PII
			if resp.StatusCode == 200 && DetectPII(body) {
				return &models.Vulnerability{
					Target:   target,
					Name:     "BOLA / IDOR (Unauthenticated Access to PII)",
					Severity: "CRITICAL",
					CVSS:     9.1,
					Description: fmt.Sprintf(
						"Unauthenticated access to an endpoint returned sensitive PII.\n"+
							"Endpoint: %s\nID tested: %s",
						targetURL, id,
					),
					Solution:  "Implement strict access controls. Enforce authentication and authorization checks on all data endpoints.",
					Reference: "OWASP API1:2023 - Broken Object Level Authorization",
				}
			}
		}
	}
	return nil
}

// runMethodTampering tests if changing the HTTP method bypasses authorization.
func runMethodTampering(client *http.Client, baseURL string, target models.ScanTarget, token string) *models.Vulnerability {
	// Implementation placeholder
	return nil
}

// runBatchIDOR tests array-based IDOR (/api/users?ids=1,2,3).
func runBatchIDOR(client *http.Client, baseURL string, target models.ScanTarget, token string) *models.Vulnerability {
	// Implementation placeholder
	return nil
}
