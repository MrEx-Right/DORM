// ============================================================
//  BFLA / BOLA ENGINE — v1.1 (PEP 2.2)
//  Broken Function Level Authorization  (OWASP API5:2023)
//  Broken Object Level Authorization    (OWASP API1:2023)
//
//  Differs from the IDOR engine:
//    - IDOR → Sequential ID enumeration for data leakage
//    - BFLA → HTTP method tampering (GET→PUT/DELETE) +
//             role boundary bypass (user→admin endpoint)
// ============================================================
package bflaengine

import "DORM/models"

type BFLABOLAPlugin struct{}

func (p *BFLABOLAPlugin) Name() string {
	return "BFLA/BOLA — Broken Function & Object Level Authorization"
}

func (p *BFLABOLAPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	// Shared with the IDOR engine — a future auth-setup step that seeds
	// these keys benefits both engines at once.
	tokenA := models.GetSharedString("user1_token")
	tokenB := models.GetSharedString("user2_token")

	// ==================================================================
	// PHASE 1: ADMIN ENDPOINT DISCOVERY
	// Combine spider-discovered endpoints with known admin path patterns
	// ==================================================================
	adminEndpoints := DiscoverAdminEndpoints(client, baseURL, target)

	// ==================================================================
	// PHASE 2: UNAUTHORIZED ROLE ESCALATION (BFLA)
	// Attempt access to admin endpoints using a low-privilege token (B)
	// or unauthenticated requests
	// ==================================================================
	if result := TestRoleEscalation(client, baseURL, target, adminEndpoints, tokenA, tokenB); result != nil {
		return result
	}

	// ==================================================================
	// PHASE 3: HTTP METHOD TAMPERING ON OBJECTS (BOLA via Method Swap)
	// Replay successful GET requests using PUT/DELETE/PATCH to test
	// whether write/delete authorization is enforced separately
	// ==================================================================
	if result := TestMethodTampering(client, baseURL, target, tokenA, tokenB); result != nil {
		return result
	}

	// ==================================================================
	// PHASE 4: CROSS-TENANT OBJECT ACCESS VIA METHOD CHANGE
	// Use Token B to perform destructive methods on objects owned by Token A
	// ==================================================================
	if tokenA != "" && tokenB != "" {
		if result := TestCrossTenantMethodAccess(client, baseURL, target, tokenA, tokenB); result != nil {
			return result
		}
	}

	return nil
}
