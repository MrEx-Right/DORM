// ==============================================================
// JWT ENGINE — v3.1 "Key Breaker" (PEP 2.2)
// ==============================================================
package jwtengine

import (
	"DORM/models"
	"net/http"
)

type JWTWeaknessPlugin struct{}

func (p *JWTWeaknessPlugin) Name() string { return "JWT Security Scanner (Key Breaker v3)" }

// TestToken reports whether tok is accepted (HTTP 200) against endpoint —
// the shared acceptance check used by all 6 attacks.
func TestToken(client *http.Client, target models.ScanTarget, tok, endpoint string) bool {
	req, _ := http.NewRequest("GET", models.GetURL(target, endpoint), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = r.Body.Close() }()
	return r.StatusCode == 200
}

func (p *JWTWeaknessPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	// Collect URLs to probe (root + Spider-discovered)
	probeURLs := []string{models.GetURL(target, "/")}
	if existing, ok := models.SharedData.Load("endpoints_" + target.IP); ok {
		for _, ep := range existing.([]models.Endpoint) {
			probeURLs = append(probeURLs, ep.URL)
		}
	}

	var token, origHeaderB64, origPayloadB64 string

	// Find the first valid JWT across probe URLs
	for _, pu := range probeURLs {
		resp, err := client.Get(pu)
		if err != nil {
			continue
		}
		body := models.ReadBody(resp, 131072)

		t := models.FindJWT(body, resp.Header)
		if t == "" {
			continue
		}
		h, pay, _, valid := models.ParseAndValidateJWT(t)
		if !valid {
			continue
		}
		token = t
		origHeaderB64 = h
		origPayloadB64 = pay
		break
	}

	if token == "" {
		return nil
	}

	// Verify server actually validates JWTs (sanity check)
	badToken := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.invalid_signature_block"
	reqCheck, _ := http.NewRequest("GET", models.GetURL(target, "/"), nil)
	reqCheck.Header.Set("Authorization", "Bearer "+badToken)
	respCheck, err := client.Do(reqCheck)
	if err != nil {
		return nil
	}
	_ = respCheck.Body.Close()
	if respCheck.StatusCode == 200 {
		return nil // JWT not enforced
	}

	testToken := func(tok, endpoint string) bool {
		return TestToken(client, target, tok, endpoint)
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 1 — Weak Secret Brute-Force (HS256)
	// ══════════════════════════════════════════════════════════════════
	if vuln := RunWeakSecretAttack(target, origHeaderB64, origPayloadB64, testToken); vuln != nil {
		return vuln
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 2 — 'None' Algorithm Bypass
	// ══════════════════════════════════════════════════════════════════
	if vuln := RunAlgNoneAttack(target, origHeaderB64, origPayloadB64, testToken); vuln != nil {
		return vuln
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 3 — Algorithm Confusion: RS256 → HS256 (using public key)
	// ══════════════════════════════════════════════════════════════════
	if vuln := RunAlgConfusionAttack(target, baseURL, origHeaderB64, origPayloadB64, testToken); vuln != nil {
		return vuln
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 4 — KID Injection (Path Traversal + SQL Injection)
	// ══════════════════════════════════════════════════════════════════
	if vuln := RunKIDInjectionAttack(target, origPayloadB64, testToken); vuln != nil {
		return vuln
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 5 — JWK Self-Embed (attacker-controlled key in header)
	// ══════════════════════════════════════════════════════════════════
	if vuln := RunJWKEmbedAttack(target, origPayloadB64, testToken); vuln != nil {
		return vuln
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 6 — JKU (JSON Web Key Set URL) Injection
	// ══════════════════════════════════════════════════════════════════
	if vuln := RunJKUInjectionAttack(target, origPayloadB64, testToken); vuln != nil {
		return vuln
	}

	return nil
}
