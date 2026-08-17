package nosqliengine

import (
	"DORM/models"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ============================================================
//  MONGODB JSON BODY INJECTOR — POST application/json
// ============================================================

// RunMongoJSONInjection tests JSON body NoSQL injection on POST endpoints.
func RunMongoJSONInjection(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	postEndpoints := []string{"/login", "/api/login", "/auth", "/api/auth", "/user/login", "/signin"}
	jsonPayloads := GetJSONPayloads()

	for _, ep := range postEndpoints {
		targetURL := baseURL + ep

		// Baseline (invalid credentials)
		baseBody := bytes.NewReader([]byte(`{"username": "invalid_dorm_x9", "password": "invalid_dorm_x9"}`))
		baseResp, err := client.Post(targetURL, "application/json", baseBody)
		if err != nil {
			continue
		}
		baseBytes, _ := io.ReadAll(io.LimitReader(baseResp.Body, 65536))
		baseResp.Body.Close()
		baseCode := baseResp.StatusCode
		baseLen := len(baseBytes)

		for _, pl := range jsonPayloads {
			attackBody := bytes.NewReader([]byte(pl.Body))
			resp, err := client.Post(targetURL, "application/json", attackBody)
			if err != nil {
				continue
			}
			respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
			resp.Body.Close()
			attackCode := resp.StatusCode
			attackLen := len(respBytes)

			if (baseCode != 200 && attackCode == 200) || (attackLen > baseLen+100) {
				// Check response body for auth success indicators
				bodyStr := strings.ToLower(string(respBytes))
				isAuthSuccess := strings.Contains(bodyStr, "token") ||
					strings.Contains(bodyStr, "session") ||
					strings.Contains(bodyStr, "success") ||
					strings.Contains(bodyStr, "welcome") ||
					attackCode == 200 && baseCode != 200

				severity := "HIGH"
				cvss := 8.5
				if isAuthSuccess {
					severity = "CRITICAL"
					cvss = 9.1
				}

				return &models.Vulnerability{
					Target:   target,
					Name:     "NoSQL Injection (JSON Body — Auth Bypass)",
					Severity: severity,
					CVSS:     cvss,
					Description: fmt.Sprintf(
						"Authentication bypassed via NoSQL injection in JSON body.\n"+
							"Endpoint: %s\nTechnique: %s\nPayload: %s\n"+
							"Baseline: HTTP %d (%d bytes) → Attack: HTTP %d (%d bytes)",
						targetURL, pl.Desc, pl.Body, baseCode, baseLen, attackCode, attackLen,
					),
					Solution:  "Enforce all fields in JSON body as strings. Whitelist/block MongoDB operators ($gt, $ne, $regex).",
					Reference: "OWASP NoSQL Injection / CWE-943",
				}
			}
		}
	}
	return nil
}
