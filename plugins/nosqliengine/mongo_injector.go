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
		_ = baseResp.Body.Close()
		baseCode := baseResp.StatusCode
		baseLen := len(baseBytes)

		for _, pl := range jsonPayloads {
			attackBody := bytes.NewReader([]byte(pl.Body))
			resp, err := client.Post(targetURL, "application/json", attackBody)
			if err != nil {
				continue
			}
			respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
			_ = resp.Body.Close()
			attackCode := resp.StatusCode
			attackLen := len(respBytes)

			// Require an explicit auth-failure → auth-success status code
			// transition (401/403 → 200). The previous version also fired on
			// *any* response merely 100+ bytes longer than the baseline,
			// or on a baseline that was simply non-200 for unrelated reasons
			// (a 404, a redirect, a transient 500) — both are extremely
			// common on ordinary sites for reasons that have nothing to do
			// with auth, which is why this was flagging a "CRITICAL Auth
			// Bypass" on sites that don't even have this login endpoint.
			if (baseCode == 401 || baseCode == 403) && attackCode == 200 {
				// A real bypass hands back a session artifact. Look for an
				// actual Set-Cookie or a JSON token *key* rather than bare
				// words like "success"/"welcome"/"session" anywhere in the
				// body — those show up in completely unrelated page text
				// (a welcome banner, a "session" cookie-consent notice...)
				// constantly.
				bodyStr := strings.ToLower(string(respBytes))
				isAuthSuccess := resp.Header.Get("Set-Cookie") != "" ||
					strings.Contains(bodyStr, "\"token\"") ||
					strings.Contains(bodyStr, "\"access_token\"") ||
					strings.Contains(bodyStr, "\"session_id\"")

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
