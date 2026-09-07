package ssrfengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"strings"
)

// RunLocalhostBypass tries every localhost-encoding payload. For these, the
// server returning any internal content is sufficient signal: 200 + a
// non-empty body that isn't the target site's own HTML page.
func RunLocalhostBypass(client *http.Client, baseURL string, target models.ScanTarget, params []string) *models.Vulnerability {
	for _, param := range params {
		for _, pl := range LocalhostBypass {
			attackURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, pl.URL)
			resp, err := client.Get(attackURL)
			if err != nil {
				continue
			}
			body := models.ReadBody(resp, 8192)

			// 200 + non-empty content + not the target site's own content
			if resp.StatusCode == 200 && len(body) > 50 && !strings.Contains(body, "<html") {
				return &models.Vulnerability{
					Target:   target,
					Name:     "SSRF: Localhost Bypass Detected",
					Severity: "CRITICAL",
					CVSS:     pl.CVSS,
					Description: fmt.Sprintf(
						"SSRF confirmed via localhost bypass technique.\nTechnique: %s\nPayload: %s\nParam: %s\nResponse Size: %d bytes",
						pl.Desc, pl.URL, param, len(body),
					),
					Solution:  "Block 127.0.0.1, 0.0.0.0, [::1] and all encoding variants except whitelisted ones.",
					Reference: "CWE-918: Server-Side Request Forgery",
				}
			}
		}
	}
	return nil
}
