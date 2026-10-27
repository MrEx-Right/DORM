package ssrfengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// volatileRe matches the parts of a response that change on every request
// (ids, tokens, timestamps, counters), masked before a body is compared
// with the control's.
var volatileRe = regexp.MustCompile(`[0-9a-fA-F-]{8,}|[0-9]+`)

// RunLocalhostBypass tries every localhost-encoding payload. For these, the
// server returning internal content is the signal: 200 + a non-empty body
// that isn't the target site's own HTML page, and that differs from what
// the same parameter returns for a harmless URL (an API that answers every
// request the same way is not fetching anything).
func RunLocalhostBypass(client *http.Client, baseURL string, target models.ScanTarget, params []string) *models.Vulnerability {
	for _, param := range params {
		control, ok := controlBody(client, baseURL, param)
		if !ok {
			continue
		}
		for _, pl := range LocalhostBypass {
			attackURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, pl.URL)
			resp, err := client.Get(attackURL)
			if err != nil {
				continue
			}
			body := models.ReadBody(resp, 8192)

			// 200 + non-empty content + not the target site's own content
			if resp.StatusCode == 200 && len(body) > 50 && !strings.Contains(body, "<html") && volatileRe.ReplaceAllString(body, "#") != volatileRe.ReplaceAllString(control, "#") {
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
