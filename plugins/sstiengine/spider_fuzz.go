package sstiengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// RunSpiderFuzz is Phase 2: replay a reduced probe set (RCE payloads
// excluded) against spider-discovered GET and POST endpoints.
func RunSpiderFuzz(client *http.Client, target models.ScanTarget) *models.Vulnerability {
	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if !ok {
		return nil
	}
	spiderEndpoints := existing.([]models.Endpoint)

	for _, ep := range spiderEndpoints {
		// ── GET Parameter Fuzzing ─────────────────────────────────────
		if ep.Method == "GET" && len(ep.Params) > 0 {
			for _, param := range ep.Params {
				for _, probe := range Probes[:8] { // First 8 probes (RCE-free)
					parsedURL, err := url.Parse(ep.URL)
					if err != nil {
						continue
					}
					q := parsedURL.Query()
					q.Set(param, probe.Payload)
					parsedURL.RawQuery = q.Encode()

					resp, err := client.Get(parsedURL.String())
					if err != nil {
						continue
					}
					body := models.ReadBody(resp, 65536)

					if strings.Contains(body, probe.Expected) && !strings.Contains(body, probe.Payload) {
						return &models.Vulnerability{
							Target:   target,
							Name:     fmt.Sprintf("SSTI (Spider-Discovered — %s)", probe.Engine),
							Severity: "CRITICAL",
							CVSS:     9.9,
							Description: fmt.Sprintf(
								"Template injection confirmed on spider-discovered endpoint.\nURL: %s\nParam: %s\nPayload: %s\nEngine: %s",
								parsedURL.String(), param, probe.Payload, probe.Engine,
							),
							Solution:  "Sanitize user inputs before passing them to the template engine.",
							Reference: "OWASP SSTI / CWE-94",
						}
					}
				}
			}
		}

		// ── POST Parameter Fuzzing ────────────────────────────────────
		if ep.Method == "POST" && len(ep.Params) > 0 {
			for _, param := range ep.Params {
				for _, probe := range Probes[:6] {
					formData := url.Values{}
					formData.Set(param, probe.Payload)

					resp, err := client.PostForm(ep.URL, formData)
					if err != nil {
						continue
					}
					body := models.ReadBody(resp, 65536)

					if strings.Contains(body, probe.Expected) && !strings.Contains(body, probe.Payload) {
						return &models.Vulnerability{
							Target:   target,
							Name:     fmt.Sprintf("SSTI (POST Spider-Discovered — %s)", probe.Engine),
							Severity: "CRITICAL",
							CVSS:     9.9,
							Description: fmt.Sprintf(
								"Template injection confirmed via POST parameter.\nURL: %s\nParam: %s\nPayload: %s\nEngine: %s",
								ep.URL, param, probe.Payload, probe.Engine,
							),
							Solution:  "Sanitize all user data, including POST inputs.",
							Reference: "OWASP SSTI / CWE-94",
						}
					}
				}
			}
		}
	}

	return nil
}
