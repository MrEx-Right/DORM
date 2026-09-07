package sstiengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// RunStaticFuzz is Phase 1: fuzz a curated list of endpoint/parameter
// combinations with the full probe corpus, checking both canary execution
// and template-engine error leaks.
func RunStaticFuzz(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	endpoints := []string{"/", "/index.php", "/home", "/search", "/error", "/render", "/template", "/page"}
	params := []string{"q", "s", "search", "name", "username", "id", "template", "msg", "page", "text", "content"}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, probe := range Probes {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(probe.Payload))

				resp, err := client.Get(targetURL)
				if err != nil {
					continue
				}
				body := models.ReadBody(resp, 65536)

				// Math/fingerprint canary match
				if strings.Contains(body, probe.Expected) && !strings.Contains(body, probe.Payload) {
					sev := "CRITICAL"
					cvss := 9.9
					var name string

					if probe.IsRCE && strings.Contains(body, "uid=") {
						name = fmt.Sprintf("SSTI RCE Confirmed (%s)", probe.Engine)
						cvss = 10.0
					} else {
						name = fmt.Sprintf("SSTI Detected — Engine: %s", probe.Engine)
					}

					return &models.Vulnerability{
						Target:   target,
						Name:     name,
						Severity: sev,
						CVSS:     cvss,
						Description: fmt.Sprintf(
							"Template engine executed the injected code.\nEndpoint: %s\nParam: %s\nPayload: %s\nExpected Output: %s\nEngine Fingerprint: %s",
							targetURL, param, probe.Payload, probe.Expected, probe.Engine,
						),
						Solution:  "Sanitize user inputs before passing them to the template engine. Enable sandbox mode.",
						Reference: "OWASP SSTI / CWE-94: Code Injection",
					}
				}

				// Error-based detection
				for _, errSig := range ErrorSigs {
					if strings.Contains(body, errSig) {
						engine := Fingerprint(body)
						return &models.Vulnerability{
							Target:   target,
							Name:     "SSTI (Template Syntax Error Leak)",
							Severity: "HIGH",
							CVSS:     8.0,
							Description: fmt.Sprintf(
								"Template engine parse error leaked — SSTI surface area confirmed.\nEndpoint: %s\nParam: %s\nPayload: %s\nError: %s\nEngine: %s",
								targetURL, param, probe.Payload, errSig, engine,
							),
							Solution:  "Do not show template error messages to the user in production.",
							Reference: "OWASP SSTI / CWE-209: Error Message Information Exposure",
						}
					}
				}
			}
		}
	}

	return nil
}
