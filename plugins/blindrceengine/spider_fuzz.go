package blindrceengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
)

// RunSpiderFuzz covers Phases 2 and 3: replaying the obfuscated sleep
// payloads against spider-discovered GET and POST endpoints.
func RunSpiderFuzz(client *http.Client, target models.ScanTarget, probes2, probes7 []RCEPayload) *models.Vulnerability {
	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if !ok {
		return nil
	}
	spiderEndpoints := existing.([]models.Endpoint)

	for _, ep := range spiderEndpoints {
		// ── PHASE 2: GET endpoints ──────────────────────────────────
		if ep.Method == "GET" && len(ep.Params) > 0 {
			baseline := MeasureBaseline(target, "/")

			for _, param := range ep.Params {
				for i, p2 := range probes2 {
					parsedURL, err := url.Parse(ep.URL)
					if err != nil {
						continue
					}
					q := parsedURL.Query()
					q.Set(param, p2.Payload)
					parsedURL.RawQuery = q.Encode()
					probeURL := parsedURL.String()

					p7 := probes7[i]
					q.Set(param, p7.Payload)
					parsedURL.RawQuery = q.Encode()
					confirmURL := parsedURL.String()

					result := ConfirmTiming(baseline,
						func() (*http.Response, error) { return client.Get(probeURL) },
						func() (*http.Response, error) { return client.Get(confirmURL) },
					)
					if result.Confirmed {
						return &models.Vulnerability{
							Target:   target,
							Name:     "Blind OS Command Injection (Spider-Discovered — Confirmed)",
							Severity: "CRITICAL",
							CVSS:     9.8,
							Description: fmt.Sprintf(
								"Command injection confirmed on spider-discovered endpoint.\n"+
									"URL: %s\nParameter: %s\nPayload OS: %s\n"+
									"t1(sleep2): %.2fs | t2(sleep7): %.2fs | Ratio: %.2f",
								ep.URL, param, p2.OS, result.T1.Seconds(), result.T2.Seconds(), result.Ratio,
							),
							Solution:  "Disable system command execution functions. Use allow-list input validation.",
							Reference: "OWASP A03:2021 – Injection / CWE-78",
						}
					}
				}
			}
		}

		// ── PHASE 3: POST endpoints ──────────────────────────────────
		if ep.Method == "POST" && len(ep.Params) > 0 {
			baseline := MeasureBaseline(target, "/")

			for _, param := range ep.Params {
				for i, p2 := range probes2 {
					formData := url.Values{}
					formData.Set(param, p2.Payload)

					p7 := probes7[i]
					confirmData := url.Values{}
					confirmData.Set(param, p7.Payload)

					result := ConfirmTiming(baseline,
						func() (*http.Response, error) { return client.PostForm(ep.URL, formData) },
						func() (*http.Response, error) { return client.PostForm(ep.URL, confirmData) },
					)
					if result.Confirmed {
						return &models.Vulnerability{
							Target:   target,
							Name:     "Blind OS Command Injection (POST — Confirmed)",
							Severity: "CRITICAL",
							CVSS:     9.8,
							Description: fmt.Sprintf(
								"Command injection confirmed via POST parameter.\n"+
									"URL: %s\nParameter: %s\nPayload OS: %s\n"+
									"t1(sleep2): %.2fs | t2(sleep7): %.2fs | Ratio: %.2f\nBaseline: %v",
								ep.URL, param, p2.OS, result.T1.Seconds(), result.T2.Seconds(), result.Ratio, baseline,
							),
							Solution:  "Disable system command execution functions. Use allow-list input validation.",
							Reference: "OWASP A03:2021 – Injection / CWE-78",
						}
					}
				}
			}
		}
	}

	return nil
}
