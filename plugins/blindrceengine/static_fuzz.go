package blindrceengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
)

// RunStaticFuzz is Phase 1: fuzz a curated list of common endpoint/parameter
// combinations with the obfuscated sleep payloads.
func RunStaticFuzz(client *http.Client, baseURL string, target models.ScanTarget, probes2, probes7 []RCEPayload) *models.Vulnerability {
	endpoints := []string{
		"/", "/ping.php", "/status.php", "/check.php", "/test.php",
		"/admin.php", "/exec.php", "/cmd.php", "/run.php", "/api/exec",
		"/api/run", "/api/ping", "/api/status",
	}
	params := []string{
		"cmd", "ip", "host", "addr", "query", "file", "download",
		"path", "exec", "command", "ping", "target", "run", "shell",
	}

	for _, ep := range endpoints {
		baseline := MeasureBaseline(target, ep)

		for _, param := range params {
			for i, p2 := range probes2 {
				encodedPayload := url.QueryEscape(p2.Payload)
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, encodedPayload)

				p7 := probes7[i]
				encoded7 := url.QueryEscape(p7.Payload)
				confirmURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, encoded7)

				result := ConfirmTiming(baseline,
					func() (*http.Response, error) { return client.Get(targetURL) },
					func() (*http.Response, error) { return client.Get(confirmURL) },
				)
				if result.Confirmed {
					return &models.Vulnerability{
						Target:   target,
						Name:     "Blind OS Command Injection (Phantom Strike — Confirmed)",
						Severity: "CRITICAL",
						CVSS:     9.8,
						Description: fmt.Sprintf(
							"Command injection confirmed via adaptive dual-timing delta analysis.\n"+
								"Endpoint:   %s\nParameter:  %s\n"+
								"Payload OS: %s\nSmall Probe: %s → %.2fs\nLarge Probe: %s → %.2fs\n"+
								"Ratio: %.2f (expected ~3.5 for sleep7/sleep2)\nBaseline RTT: %v",
							targetURL, param, p2.OS,
							p2.Payload, result.T1.Seconds(),
							p7.Payload, result.T2.Seconds(),
							result.Ratio, baseline,
						),
						Solution:  "Disable system command execution functions. Use allow-list input validation.",
						Reference: "OWASP A03:2021 – Injection / CWE-78",
					}
				}
			}
		}
	}

	return nil
}
