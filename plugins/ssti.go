package plugins

import (
	"DORM/models"
	"fmt"
	"net/url"
	"strings"
)

// 36. SSTI (V2.1 - SMART GUESSING)
type SSTIPlugin struct{}

func (p *SSTIPlugin) Name() string { return "SSTI (Template Injection - Smart)" }

func (p *SSTIPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// Matematik işlemi: 1337 * 1337 = 1787569
	const expectedResult = "1787569"

	endpoints := []string{"/", "/index.php", "/home", "/search", "/error"}
	params := []string{"q", "s", "search", "name", "username", "id", "template", "msg"}

	payloads := []string{
		"{{1337*1337}}",
		"${1337*1337}",
		"#{1337*1337}",
		"<%= 1337*1337 %>",
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range payloads {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(payload))

				resp, err := client.Get(targetURL)
				if err == nil {
					defer resp.Body.Close()
					buf := make([]byte, 4096)
					n, _ := resp.Body.Read(buf)
					body := string(buf[:n])

					if strings.Contains(body, expectedResult) && !strings.Contains(body, payload) {
						return &models.Vulnerability{
							Target:      target,
							Name:        "Server Side Template Injection (SSTI)",
							Severity:    "CRITICAL",
							CVSS:        9.9,
							Description: fmt.Sprintf("Template engine executed code.\nURL: %s\nPayload: %s\nResult: %s", targetURL, payload, expectedResult),
							Solution:    "Sanitize inputs before passing to template engine.",
							Reference:   "OWASP SSTI",
						}
					}
				}
			}
		}
	}
	return nil
}
