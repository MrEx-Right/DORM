package plugins

import (
	"DORM/models"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// 12. XSS (V3.1 - SMART CONTEXT AWARE)
type XSSPlugin struct{}

func (p *XSSPlugin) Name() string { return "XSS (Reflected - Smart)" }

func (p *XSSPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	canary := "dormxss" + fmt.Sprintf("%d", time.Now().Unix()%1000)

	endpoints := []string{"/", "/search", "/search.php", "/results.aspx", "/index.php", "/Search.aspx"}
	params := []string{"q", "s", "search", "keyword", "query", "lang", "id", "msg"}

	payloads := []string{
		fmt.Sprintf("<script>alert('%s')</script>", canary),
		fmt.Sprintf("\"><img src=x onerror=alert('%s')>", canary),
		fmt.Sprintf("javascript:alert('%s')//", canary),
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range payloads {

				targetURL := fmt.Sprintf("%s%s?%s=%s", getURL(target, ""), ep, param, url.QueryEscape(payload))

				resp, err := client.Get(targetURL)
				if err == nil {
					resp.Body.Close()

					headerCheck := make([]byte, 10240)
					n, _ := resp.Body.Read(headerCheck)
					bodyString := string(headerCheck[:n])

					if strings.Contains(bodyString, canary) {

						if strings.Contains(bodyString, "<script>") || strings.Contains(bodyString, "<img") || strings.Contains(bodyString, "javascript:") {
							return &models.Vulnerability{
								Target:      target,
								Name:        "Reflected XSS (Verified)",
								Severity:    "HIGH",
								CVSS:        7.2,
								Description: fmt.Sprintf("XSS Payload reflected in response body without encoding.\nURL: %s\nPayload: %s", targetURL, payload),
								Solution:    "Implement Context-Aware Output Encoding (HTML Entity Encode).",
								Reference:   "OWASP Cross Site Scripting (XSS)",
							}
						}
					}
				}
			}
		}
	}
	return nil
}
