package plugins

import (
	"DORM/models"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 10. OPEN REDIRECT
type OpenRedirectPlugin struct{}

func (p *OpenRedirectPlugin) Name() string { return "Open Redirect" }

func (p *OpenRedirectPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	client := models.GetClient()
	client.Timeout = 4 * time.Second
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(getURL(target, "/?url=http://example.com"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(resp.Header.Get("Location"), "example.com") {
		return &models.Vulnerability{Target: target, Name: "Open Redirect", Severity: "MEDIUM", CVSS: 6.1, Description: "Open redirect detected.", Solution: "Use a whitelist.", Reference: ""}
	}
	// === SPIDER ENDPOINT INTEGRATION ===
	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if ep.Method == "GET" && len(ep.Params) > 0 {
				for _, param := range ep.Params {
					parsedUrl, err := url.Parse(ep.URL)
					if err != nil {
						continue
					}
					q := parsedUrl.Query()
					q.Set(param, "http://example.com")
					parsedUrl.RawQuery = q.Encode()

					targetURL := parsedUrl.String()
					resp, err := client.Get(targetURL)
					if err == nil {
						resp.Body.Close()
						if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(resp.Header.Get("Location"), "example.com") {
							return &models.Vulnerability{
								Target:      target,
								Name:        "Open Redirect (Spider-Discovered)",
								Severity:    "MEDIUM",
								CVSS:        6.1,
								Description: "Open redirect detected on parameter discovered by Spider.\nURL: " + targetURL,
								Solution:    "Use a whitelist.",
								Reference:   "",
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
