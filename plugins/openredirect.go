package plugins

import (
	"DORM/models"
	"net/http"
	"net/url"
	"time"
)

// 10. OPEN REDIRECT
type OpenRedirectPlugin struct{}

func (p *OpenRedirectPlugin) Name() string { return "Open Redirect" }

func (p *OpenRedirectPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// models.GetClient() returns the scan's single shared *http.Client. Writing
	// Timeout/CheckRedirect onto it (as this used to) is a data race between
	// concurrent runs and silently changes every other plugin's requests for
	// the rest of the scan (no redirect following, 4s timeout). Use a private
	// copy that keeps the shared Transport (proxy, auth, UA) and cookie Jar.
	base := models.GetClient()
	client := &http.Client{
		Transport:     base.Transport,
		Jar:           base.Jar,
		Timeout:       4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Get(getURL(target, "/?url=http://example.com"))
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		locURL, err := url.Parse(resp.Header.Get("Location"))
		if err == nil && locURL.Host == "example.com" {
			return &models.Vulnerability{Target: target, Name: "Open Redirect", Severity: "MEDIUM", CVSS: 6.1, Description: "Open redirect detected.", Solution: "Use a whitelist.", Reference: ""}
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
						_ = resp.Body.Close()
						if resp.StatusCode >= 300 && resp.StatusCode < 400 {
							locURL, err := url.Parse(resp.Header.Get("Location"))
							if err == nil && locURL.Host == "example.com" {
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
	}
	// ===================================
	return nil
}
