package plugins

import (
	"DORM/models"
	"crypto/tls"
	"net/http"
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
	client := &http.Client{
		Timeout:       4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(getURL(target, "/?url=http://example.com"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(resp.Header.Get("Location"), "example.com") {
		return &models.Vulnerability{Target: target, Name: "Open Redirect", Severity: "MEDIUM", CVSS: 6.1, Description: "Open redirect detected.", Solution: "Use a whitelist.", Reference: ""}
	}
	return nil
}
