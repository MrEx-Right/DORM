package plugins

import (
	"DORM/models"
	"net/http"
	"strings"
)

// 34. HOST HEADER INJECTION
type HostHeaderPlugin struct{}

func (p *HostHeaderPlugin) Name() string { return "Host Header Injection" }

func (p *HostHeaderPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, _ := http.NewRequest("GET", getURL(target, "/"), nil)
	req.Host = "evil.com"
	resp, err := models.GetClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 1024)
	resp.Body.Read(buf)
	if strings.Contains(string(buf), "evil.com") || resp.Header.Get("Location") == "evil.com" {
		return &models.Vulnerability{
			Target: target, Name: "Host Header Injection", Severity: "MEDIUM", CVSS: 5.4,
			Description: "Host header can be manipulated.",
			Solution:    "Validate the Host header.",
			Reference:   "",
		}
	}
	return nil
}
