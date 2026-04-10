package plugins

import (
	"DORM/models"
	"net/http"
)

// 19. TRACE METHOD
type TraceMethodPlugin struct{}

func (p *TraceMethodPlugin) Name() string { return "HTTP TRACE Method" }

func (p *TraceMethodPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, _ := http.NewRequest("TRACE", getURL(target, ""), nil)
	resp, err := models.GetClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return &models.Vulnerability{Target: target, Name: "TRACE Method Enabled", Severity: "MEDIUM", CVSS: 4.5, Description: "Vulnerable to XST attacks.", Solution: "Set TraceEnable Off.", Reference: ""}
	}
	return nil
}
