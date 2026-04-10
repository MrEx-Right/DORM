package plugins

import "DORM/models"

// 37. HSTS CHECK
type HSTSPlugin struct{}

func (p *HSTSPlugin) Name() string { return "HSTS (HTTPS Enforcement)" }

func (p *HSTSPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 443 {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		return &models.Vulnerability{Target: target, Name: "HSTS Missing", Severity: "LOW", CVSS: 2.0, Description: "Strict-Transport-Security header is missing.", Solution: "Enable HSTS.", Reference: ""}
	}
	return nil
}
