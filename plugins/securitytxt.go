package plugins

import "DORM/models"

// 27. SECURITY.TXT CHECK
type SecurityTxtPlugin struct{}

func (p *SecurityTxtPlugin) Name() string { return "Security.txt File" }

func (p *SecurityTxtPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/.well-known/security.txt"))
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		return &models.Vulnerability{Target: target, Name: "Security.txt Found", Severity: "INFO", CVSS: 0.0, Description: "Security contact info available.", Solution: "Informational.", Reference: ""}
	}
	return nil
}
