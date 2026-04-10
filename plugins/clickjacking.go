package plugins

import "DORM/models"

// 31. CLICKJACKING (X-Frame-Options)
type ClickjackingPlugin struct{}

func (p *ClickjackingPlugin) Name() string { return "Clickjacking Check" }

func (p *ClickjackingPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	resp, err := models.GetClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Frame-Options") == "" && resp.Header.Get("Content-Security-Policy") == "" {
		return &models.Vulnerability{
			Target: target, Name: "Clickjacking Risk", Severity: "LOW", CVSS: 3.0,
			Description: "X-Frame-Options header is missing.",
			Solution:    "Add DENY or SAMEORIGIN directives.",
			Reference:   "OWASP Clickjacking",
		}
	}
	return nil
}
