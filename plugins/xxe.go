package plugins

import (
	"DORM/models"
	"strings"
)

// 42. XXE INJECTION (XML External Entity)
type XXEPlugin struct{}

func (p *XXEPlugin) Name() string { return "XXE Injection" }

func (p *XXEPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	payload := `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe "DORM_XXE_TEST">]><foo>&xxe;</foo>`
	resp, err := models.GetClient().Post(getURL(target, "/xml"), "application/xml", strings.NewReader(payload))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)

		if strings.Contains(string(buf), "DORM_XXE_TEST") {
			return &models.Vulnerability{
				Target: target, Name: "XML External Entity (XXE)", Severity: "HIGH", CVSS: 8.2,
				Description: "XML parsing can be manipulated.",
				Solution:    "Disable external entities in XML parser.",
				Reference:   "OWASP XXE",
			}
		}
	}
	return nil
}
