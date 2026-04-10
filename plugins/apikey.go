package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 63. API KEY LEAK (JS SCAN)
type APIKeyPlugin struct{}

func (p *APIKeyPlugin) Name() string { return "API Key in JS Files" }

func (p *APIKeyPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	resp, err := models.GetClient().Get(getURL(target, "/"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if strings.Contains(body, "AKIA") && len(body) > 20 {
		return &models.Vulnerability{
			Target: target, Name: "AWS API Key Leak", Severity: "CRITICAL", CVSS: 9.5,
			Description: "AWS key starting with 'AKIA' found in source code.",
			Solution:    "Rotate and delete the key.",
			Reference:   "",
		}
	}
	if strings.Contains(body, "AIza") {
		return &models.Vulnerability{
			Target: target, Name: "Google API Key Leak", Severity: "MEDIUM", CVSS: 5.0,
			Description: "Google API key found in source code.",
			Solution:    "Restrict key usage.",
			Reference:   "",
		}
	}
	return nil
}
