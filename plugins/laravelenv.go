package plugins

import (
	"DORM/models"
	"strings"
)

// 66. LARAVEL .ENV
type LaravelEnvPlugin struct{}

func (p *LaravelEnvPlugin) Name() string { return "Laravel .env Disclosure" }

func (p *LaravelEnvPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/.env"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "APP_KEY=") {
			return &models.Vulnerability{
				Target: target, Name: "Laravel .env Disclosure", Severity: "CRITICAL", CVSS: 10.0,
				Description: "Application keys and DB passwords exposed.",
				Solution:    "Block access to .env file.",
				Reference:   "",
			}
		}
	}
	return nil
}
