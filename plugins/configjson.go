package plugins

import (
	"DORM/models"
	"strings"
)

// 49. CONFIG.JSON EXPOSURE
type ConfigJsonPlugin struct{}

func (p *ConfigJsonPlugin) Name() string { return "Config.json Disclosure" }

func (p *ConfigJsonPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	files := []string{"/config.json", "/app_config.json", "/settings.js"}
	for _, f := range files {
		resp, err := models.GetClient().Get(getURL(target, f))
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			buf := make([]byte, 500)
			resp.Body.Read(buf)
			if strings.Contains(string(buf), "api_key") || strings.Contains(string(buf), "secret") || strings.Contains(string(buf), "db_host") {
				return &models.Vulnerability{
					Target: target, Name: "Config File Disclosure", Severity: "HIGH", CVSS: 7.5,
					Description: "Configuration file contains sensitive data.",
					Solution:    "Block access.",
					Reference:   "",
				}
			}
		}
	}
	return nil
}
