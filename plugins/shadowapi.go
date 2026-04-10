package plugins

import (
	"DORM/models"
	"fmt"
)

// 83. SHADOW API DISCOVERY
type ShadowAPIPlugin struct{}

func (p *ShadowAPIPlugin) Name() string { return "Shadow API Discovery" }

func (p *ShadowAPIPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	prefixes := []string{"/api/v2", "/api/mobile", "/api/internal", "/api/private", "/v1/admin"}
	for _, prefix := range prefixes {
		resp, err := models.GetClient().Get(getURL(target, prefix))
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 401 {
				return &models.Vulnerability{
					Target: target, Name: "Shadow API Endpoint Found", Severity: "INFO", CVSS: 0.0,
					Description: fmt.Sprintf("Potentially undocumented API endpoint found: %s", prefix),
					Solution:    "Audit and document all API routes.", Reference: "OWASP API Security",
				}
			}
		}
	}
	return nil
}
