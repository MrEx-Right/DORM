package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 82. TEAMCITY AUTH BYPASS
type TeamCityPlugin struct{}

func (p *TeamCityPlugin) Name() string { return "TeamCity Auth Bypass" }

func (p *TeamCityPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	targetURL := getURL(target, "/app/rest/users/id:1/tokens/RPC2")
	resp, err := models.GetClient().Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == 200 && strings.Contains(string(body), "<token") {
			return &models.Vulnerability{
				Target: target, Name: "TeamCity Auth Bypass", Severity: "CRITICAL", CVSS: 9.8,
				Description: "Administrative access token created without authentication.",
				Solution:    "Upgrade TeamCity immediately.", Reference: "CVE-2023-42793",
			}
		}
	}
	return nil
}
