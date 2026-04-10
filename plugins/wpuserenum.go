package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 7. WORDPRESS USER ENUM - v2
type WPUserEnumPlugin struct{}

func (p *WPUserEnumPlugin) Name() string { return "WordPress User Disclosure (Pro)" }

func (p *WPUserEnumPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	endpoints := []string{"/wp-json/wp/v2/users", "/?author=1"}

	for _, ep := range endpoints {
		resp, err := models.GetClient().Get(getURL(target, ep))
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if strings.Contains(string(body), "\"slug\":\"") || strings.Contains(string(body), "/author/") {
				return &models.Vulnerability{
					Target: target, Name: "WordPress Username Disclosure", Severity: "MEDIUM", CVSS: 5.0,
					Description: "Usernames can be extracted via WP-JSON or Author archives. Risk of Brute-force!",
					Solution:    "Restrict REST API access and disable author archives.",
				}
			}
		}
	}
	return nil
}
