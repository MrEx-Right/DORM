package plugins

import (
	"DORM/models"
	"strings"
)

// 68. DRUPALGEDDON2 (CVE-2018-7600)
type DrupalPlugin struct{}

func (p *DrupalPlugin) Name() string { return "Drupalgeddon2 RCE" }

func (p *DrupalPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	resp, err := models.GetClient().Get(getURL(target, "/CHANGELOG.txt"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "Drupal 7.") {
			return &models.Vulnerability{
				Target: target, Name: "Outdated Drupal Version", Severity: "MEDIUM", CVSS: 6.0,
				Description: "Old Drupal version detected, possible Drupalgeddon risk.",
				Solution:    "Update Drupal.",
				Reference:   "",
			}
		}
	}
	return nil
}
