package plugins

import (
	"DORM/models"
	"strings"
)

// 56. JENKINS SCRIPT CONSOLE
type JenkinsPlugin struct{}

func (p *JenkinsPlugin) Name() string { return "Jenkins Script Console" }

func (p *JenkinsPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/script"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "println") || strings.Contains(string(buf), "Groovy") {
			return &models.Vulnerability{
				Target: target, Name: "Jenkins Script Console Open", Severity: "CRITICAL", CVSS: 9.8,
				Description: "Unauthenticated RCE panel found.",
				Solution:    "Secure Jenkins with password.",
				Reference:   "",
			}
		}
	}
	return nil
}
