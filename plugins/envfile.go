package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 20. ENV FILE
type EnvFilePlugin struct{}

func (p *EnvFilePlugin) Name() string { return "ENV File Disclosure" }

func (p *EnvFilePlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/.env"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && (strings.Contains(string(body), "APP_KEY=") || strings.Contains(string(body), "DB_PASSWORD=")) {
		return &models.Vulnerability{Target: target, Name: "ENV File Read", Severity: "CRITICAL", CVSS: 10.0, Description: "Passwords/Secrets disclosed.", Solution: "Block access.", Reference: ""}
	}
	return nil
}
