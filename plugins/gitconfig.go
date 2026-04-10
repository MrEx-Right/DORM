package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 15. GIT CONFIG
type GitConfigPlugin struct{}

func (p *GitConfigPlugin) Name() string { return "Git Configuration" }

func (p *GitConfigPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/.git/config"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && strings.Contains(string(body), "[core]") {
		return &models.Vulnerability{Target: target, Name: "Git Disclosure (.git)", Severity: "HIGH", CVSS: 7.5, Description: "Git config file is accessible.", Solution: "Block access.", Reference: ""}
	}
	return nil
}
