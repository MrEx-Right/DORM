package plugins

import (
	"DORM/models"
	"strings"
)

// 69. EXPOSED GITLAB USER ENUM
type GitLabPlugin struct{}

func (p *GitLabPlugin) Name() string { return "GitLab User Enum" }

func (p *GitLabPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/api/v4/users?per_page=1"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "\"username\":") {
			return &models.Vulnerability{
				Target: target, Name: "GitLab API Exposed", Severity: "MEDIUM", CVSS: 5.3,
				Description: "GitLab user list accessible via public API.",
				Solution:    "Restrict public API access.",
				Reference:   "",
			}
		}
	}
	return nil
}
