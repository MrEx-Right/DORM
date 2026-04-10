package plugins

import "DORM/models"

// 39. SENSITIVE CONFIGS
type SensitiveConfigPlugin struct{}

func (p *SensitiveConfigPlugin) Name() string { return "Editor/Config File Disclosure" }

func (p *SensitiveConfigPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	files := []string{"/.vscode/sftp.json", "/.idea/workspace.xml", "/.git/config"}
	for _, f := range files {
		resp, err := models.GetClient().Get(getURL(target, f))
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			return &models.Vulnerability{Target: target, Name: "Sensitive Config File", Severity: "MEDIUM", CVSS: 5.0, Description: "File found: " + f, Solution: "Block access.", Reference: ""}
		}
	}
	return nil
}
