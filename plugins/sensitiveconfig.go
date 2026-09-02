package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 39. SENSITIVE CONFIGS
type SensitiveConfigPlugin struct{}

func (p *SensitiveConfigPlugin) Name() string { return "Editor/Config File Disclosure" }

// sensitiveConfigSignature is what each path's body must actually contain —
// a bare 200 isn't enough on its own, since a SPA catch-all router 200s
// every unmatched path with the same index.html.
var sensitiveConfigSignature = map[string]string{
	"/.vscode/sftp.json": "\"host\"",
	"/.idea/workspace.xml": "<project",
	"/.git/config":       "[core]",
}

func (p *SensitiveConfigPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	files := []string{"/.vscode/sftp.json", "/.idea/workspace.xml", "/.git/config"}
	for _, f := range files {
		resp, err := models.GetClient().Get(getURL(target, f))
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()
		if strings.Contains(string(body), sensitiveConfigSignature[f]) {
			return &models.Vulnerability{Target: target, Name: "Sensitive Config File", Severity: "MEDIUM", CVSS: 5.0, Description: "File found: " + f, Solution: "Block access.", Reference: ""}
		}
	}
	return nil
}
