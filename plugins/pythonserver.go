package plugins

import (
	"DORM/models"
	"strings"
)

// 40. PYTHON SERVER CHECK
type PythonServerPlugin struct{}

func (p *PythonServerPlugin) Name() string { return "Open Directory Listing" }

func (p *PythonServerPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/"))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "Directory listing for") {
			return &models.Vulnerability{
				Target: target, Name: "Directory Listing Enabled", Severity: "MEDIUM", CVSS: 5.0,
				Description: "Folder contents are visible to everyone.",
				Solution:    "Disable indexing.",
				Reference:   "",
			}
		}
	}
	return nil
}
