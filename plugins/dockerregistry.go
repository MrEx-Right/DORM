package plugins

import (
	"DORM/models"
	"strings"
)

// 53. DOCKER REGISTRY CATALOG
type DockerRegistryPlugin struct{}

func (p *DockerRegistryPlugin) Name() string { return "Docker Registry Exposure" }

func (p *DockerRegistryPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/v2/_catalog"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "repositories") {
			return &models.Vulnerability{
				Target: target, Name: "Open Docker Registry", Severity: "HIGH", CVSS: 7.5,
				Description: "Docker image list is public.",
				Solution:    "Enable Authentication.",
				Reference:   "",
			}
		}
	}
	return nil
}
