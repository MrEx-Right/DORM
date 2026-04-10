package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 25. DOCKER API EXPOSURE
type DockerAPIPlugin struct{}

func (p *DockerAPIPlugin) Name() string { return "Docker API Exposure" }

func (p *DockerAPIPlugin) Run(target models.ScanTarget) *models.Vulnerability {

	if target.Port != 2375 {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/version"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "Platform") && strings.Contains(string(body), "GoVersion") {
		return &models.Vulnerability{Target: target, Name: "Docker API Publicly Exposed", Severity: "CRITICAL", CVSS: 10.0, Description: "Unauthorized Docker control possible.", Solution: "Close port to public.", Reference: ""}
	}
	return nil
}
