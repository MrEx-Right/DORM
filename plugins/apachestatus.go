package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 17. APACHE STATUS
type ApacheStatusPlugin struct{}

func (p *ApacheStatusPlugin) Name() string { return "Apache Server Status" }

func (p *ApacheStatusPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/server-status"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && strings.Contains(string(body), "Apache Server Status") {
		return &models.Vulnerability{Target: target, Name: "Apache Status Page", Severity: "LOW", CVSS: 3.0, Description: "Server status is accessible.", Solution: "Disable it.", Reference: ""}
	}
	return nil
}
