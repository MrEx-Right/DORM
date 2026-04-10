package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 65. ASP.NET VIEWSTATE (Unencrypted)
type ViewStatePlugin struct{}

func (p *ViewStatePlugin) Name() string { return "ASP.NET ViewState Encryption" }

func (p *ViewStatePlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/"))
	if err == nil {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		body := string(bodyBytes)

		if strings.Contains(body, "__VIEWSTATE") {

			if !strings.Contains(body, "mac=") && !strings.Contains(body, "__VIEWSTATEGENERATOR") {
				return &models.Vulnerability{
					Target: target, Name: "Unencrypted ViewState", Severity: "MEDIUM", CVSS: 5.5,
					Description: "ASP.NET ViewState is not encrypted or signed.",
					Solution:    "Add validation='SHA1' to machineKey config.",
					Reference:   "",
				}
			}
		}
	}
	return nil
}
