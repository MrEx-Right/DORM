package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

// 67. COLDFUSION DEBUGGING & ADMIN (SMART CHECK)
type ColdFusionPlugin struct{}

func (p *ColdFusionPlugin) Name() string { return "ColdFusion Exposure" }

func (p *ColdFusionPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	endpoints := []string{
		"/CFIDE/debug/cf_debug.cfm",
		"/CFIDE/administrator/index.cfm",
		"/CFIDE/main/ide.cfm",
		"/CFIDE/componentutils/componentdoc.cfm",
	}

	signatures := []string{
		"ColdFusion",
		"cf_debug",
		"CF_TEMPLATE_PATH",
		"Macromedia",
		"Adobe ColdFusion",
		"rds_password",
		"enter password",
	}

	for _, endpoint := range endpoints {
		targetURL := getURL(target, endpoint)

		resp, err := client.Get(targetURL)
		if err != nil {
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
		resp.Body.Close()
		bodyStr := string(bodyBytes)

		if resp.StatusCode != 200 {
			continue
		}

		lowerBody := strings.ToLower(bodyStr)
		if strings.Contains(lowerBody, "not found") ||
			strings.Contains(lowerBody, "error 404") ||
			strings.Contains(lowerBody, "page does not exist") {
			continue
		}

		foundSig := ""
		for _, sig := range signatures {
			if strings.Contains(bodyStr, sig) {
				foundSig = sig
				break
			}
		}

		if foundSig != "" {
			return &models.Vulnerability{
				Target:      target,
				Name:        "ColdFusion Sensitive Interface Exposed",
				Severity:    "HIGH",
				CVSS:        7.5,
				Description: fmt.Sprintf("A ColdFusion interface was found at %s.\nConfirmation: Server returned 200 OK and body contained ColdFusion signature: '%s'.", endpoint, foundSig),
				Solution:    "Restrict access to the /CFIDE directory to localhost or VPN only.",
				Reference:   "Adobe ColdFusion Lockdown Guide",
			}
		}
	}

	return nil
}
