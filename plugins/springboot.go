package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

// 14. SPRING BOOT ACTUATOR (Information Disclosure) - v2
type SpringBootPlugin struct{}

func (p *SpringBootPlugin) Name() string { return "Spring Boot Actuator (Verified)" }

func (p *SpringBootPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	endpoints := []string{
		"/actuator/env",
		"/env",
	}

	for _, endpoint := range endpoints {
		fullURL := getURL(target, endpoint)
		resp, err := client.Get(fullURL)

		if err == nil {

			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyString := string(bodyBytes)

			isVerified := resp.StatusCode == 200 && (strings.Contains(bodyString, "\"propertySources\"") ||
				strings.Contains(bodyString, "\"systemProperties\"") ||
				(strings.Contains(bodyString, "\"activeProfiles\"") && strings.Contains(bodyString, "server.port")))

			if isVerified {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Spring Boot Actuator Exposed",
					Severity:    "CRITICAL",
					CVSS:        9.8,
					Description: fmt.Sprintf("Sensitive configuration and environment variables exposed via %s.\nSignature verified: Spring Boot JSON structure detected.", endpoint),
					Solution:    "Restrict access to Actuator endpoints using Spring Security or block external access via firewall.",
					Reference:   "OWASP Security Misconfiguration",
				}
			}
		}
	}
	return nil
}
