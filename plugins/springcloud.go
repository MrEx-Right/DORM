package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 54. SPRING CLOUD GATEWAY RCE (CVE-2022-22947) - v2
type SpringCloudPlugin struct{}

func (p *SpringCloudPlugin) Name() string { return "Spring Cloud Gateway RCE (Verified)" }

func (p *SpringCloudPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	targetEndpoint := "/actuator/gateway/routes"
	fullURL := getURL(target, targetEndpoint)

	resp, err := client.Get(fullURL)
	if err == nil {
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)

		if resp.StatusCode == 200 {
			if strings.Contains(bodyString, "\"predicate\"") && (strings.Contains(bodyString, "\"filters\"") || strings.Contains(bodyString, "\"route_id\"")) {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Spring Cloud Gateway RCE (Exposed Actuator)",
					Severity:    "CRITICAL",
					CVSS:        10.0,
					Description: "Spring Cloud Gateway Actuator endpoint is exposed and unauthenticated.\nVerified Signature: Valid Route JSON structure detected.",
					Solution:    "Disable the gateway actuator endpoint (`management.endpoint.gateway.enabled=false`) or secure it with authentication.",
					Reference:   "CVE-2022-22947",
				}
			}
		}
	}
	return nil
}
