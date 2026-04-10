package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
	"time"
)

// 24. LARAVEL DEBUG MODE (Advanced & Verified) v2
type LaravelDebugPlugin struct{}

func (p *LaravelDebugPlugin) Name() string { return "Laravel Debug Mode / Ignition (Verified)" }

func (p *LaravelDebugPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	ignitionURL := getURL(target, "/_ignition/health-check")
	respIgnition, err := client.Get(ignitionURL)

	if err == nil {
		defer respIgnition.Body.Close()
		bodyBytes, _ := io.ReadAll(respIgnition.Body)
		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, "\"can_execute_commands\"") {
			severity := "HIGH"
			desc := "Laravel Ignition health check exposed. Debug information available."

			if strings.Contains(bodyString, "\"can_execute_commands\":true") || strings.Contains(bodyString, "\"can_execute_commands\": true") {
				severity = "CRITICAL"
				desc = "Laravel Ignition exposed with command execution enabled (CVE-2021-3129)."
			}

			return &models.Vulnerability{
				Target:      target,
				Name:        "Laravel Ignition Debug Page",
				Severity:    severity,
				CVSS:        9.8,
				Description: desc,
				Solution:    "Disable 'APP_DEBUG' in .env and restrict access to '_ignition' endpoints.",
				Reference:   "CVE-2021-3129",
			}
		}
	}

	errorURL := getURL(target, "/dorm-404-test-"+fmt.Sprintf("%d", time.Now().Unix()))
	respError, err := client.Get(errorURL)

	if err == nil {
		defer respError.Body.Close()
		bodyBytes, _ := io.ReadAll(respError.Body)
		bodyString := string(bodyBytes)

		isIgnition := strings.Contains(bodyString, "window.ignition")
		isSymfonyDump := strings.Contains(bodyString, "sf-dump")
		isFacade := strings.Contains(bodyString, "facade/ignition")

		if isIgnition || (isSymfonyDump && isFacade) {
			return &models.Vulnerability{
				Target:      target,
				Name:        "Laravel Debug Mode Enabled (Stack Trace)",
				Severity:    "MEDIUM",
				CVSS:        5.3,
				Description: "Application reveals detailed stack traces and environment variables on error pages.",
				Solution:    "Set 'APP_DEBUG=false' in your production environment configuration.",
				Reference:   "OWASP Information Exposure",
			}
		}
	}

	return nil
}
