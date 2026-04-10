package plugins

import (
	"DORM/models"
	"fmt"
)

// 9. WAF DETECTOR - v1.5.0 DEEP FINGERPRINT INTEGRATED
type WAFDetectorPlugin struct{}

func (p *WAFDetectorPlugin) Name() string { return "WAF Detection" }

func (p *WAFDetectorPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	profile := models.DeepScanTarget(getURL(target, ""))

	if profile.WAF != "" {
		return &models.Vulnerability{
			Target:      target,
			Name:        fmt.Sprintf("WAF Detected: %s", profile.WAF),
			Severity:    "INFO",
			CVSS:        0.0,
			Description: fmt.Sprintf("Active Web Application Firewall (%s) detected on the target. This may filter common exploit payloads.", profile.WAF),
			Solution:    "Consider using WAF bypass techniques or testing from a whitelisted IP address if authorized.",
			Reference:   "https://owasp.org/www-community/Web_Application_Firewall",
		}
	}

	return nil
}
