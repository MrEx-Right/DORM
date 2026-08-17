package wafengine

import (
	"DORM/models"
	"fmt"
	"strings"
)

// ============================================================
//  WAF DETECTOR ENGINE — v3.0 "Deep Sentinel"
//  Multi-layer WAF fingerprinting + CDN detection
//  Behavioral probing + bypass advisory
// ============================================================

type WAFDetectorPlugin struct{}

func (p *WAFDetectorPlugin) Name() string { return "WAF Detection" }

func (p *WAFDetectorPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	// ================================================================
	// PHASE 1: PASSIVE FINGERPRINT — Header Analysis
	// ================================================================
	wafName, confidence, details := AnalyzeHeaders(client, baseURL)

	// ================================================================
	// PHASE 2: CDN vs WAF Differentiation
	// ================================================================
	cdnName, isCDNOnly := DetectCDN(client, baseURL)
	if isCDNOnly && wafName == "" {
		// It's a CDN without WAF capabilities — store but don't alert
		models.SharedData.Store(fmt.Sprintf("cdn_type_%s", target.IP), cdnName)
	}

	// ================================================================
	// PHASE 3: ACTIVE BEHAVIORAL PROBE
	// ================================================================
	if wafName == "" {
		wafName, confidence, details = BehaviorProbe(client, baseURL)
	}

	// ================================================================
	// PHASE 4: STORE WAF INFO + BYPASS ADVISORY
	// ================================================================
	if wafName != "" {
		// Store WAF type for other engines (XSS, SQLi, etc.)
		models.SharedData.Store(fmt.Sprintf("waf_type_%s", target.IP), wafName)

		// Generate bypass hints
		bypassHints := GetBypassAdvisory(wafName)
		models.SharedData.Store(fmt.Sprintf("waf_bypass_%s", target.IP), bypassHints)

		severity := "INFO"
		cvss := 0.0

		var desc strings.Builder
		desc.WriteString(fmt.Sprintf("Active Web Application Firewall detected: %s\n", wafName))
		desc.WriteString(fmt.Sprintf("Detection Confidence: %s\n\n", confidence))

		if details != "" {
			desc.WriteString(fmt.Sprintf("Detection Details:\n%s\n\n", details))
		}

		if cdnName != "" {
			desc.WriteString(fmt.Sprintf("CDN Layer: %s\n", cdnName))
		}

		desc.WriteString(fmt.Sprintf("Bypass Advisory: %s", bypassHints))

		return &models.Vulnerability{
			Target:      target,
			Name:        fmt.Sprintf("WAF Detected: %s", wafName),
			Severity:    severity,
			CVSS:        cvss,
			Description: desc.String(),
			Solution:    "Consider using WAF bypass techniques or testing from a whitelisted IP address if authorized.",
			Reference:   "https://owasp.org/www-community/Web_Application_Firewall",
		}
	}

	// Also check via DeepScan (legacy fallback)
	profile := models.DeepScanTarget(baseURL)
	if profile != nil && profile.WAF != "" {
		models.SharedData.Store(fmt.Sprintf("waf_type_%s", target.IP), profile.WAF)
		bypassHints := GetBypassAdvisory(profile.WAF)
		models.SharedData.Store(fmt.Sprintf("waf_bypass_%s", target.IP), bypassHints)

		return &models.Vulnerability{
			Target:      target,
			Name:        fmt.Sprintf("WAF Detected: %s", profile.WAF),
			Severity:    "INFO",
			CVSS:        0.0,
			Description: fmt.Sprintf("Active Web Application Firewall (%s) detected on the target via deep fingerprinting.\nBypass Advisory: %s", profile.WAF, bypassHints),
			Solution:    "Consider using WAF bypass techniques or testing from a whitelisted IP address if authorized.",
			Reference:   "https://owasp.org/www-community/Web_Application_Firewall",
		}
	}

	return nil
}
