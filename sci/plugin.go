package sci

import (
	"DORM/models"
	"fmt"
	"strings"
)

// SupplyChainPlugin integrates supply chain analysis into the DORM scan engine.
// It runs automatically with every scan (same start/stop lifecycle as the engine).
// For each web target, it performs full supply chain analysis and reports
// any components with CVEs as a vulnerability finding.
type SupplyChainPlugin struct{}

func (p *SupplyChainPlugin) Name() string { return "Supply Chain Risk Analysis" }

func (p *SupplyChainPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPortSCI(target.Port) {
		return nil
	}

	proto := "https"
	if target.Port == 80 || target.Port == 8080 || target.Port == 8000 || target.Port == 8001 {
		proto = "http"
	}
	targetURL := fmt.Sprintf("%s://%s:%d", proto, target.IP, target.Port)

	result := AnalyzeTarget(targetURL)

	if result.Error != "" || len(result.Components) == 0 {
		return nil
	}

	// Only report if there are CVE findings
	riskyComponents := 0
	for _, c := range result.Components {
		if c.CVECount > 0 {
			riskyComponents++
		}
	}

	if riskyComponents == 0 {
		return nil
	}

	// Build structured report
	var sb strings.Builder
	_, _ = fmt.Fprintf(&sb, "Supply chain analysis detected %d components, %d with known CVEs (total: %d CVEs)\n\n",
		result.RiskSummary.TotalComponents,
		result.RiskSummary.WithCVEs,
		result.TotalCVEs,
	)

	// Risk breakdown
	if result.RiskSummary.Critical > 0 {
		_, _ = fmt.Fprintf(&sb, "🔴 CRITICAL risk components: %d\n", result.RiskSummary.Critical)
	}
	if result.RiskSummary.High > 0 {
		_, _ = fmt.Fprintf(&sb, "🟠 HIGH risk components: %d\n", result.RiskSummary.High)
	}
	if result.RiskSummary.Medium > 0 {
		_, _ = fmt.Fprintf(&sb, "🟡 MEDIUM risk components: %d\n", result.RiskSummary.Medium)
	}
	if result.RiskSummary.Low > 0 {
		_, _ = fmt.Fprintf(&sb, "🔵 LOW risk components: %d\n", result.RiskSummary.Low)
	}
	sb.WriteString("\n")

	// Per-component CVE details (highest risk first)
	for _, c := range result.Components {
		if c.CVECount == 0 {
			continue
		}
		version := c.Version
		if version == "" {
			version = "unknown version"
		}
		_, _ = fmt.Fprintf(&sb, "▶ [%s] %s %s (%s) — %d CVE(s), CVSS max: %.1f\n",
			c.RiskLevel, c.Name, version, c.Category, c.CVECount, c.HighestCVSS)

		// List up to 5 CVEs per component to keep output readable
		limit := c.CVECount
		if limit > 5 {
			limit = 5
		}
		for i := 0; i < limit; i++ {
			cve := c.CVEs[i]
			_, _ = fmt.Fprintf(&sb, "   - [%s] %s (CVSS: %.1f) — %s\n",
				cve.ID, cve.Severity, cve.CVSS,
				truncate(cve.Description, 120))
		}
		if c.CVECount > 5 {
			_, _ = fmt.Fprintf(&sb, "   ... and %d more CVEs. Use Supply Chain Interface for full details.\n", c.CVECount-5)
		}
		sb.WriteString("\n")
	}

	// Determine overall severity based on highest CVSS across all findings
	highestCVSS := 0.0
	for _, c := range result.Components {
		if c.HighestCVSS > highestCVSS {
			highestCVSS = c.HighestCVSS
		}
	}

	var severity string
	switch {
	case highestCVSS >= 9.0:
		severity = "CRITICAL"
	case highestCVSS >= 7.0:
		severity = "HIGH"
	case highestCVSS >= 4.0:
		severity = "MEDIUM"
	default:
		severity = "LOW"
	}

	return &models.Vulnerability{
		Target:      target,
		Name:        fmt.Sprintf("Supply Chain Risk — %d Vulnerable Component(s) Detected", riskyComponents),
		Severity:    severity,
		CVSS:        highestCVSS,
		Description: sb.String(),
		Solution:    "Update all listed components to their latest patched versions. Review the Supply Chain Interface panel for complete CVE details and remediation guidance.",
		Reference:   "https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components",
	}
}

// isWebPortSCI checks if the port is a standard web port for supply chain analysis.
func isWebPortSCI(port int) bool {
	switch port {
	case 80, 443, 8080, 8443, 8000, 8001, 8081, 3000, 5000, 9090, 4000, 4443:
		return true
	}
	return false
}

// truncate cuts a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
