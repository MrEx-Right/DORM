package plugins

import (
	"DORM/models"
	"fmt"
	"strings"
)

type PassiveCVEPlugin struct{}

func (p *PassiveCVEPlugin) Name() string { return "Offline CVE Radar (Precision Mode)" }

func (p *PassiveCVEPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	profile := models.DeepScanTarget(getURL(target, ""))

	var allFindings string
	var highestCVSS float64 = 0.0
	var severity string = "INFO"

	for _, tech := range profile.Techs {

		if len(tech.Version) < 2 {
			continue
		}

		cves := models.SearchLocalCVEs(tech.Product, "Any")

		for _, cve := range cves {

			if isVersionVulnerable(tech.Version, cve.Description) {
				if cve.CVSS >= 7.0 {
					allFindings += fmt.Sprintf("- [%s] %s v%s (CVSS: %.1f)\n  %s\n\n", cve.ID, strings.Title(tech.Product), tech.Version, cve.CVSS, cve.Description)
					if cve.CVSS > highestCVSS {
						highestCVSS = cve.CVSS
					}
				}
			}
		}
	}

	if allFindings != "" {
		if highestCVSS >= 9.0 {
			severity = "CRITICAL"
		} else if highestCVSS >= 7.0 {
			severity = "HIGH"
		}

		return &models.Vulnerability{
			Target:      target,
			Name:        "Verified Outdated Technology / Known CVEs",
			Severity:    severity,
			CVSS:        highestCVSS,
			Description: fmt.Sprintf("Precision analysis confirmed the server is explicitly vulnerable:\n\n%s", allFindings),
			Solution:    "Review the listed CVEs and apply vendor patches immediately.",
			Reference:   "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
		}
	}

	return nil
}
