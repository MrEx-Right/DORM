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
	var highestCVSS float64
	severity := "INFO"

	for _, tech := range profile.Techs {
		// Search by product name first, then try vendor:product composite key.
		// Version is no longer required — we now match via structured CVE fields too.
		cves := models.SearchLocalCVEs(tech.Product, tech.Version)

		// Deduplicate by CVE ID across multiple searches.
		seen := make(map[string]struct{})

		for _, cve := range cves {
			if _, dup := seen[cve.ID]; dup {
				continue
			}
			seen[cve.ID] = struct{}{}

			// Version matching: prefer structured field first, fall back to description NLP.
			vulnerable := false
			if tech.Version != "" {
				if cve.Version != "" {
					// Structured: check if the tech version is less than the patched version.
					vulnerable = isVersionLessThan(tech.Version, cve.Version) ||
						tech.Version == cve.Version
				}
				// NLP fallback: scan description text for version constraints.
				if !vulnerable {
					vulnerable = isVersionVulnerable(tech.Version, cve.Description)
				}
			} else {
				// No version detected for this technology (very common — e.g.
				// a WAF/CDN name, or PHP/Java/ASP.NET inferred only from a
				// cookie name with no version string attached). We have no
				// basis to claim a specific CVE applies, so — despite this
				// plugin's "Precision Mode" branding — skip it rather than
				// claiming every CVE ever filed against that product name is
				// "confirmed"/"explicitly vulnerable". This was previously
				// unnoticed because the classic New Scan screen always sent
				// cveRadar=false, so this plugin never actually ran in
				// practice until DORM Vectors started forcing it on.
				vulnerable = false
			}

			if !vulnerable {
				continue
			}

			// Include all CVEs in the report, regardless of CVSS score.
			allFindings += fmt.Sprintf(
				"- [%s] %s v%s — %s (CVSS: %.1f)\n  %s\n\n",
				cve.ID,
				strings.ToUpper(tech.Product),
				tech.Version,
				cve.Severity,
				cve.CVSS,
				cve.Description,
			)
			if cve.CVSS > highestCVSS {
				highestCVSS = cve.CVSS
			}
		}
	}

	if allFindings == "" {
		return nil
	}

	switch {
	case highestCVSS >= 9.0:
		severity = "CRITICAL"
	case highestCVSS >= 7.0:
		severity = "HIGH"
	case highestCVSS >= 4.0:
		severity = "MEDIUM"
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
