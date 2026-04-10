package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

type WPEnumPlugin struct{}

func (p *WPEnumPlugin) Name() string { return "WordPress Enumeration & CVE Radar" }

func (p *WPEnumPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	resp, err := client.Get(baseURL + "/wp-login.php")
	if err != nil {
		return nil
	}
	resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 403 {
		return nil
	}

	var findings []string
	var highestCVSS float64 = 0.0
	var severity string = "INFO"

	checkCVEs := func(product string, version string) {
		if version == "" {
			return
		}

		cves := models.SearchLocalCVEs(product, "Any")
		for _, cve := range cves {

			if isVersionVulnerable(version, cve.Description) {
				if cve.CVSS >= 7.0 {
					findings = append(findings, fmt.Sprintf("- [%s] %s v%s (CVSS: %.1f)\n  %s", cve.ID, strings.Title(product), version, cve.CVSS, cve.Description))
					if cve.CVSS > highestCVSS {
						highestCVSS = cve.CVSS
					}
				}
			}
		}
	}

	wpVersion := ""
	req1, _ := http.NewRequest("GET", baseURL+"/readme.html", nil)
	resp1, err1 := client.Do(req1)

	if err1 == nil && resp1.StatusCode == 200 {

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp1.Body, 2048))
		resp1.Body.Close()

		re := regexp.MustCompile(`(?i)Version\s+([0-9\.]+)`)
		m := re.FindStringSubmatch(string(bodyBytes))

		if len(m) > 1 {
			wpVersion = m[1]
			findings = append(findings, fmt.Sprintf("[+] Core: WordPress v%s (Disclosed via readme.html)", wpVersion))
			checkCVEs("wordpress", wpVersion)
		}
	}

	plugins := []string{
		"akismet", "contact-form-7", "woocommerce", "elementor",
		"revslider", "wp-file-manager", "duplicator", "updraftplus",
		"wordfence", "wp-mail-smtp", "jetpack", "yoast-seo",
	}

	for _, plugin := range plugins {
		pluginURL := fmt.Sprintf("%s/wp-content/plugins/%s/readme.txt", baseURL, plugin)
		reqP, _ := http.NewRequest("GET", pluginURL, nil)
		respP, errP := client.Do(reqP)

		if errP == nil && respP.StatusCode == 200 {
			bodyBytes, _ := io.ReadAll(io.LimitReader(respP.Body, 2048))
			respP.Body.Close()

			reStable := regexp.MustCompile(`(?i)Stable tag:\s*([0-9\.]+)`)
			m := reStable.FindStringSubmatch(string(bodyBytes))

			pluginVersion := "Unknown"
			if len(m) > 1 {
				pluginVersion = m[1]
			}

			findings = append(findings, fmt.Sprintf("[+] Plugin: %s v%s", plugin, pluginVersion))

			if pluginVersion != "Unknown" {
				checkCVEs(plugin, pluginVersion)
			}
		}
	}

	if len(findings) > 0 {
		if highestCVSS >= 9.0 {
			severity = "CRITICAL"
		} else if highestCVSS >= 7.0 {
			severity = "HIGH"
		} else {
			severity = "MEDIUM"
		}

		return &models.Vulnerability{
			Target:      target,
			Name:        "WordPress Enumeration & Known CVEs",
			Severity:    severity,
			CVSS:        highestCVSS,
			Description: fmt.Sprintf("WordPress infrastructure enumeration revealed the following components and associated vulnerabilities:\n\n%s", strings.Join(findings, "\n\n")),
			Solution:    "Restrict access to readme.html, disable directory listing, and update all themes/plugins to their latest stable versions.",
			Reference:   "OWASP Vulnerable and Outdated Components",
		}
	}

	return nil
}
