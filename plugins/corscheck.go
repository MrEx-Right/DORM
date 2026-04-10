package plugins

import (
	"DORM/models"
	"fmt"
	"net/http"
	"strings"
)

type CORSCheckPlugin struct{}

func (p *CORSCheckPlugin) Name() string { return "CORS Misconfiguration Scanner" }

func (p *CORSCheckPlugin) Run(target models.ScanTarget) *models.Vulnerability {

	if !isWebPort(target.Port) {
		return nil
	}

	baseURL := getURL(target, "")
	client := models.GetClient()

	var vulns []string
	highestSeverity := "LOW"
	highestCVSS := 0.0

	testOrigins := []string{
		"http://evil-attacker.com",
		"https://evil-attacker.com",
		"null",
		fmt.Sprintf("http://%s.evil-attacker.com", target.IP),
		fmt.Sprintf("http://evil%s", target.IP),
	}

	for _, origin := range testOrigins {

		req, _ := http.NewRequest("GET", baseURL, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("User-Agent", "DORM-CORS-Tester/1.3.5")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		vary := resp.Header.Get("Vary")
		resp.Body.Close()

		if acao == "*" {

			if acac == "true" {
				vulns = append(vulns, fmt.Sprintf("[INFO] Wildcard (*) allowed for public access. (Origin: %s)", origin))
			}

			if highestCVSS < 5.0 {
				highestSeverity = "LOW"
				highestCVSS = 5.3
			}
		}

		if acao == origin {
			isCrit := false

			if acac == "true" {
				vulns = append(vulns, fmt.Sprintf("[CRITICAL] Reflected Origin WITH Credentials allowed! Origin: %s", origin))
				highestSeverity = "CRITICAL"
				highestCVSS = 9.5
				isCrit = true
			} else {

				vulns = append(vulns, fmt.Sprintf("[HIGH] Reflected Origin allowed (No Creds). Origin: %s", origin))
				if highestCVSS < 7.5 {
					highestSeverity = "HIGH"
					highestCVSS = 7.5
				}
			}

			if !strings.Contains(vary, "Origin") {
				if highestCVSS < 6.5 {
					highestSeverity = "MEDIUM"
					highestCVSS = 6.5
				}
			}

			if isCrit {
				reqOpts, _ := http.NewRequest("OPTIONS", baseURL, nil)
				reqOpts.Header.Set("Origin", origin)
				reqOpts.Header.Set("Access-Control-Request-Method", "POST")
				reqOpts.Header.Set("Access-Control-Request-Headers", "X-DORM-Test")

				respOpts, errOpts := client.Do(reqOpts)
				if errOpts == nil {
					optsACAO := respOpts.Header.Get("Access-Control-Allow-Origin")
					if optsACAO == origin || optsACAO == "*" {
						vulns = append(vulns, fmt.Sprintf("[CRITICAL] Preflight (OPTIONS) also trusts malicious origin: %s", origin))
					}
					respOpts.Body.Close()
				}
			}
		}
	}

	if len(vulns) > 0 {

		uniqueVulns := make(map[string]bool)
		cleanVulns := []string{}
		for _, v := range vulns {
			if !uniqueVulns[v] {
				uniqueVulns[v] = true
				cleanVulns = append(cleanVulns, v)
			}
		}

		return &models.Vulnerability{
			Target:      target,
			Name:        "CORS Policy Misconfiguration",
			Severity:    highestSeverity,
			CVSS:        highestCVSS,
			Description: strings.Join(cleanVulns, "\n"),
			Solution:    "1. Avoid using wildcard (*) with credentials.\n2. Whitelist trusted origins explicitly.\n3. If reflecting origin, verify it against a server-side whitelist regex.\n4. Always send 'Vary: Origin' header to prevent cache poisoning.",
			Reference:   "PortSwigger: CORS Vulnerabilities / OWASP API Security",
		}
	}

	return nil
}
