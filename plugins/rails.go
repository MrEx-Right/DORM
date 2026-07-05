package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

type RailsPlugin struct{}

func (p *RailsPlugin) Name() string { return "Ruby on Rails Security Misconfiguration Scanner" }

func (p *RailsPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Fingerprint ──────────────────────────────────────────────────────────
	// X-Runtime header (Rails always sets this as a float, e.g. "0.123456")
	// or _session_id cookie in Set-Cookie header
	probeResp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	probeBody, _ := io.ReadAll(probeResp.Body)
	probeResp.Body.Close()

	xRuntime := probeResp.Header.Get("X-Runtime")
	setCookie := probeResp.Header.Get("Set-Cookie")
	bodyLow := strings.ToLower(string(probeBody))

	isRails := strings.Contains(xRuntime, "0.") ||
		strings.Contains(setCookie, "_session_id") ||
		strings.Contains(bodyLow, "rails") ||
		probeResp.Header.Get("X-Powered-By") == "Phusion Passenger"

	if !isRails {
		return nil
	}

	type finding struct {
		name     string
		severity string
		cvss     float64
		desc     string
	}
	var findings []finding

	// ── Probe 1: /rails/info/properties ─────────────────────────────────────
	ripResp, err := client.Get(baseURL + "/rails/info/properties")
	if err == nil {
		ripBody, _ := io.ReadAll(ripResp.Body)
		ripResp.Body.Close()
		bodyStr := string(ripBody)
		if ripResp.StatusCode == 200 && (strings.Contains(bodyStr, "Ruby version") || strings.Contains(bodyStr, "Rails version")) {
			findings = append(findings, finding{
				name:     "Rails Info Properties Page Exposed",
				severity: "HIGH",
				cvss:     7.5,
				desc:     fmt.Sprintf("The /rails/info/properties endpoint is publicly accessible. It exposes Ruby/Rails version, middleware stack, and environment configuration.\nResponse snippet: %s", bodyStr[:min(200, len(bodyStr))]),
			})
		}
	}

	// ── Probe 2: /rails/info/routes ──────────────────────────────────────────
	rrResp, err := client.Get(baseURL + "/rails/info/routes")
	if err == nil {
		rrBody, _ := io.ReadAll(rrResp.Body)
		rrResp.Body.Close()
		bodyStr := string(rrBody)
		if rrResp.StatusCode == 200 && (strings.Contains(bodyStr, "GET") || strings.Contains(bodyStr, "POST")) && strings.Contains(bodyStr, "Path") {
			findings = append(findings, finding{
				name:     "Rails Route Table Exposed",
				severity: "HIGH",
				cvss:     6.5,
				desc:     "The /rails/info/routes endpoint is publicly accessible. The full application route table — including internal/admin routes — is visible to unauthenticated users.",
			})
		}
	}

	// ── Probe 3: Development Exception Page ──────────────────────────────────
	randResp, err := client.Get(baseURL + "/dorm-rails-probe-xyz-notfound")
	if err == nil {
		randBody, _ := io.ReadAll(randResp.Body)
		randResp.Body.Close()
		bodyStr := string(randBody)
		if strings.Contains(bodyStr, "ActionController::RoutingError") || strings.Contains(bodyStr, "Rails.root") {
			findings = append(findings, finding{
				name:     "Rails Development Exception Page Exposed",
				severity: "HIGH",
				cvss:     7.2,
				desc:     "Detailed Rails exception pages are rendered in production. These expose internal file paths (Rails.root), gem structure, and source code snippets.",
			})
		}
	}

	// ── Probe 4: Mailer Previews ─────────────────────────────────────────────
	mailResp, err := client.Get(baseURL + "/rails/mailers/")
	if err == nil {
		mailBody, _ := io.ReadAll(mailResp.Body)
		mailResp.Body.Close()
		bodyLow2 := strings.ToLower(string(mailBody))
		if mailResp.StatusCode == 200 && (strings.Contains(bodyLow2, "mailer preview") || strings.Contains(bodyLow2, "mailers")) {
			findings = append(findings, finding{
				name:     "Rails Mailer Preview Endpoint Exposed",
				severity: "HIGH",
				cvss:     7.0,
				desc:     "The /rails/mailers/ endpoint is accessible. It renders email templates which may contain real user data, URLs with auth tokens, or PII.",
			})
		}
	}

	// ── Probe 5: Asset Source Maps ───────────────────────────────────────────
	mapPaths := []string{"/assets/application.js.map", "/assets/application.css.map"}
	for _, mp := range mapPaths {
		mapResp, err := client.Get(baseURL + mp)
		if err == nil {
			mapBody, _ := io.ReadAll(mapResp.Body)
			mapResp.Body.Close()
			if mapResp.StatusCode == 200 && strings.Contains(string(mapBody), `"mappings"`) {
				findings = append(findings, finding{
					name:     "Rails Asset Source Map Exposed",
					severity: "MEDIUM",
					cvss:     5.3,
					desc:     fmt.Sprintf("Source map file (%s) is publicly accessible. Attackers can reconstruct the original JavaScript/CoffeeScript source code.", mp),
				})
				break
			}
		}
	}

	// ── Probe 6: Sign-in / Auth Endpoints ────────────────────────────────────
	authPaths := []string{"/users/sign_in", "/admin/sign_in", "/user/sign_in"}
	for _, ap := range authPaths {
		authResp, err := client.Get(baseURL + ap)
		if err == nil {
			authBody, _ := io.ReadAll(authResp.Body)
			authResp.Body.Close()
			bodyLow3 := strings.ToLower(string(authBody))
			if authResp.StatusCode == 200 && strings.Contains(bodyLow3, "sign_in") && strings.Contains(bodyLow3, "password") {
				findings = append(findings, finding{
					name:     "Rails Authentication Endpoint Exposed",
					severity: "MEDIUM",
					cvss:     4.3,
					desc:     fmt.Sprintf("Authentication endpoint (%s) is publicly accessible. Enumeration and brute-force attacks are possible.", ap),
				})
				break
			}
		}
	}

	if len(findings) == 0 {
		return nil
	}

	best := findings[0]
	for _, f := range findings[1:] {
		if f.cvss > best.cvss {
			best = f
		}
	}

	var allDescs []string
	for _, f := range findings {
		allDescs = append(allDescs, fmt.Sprintf("[%s] %s: %s", f.severity, f.name, f.desc))
	}

	return &models.Vulnerability{
		Target:      target,
		Name:        "Ruby on Rails Security Misconfiguration",
		Severity:    best.severity,
		CVSS:        best.cvss,
		Description: strings.Join(allDescs, "\n\n"),
		Solution:    "Set config.consider_all_requests_local = false in production. Restrict /rails/info/* routes. Disable mailer previews in production. Disable source map generation or restrict access. Enforce authentication on all sensitive endpoints.",
		Reference:   "OWASP Security Misconfiguration / Rails Security Guide",
	}
}
