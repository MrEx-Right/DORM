package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

type ExpressJSPlugin struct{}

func (p *ExpressJSPlugin) Name() string { return "Express/Node.js Security Misconfiguration Scanner" }

func (p *ExpressJSPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Fingerprint ──────────────────────────────────────────────────────────
	probeResp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	probeBody, _ := io.ReadAll(probeResp.Body)
	probeResp.Body.Close()

	xPowered := probeResp.Header.Get("X-Powered-By")
	setCookie := probeResp.Header.Get("Set-Cookie")
	server := probeResp.Header.Get("Server")
	bodyLow := strings.ToLower(string(probeBody))

	isExpress := strings.Contains(xPowered, "Express") ||
		strings.Contains(setCookie, "connect.sid") ||
		strings.Contains(server, "node") ||
		strings.Contains(bodyLow, "express") ||
		strings.Contains(bodyLow, "node.js")

	if !isExpress {
		return nil
	}

	type finding struct {
		name     string
		severity string
		cvss     float64
		desc     string
	}
	var findings []finding

	// ── Probe 1: X-Powered-By Header (version leakage) ───────────────────────
	if strings.Contains(xPowered, "Express") {
		findings = append(findings, finding{
			name:     "Express.js Version Disclosed via X-Powered-By",
			severity: "LOW",
			cvss:     3.1,
			desc:     fmt.Sprintf("The X-Powered-By header discloses the framework: '%s'. This should be removed with app.disable('x-powered-by').", xPowered),
		})
	}

	// ── Probe 2: package.json ─────────────────────────────────────────────────
	pkgResp, err := client.Get(baseURL + "/package.json")
	if err == nil {
		pkgBody, _ := io.ReadAll(pkgResp.Body)
		pkgResp.Body.Close()
		bodyStr := string(pkgBody)
		if pkgResp.StatusCode == 200 && strings.Contains(bodyStr, `"dependencies"`) {
			findings = append(findings, finding{
				name:     "package.json Publicly Accessible",
				severity: "HIGH",
				cvss:     7.5,
				desc:     "The package.json file is publicly accessible. It exposes all application dependencies with exact versions, scripts, and project metadata — enabling targeted supply-chain attacks.",
			})
		}
	}

	// ── Probe 3: package-lock.json / yarn.lock ────────────────────────────────
	lockFiles := []string{"/package-lock.json", "/yarn.lock", "/npm-shrinkwrap.json"}
	for _, lf := range lockFiles {
		lResp, err := client.Get(baseURL + lf)
		if err == nil {
			lBody, _ := io.ReadAll(lResp.Body)
			lResp.Body.Close()
			bodyStr := string(lBody)
			if lResp.StatusCode == 200 && (strings.Contains(bodyStr, `"lockfileVersion"`) || strings.Contains(bodyStr, "__metadata")) {
				findings = append(findings, finding{
					name:     fmt.Sprintf("Node.js Lock File Exposed (%s)", lf),
					severity: "MEDIUM",
					cvss:     5.3,
					desc:     fmt.Sprintf("The dependency lock file (%s) is publicly accessible. It exposes the full resolved dependency tree.", lf),
				})
				break
			}
		}
	}

	// ── Probe 4: node_modules directory listing ───────────────────────────────
	nmResp, err := client.Get(baseURL + "/node_modules/")
	if err == nil {
		nmBody, _ := io.ReadAll(nmResp.Body)
		nmResp.Body.Close()
		bodyLow2 := strings.ToLower(string(nmBody))
		if nmResp.StatusCode == 200 && (strings.Contains(bodyLow2, "index of") || strings.Contains(bodyLow2, "<a href=")) {
			findings = append(findings, finding{
				name:     "node_modules Directory Listing Enabled",
				severity: "CRITICAL",
				cvss:     9.1,
				desc:     "The /node_modules/ directory is browsable. Attackers can directly access and download any installed package source code, including packages with known vulnerabilities.",
			})
		}
	}

	// ── Probe 5: .env file ────────────────────────────────────────────────────
	envResp, err := client.Get(baseURL + "/.env")
	if err == nil {
		envBody, _ := io.ReadAll(envResp.Body)
		envResp.Body.Close()
		bodyStr := string(envBody)
		if envResp.StatusCode == 200 && (strings.Contains(bodyStr, "NODE_ENV") || strings.Contains(bodyStr, "DB_PASSWORD") || strings.Contains(bodyStr, "SECRET") || strings.Contains(bodyStr, "API_KEY")) {
			findings = append(findings, finding{
				name:     "Node.js .env File Exposed",
				severity: "CRITICAL",
				cvss:     9.8,
				desc:     "The .env environment configuration file is publicly accessible. It likely contains database credentials, API keys, JWT secrets, and other sensitive configuration values.",
			})
		}
	}

	// ── Probe 6: Source Map Files ─────────────────────────────────────────────
	mapPaths := []string{"/app.js.map", "/main.js.map", "/bundle.js.map", "/dist/app.js.map", "/dist/bundle.js.map"}
	for _, mp := range mapPaths {
		mapResp, err := client.Get(baseURL + mp)
		if err == nil {
			mapBody, _ := io.ReadAll(mapResp.Body)
			mapResp.Body.Close()
			if mapResp.StatusCode == 200 && strings.Contains(string(mapBody), `"sources"`) {
				findings = append(findings, finding{
					name:     "JavaScript Source Map Exposed",
					severity: "HIGH",
					cvss:     7.0,
					desc:     fmt.Sprintf("A JavaScript source map file (%s) is publicly accessible. Attackers can reconstruct the original TypeScript/ES6 source code, exposing business logic and internal API structure.", mp),
				})
				break
			}
		}
	}

	// ── Probe 7: Log / Debug Endpoints ───────────────────────────────────────
	logPaths := []string{"/logs", "/log", "/debug", "/_logs", "/api/logs", "/api/debug"}
	for _, lp := range logPaths {
		logResp, err := client.Get(baseURL + lp)
		if err == nil {
			logBody, _ := io.ReadAll(logResp.Body)
			logResp.Body.Close()
			bodyStr := string(logBody)
			if logResp.StatusCode == 200 && (strings.Contains(bodyStr, "[INFO]") || strings.Contains(bodyStr, "[ERROR]") || strings.Contains(bodyStr, "[DEBUG]") || strings.Contains(bodyStr, "winston") || strings.Contains(bodyStr, "morgan")) {
				findings = append(findings, finding{
					name:     "Node.js Application Log Endpoint Exposed",
					severity: "HIGH",
					cvss:     7.2,
					desc:     fmt.Sprintf("The log endpoint (%s) is publicly accessible. Application logs may contain request data, user identifiers, internal errors, and system information.", lp),
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
		Name:        "Express/Node.js Security Misconfiguration",
		Severity:    best.severity,
		CVSS:        best.cvss,
		Description: strings.Join(allDescs, "\n\n"),
		Solution:    "Disable X-Powered-By header. Move package.json and lock files out of the web root. Block access to .env files and node_modules via the web server. Disable source map generation in production. Restrict or remove debug/log endpoints.",
		Reference:   "OWASP Security Misconfiguration / Node.js Security Best Practices",
	}
}
