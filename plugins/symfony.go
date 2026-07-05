package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

type SymfonyPlugin struct{}

func (p *SymfonyPlugin) Name() string { return "Symfony Security Misconfiguration Scanner" }

func (p *SymfonyPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Fingerprint ──────────────────────────────────────────────────────────
	// X-Debug-Token header (Symfony sets this on every response in debug mode)
	// or sf-dump class in body, or Symfony\ in a 404 response
	isSymfony := false

	probeResp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	probeBody, _ := io.ReadAll(probeResp.Body)
	probeResp.Body.Close()

	xDebugToken := probeResp.Header.Get("X-Debug-Token")
	bodyLow := strings.ToLower(string(probeBody))
	if xDebugToken != "" || strings.Contains(bodyLow, "sf-dump") || strings.Contains(bodyLow, "symfony") {
		isSymfony = true
	}

	if !isSymfony {
		randResp, err := client.Get(baseURL + "/dorm-symfony-probe-xyz")
		if err == nil {
			randBody, _ := io.ReadAll(randResp.Body)
			randResp.Body.Close()
			bodyStr := string(randBody)
			if strings.Contains(bodyStr, "Symfony\\Component") || strings.Contains(bodyStr, "Symfony\\Bundle") {
				isSymfony = true
			}
		}
	}

	if !isSymfony {
		return nil
	}

	type finding struct {
		name     string
		severity string
		cvss     float64
		desc     string
	}
	var findings []finding

	// ── Probe 1: Web Debug Toolbar ────────────────────────────────────────────
	wdtResp, err := client.Get(baseURL + "/_wdt/")
	if err == nil {
		wdtBody, _ := io.ReadAll(wdtResp.Body)
		wdtResp.Body.Close()
		bodyStr := string(wdtBody)
		bodyLow2 := strings.ToLower(bodyStr)
		if wdtResp.StatusCode == 200 && (strings.Contains(bodyLow2, "sf-toolbar") || strings.Contains(bodyLow2, "symfony") || strings.Contains(bodyLow2, "wdt")) {
			findings = append(findings, finding{
				name:     "Symfony Web Debug Toolbar (WDT) Exposed",
				severity: "HIGH",
				cvss:     7.2,
				desc:     "The Symfony Web Debug Toolbar endpoint (/_wdt/) is publicly accessible. It provides access to request profiling data, SQL queries, log messages, and Twig rendering statistics.",
			})
		}
	}

	// ── Probe 2: Profiler ─────────────────────────────────────────────────────
	profilerResp, err := client.Get(baseURL + "/_profiler/")
	if err == nil {
		profilerBody, _ := io.ReadAll(profilerResp.Body)
		profilerResp.Body.Close()
		bodyStr := string(profilerBody)
		bodyLow3 := strings.ToLower(bodyStr)
		if profilerResp.StatusCode == 200 && (strings.Contains(bodyLow3, "symfony profiler") || strings.Contains(bodyLow3, "request / response") || strings.Contains(bodyStr, "_profiler")) {
			findings = append(findings, finding{
				name:     "Symfony Profiler Exposed",
				severity: "HIGH",
				cvss:     7.5,
				desc:     "The Symfony Profiler (/_profiler/) is publicly accessible. It exposes the full HTTP request/response cycle, database query logs, cache operations, and event listener data for all previous requests.",
			})
		}
	}

	// ── Probe 3: Development Front Controllers ────────────────────────────────
	devControllers := []string{"/app_dev.php", "/index_dev.php", "/web/app_dev.php"}
	for _, dc := range devControllers {
		dcResp, err := client.Get(baseURL + dc)
		if err == nil {
			dcBody, _ := io.ReadAll(dcResp.Body)
			dcResp.Body.Close()
			bodyLow4 := strings.ToLower(string(dcBody))
			if dcResp.StatusCode == 200 && (strings.Contains(bodyLow4, "symfony") || strings.Contains(bodyLow4, "sf-dump")) {
				findings = append(findings, finding{
					name:     fmt.Sprintf("Symfony Development Front Controller Exposed (%s)", dc),
					severity: "HIGH",
					cvss:     7.2,
					desc:     fmt.Sprintf("The Symfony development front controller (%s) is publicly accessible. This enables full debug mode, detailed error pages, and profiling in the production environment.", dc),
				})
				break
			}
		}
	}

	// ── Probe 4: Exception Page Stack Trace ───────────────────────────────────
	randResp, err := client.Get(baseURL + "/dorm-symfony-probe-notfound-xyz")
	if err == nil {
		randBody, _ := io.ReadAll(randResp.Body)
		randResp.Body.Close()
		bodyStr := string(randBody)
		if strings.Contains(bodyStr, "Symfony\\Component\\HttpKernel\\Exception") ||
			strings.Contains(bodyStr, "Symfony\\Component\\Routing") ||
			strings.Contains(bodyStr, "templates/") && strings.Contains(bodyStr, ".twig") {
			findings = append(findings, finding{
				name:     "Symfony Exception Page Reveals Internal Structure",
				severity: "HIGH",
				cvss:     7.5,
				desc:     "Symfony exception pages expose internal class names (Symfony\\Component namespace), Twig template paths, and file system structure in HTTP responses.",
			})
		}
	}

	// ── Probe 5: .env Variants ────────────────────────────────────────────────
	envFiles := []string{"/.env.local", "/.env.dev", "/.env.test", "/.env.prod", "/.env.local.php"}
	for _, ef := range envFiles {
		efResp, err := client.Get(baseURL + ef)
		if err == nil {
			efBody, _ := io.ReadAll(efResp.Body)
			efResp.Body.Close()
			bodyStr := string(efBody)
			if efResp.StatusCode == 200 && (strings.Contains(bodyStr, "APP_SECRET") || strings.Contains(bodyStr, "DATABASE_URL") || strings.Contains(bodyStr, "APP_ENV") || strings.Contains(bodyStr, "MAILER_DSN")) {
				findings = append(findings, finding{
					name:     fmt.Sprintf("Symfony Environment File Exposed (%s)", ef),
					severity: "CRITICAL",
					cvss:     9.1,
					desc:     fmt.Sprintf("The Symfony environment file (%s) is publicly accessible. It contains APP_SECRET, DATABASE_URL, and other sensitive credentials.", ef),
				})
				break
			}
		}
	}

	// ── Probe 6: API Platform Documentation ──────────────────────────────────
	apiPlatformPaths := []string{"/api/platform/docs", "/api/docs", "/api", "/api/docs.json"}
	for _, ap := range apiPlatformPaths {
		apResp, err := client.Get(baseURL + ap)
		if err == nil {
			apBody, _ := io.ReadAll(apResp.Body)
			apResp.Body.Close()
			bodyStr := string(apBody)
			if apResp.StatusCode == 200 && (strings.Contains(bodyStr, `"@context"`) || strings.Contains(bodyStr, "hydra:") || strings.Contains(bodyStr, "ApiPlatform")) {
				findings = append(findings, finding{
					name:     "Symfony API Platform Documentation Exposed",
					severity: "MEDIUM",
					cvss:     5.3,
					desc:     fmt.Sprintf("The API Platform documentation (%s) is publicly accessible. Full resource schemas, operations, and relationships are exposed.", ap),
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
		Name:        "Symfony Security Misconfiguration",
		Severity:    best.severity,
		CVSS:        best.cvss,
		Description: strings.Join(allDescs, "\n\n"),
		Solution:    "Set APP_ENV=prod and APP_DEBUG=false. Remove /_wdt/ and /_profiler/ routes in production (disabled automatically in prod env). Delete app_dev.php from production servers. Block .env file access via web server configuration. Restrict API Platform docs to authenticated users.",
		Reference:   "OWASP Security Misconfiguration / Symfony Security Best Practices",
	}
}
