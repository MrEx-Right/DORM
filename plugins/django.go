package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

type DjangoPlugin struct{}

func (p *DjangoPlugin) Name() string { return "Django Security Misconfiguration Scanner" }

func (p *DjangoPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Fingerprint ──────────────────────────────────────────────────────────
	// Probe 1: /admin/ → Django administration page
	// Probe 2: Trigger a 404 and look for Django-specific error markers
	isDjango := false

	adminResp, err := client.Get(baseURL + "/admin/")
	if err == nil {
		adminBody, _ := io.ReadAll(adminResp.Body)
		adminResp.Body.Close()
		if strings.Contains(strings.ToLower(string(adminBody)), "django administration") ||
			strings.Contains(strings.ToLower(string(adminBody)), "csrfmiddlewaretoken") {
			isDjango = true
		}
	}

	if !isDjango {
		randResp, err2 := client.Get(baseURL + "/dorm-django-probe-xyz-404")
		if err2 == nil {
			randBody, _ := io.ReadAll(randResp.Body)
			randResp.Body.Close()
			bodyLow := strings.ToLower(string(randBody))
			if strings.Contains(bodyLow, "django") ||
				strings.Contains(bodyLow, "disallowedhost") ||
				strings.Contains(bodyLow, "django.core") {
				isDjango = true
			}
		}
	}

	if !isDjango {
		return nil
	}

	type finding struct {
		name     string
		severity string
		cvss     float64
		desc     string
	}
	var findings []finding

	// ── Probe 1: Debug Mode (stack trace / DisallowedHost) ───────────────────
	errResp, err := client.Get(baseURL + "/dorm-debug-probe-" + fmt.Sprintf("%d", 99999))
	if err == nil {
		body, _ := io.ReadAll(errResp.Body)
		errResp.Body.Close()
		bodyStr := string(body)
		bodyLow := strings.ToLower(bodyStr)
		if strings.Contains(bodyLow, "disallowedhost") ||
			strings.Contains(bodyLow, "improperlyconfigured") ||
			strings.Contains(bodyLow, "django.core") ||
			(strings.Contains(bodyStr, "Traceback") && strings.Contains(bodyStr, "File \"")) {
			findings = append(findings, finding{
				name:     "Django Debug Mode Enabled",
				severity: "HIGH",
				cvss:     7.5,
				desc:     "Django is running with DEBUG=True. Full stack traces and internal configuration details are exposed to unauthenticated users.",
			})
		}
		// Secret key in debug output
		if strings.Contains(bodyStr, "django-insecure-") {
			findings = append(findings, finding{
				name:     "Django Insecure Secret Key Exposed",
				severity: "CRITICAL",
				cvss:     9.1,
				desc:     "The default insecure SECRET_KEY (prefixed 'django-insecure-') is visible in the error page. This key must be replaced and kept secret.",
			})
		}
	}

	// ── Probe 2: Admin Panel Accessible ─────────────────────────────────────
	aResp, err := client.Get(baseURL + "/admin/")
	if err == nil {
		aBody, _ := io.ReadAll(aResp.Body)
		aResp.Body.Close()
		bodyLow := strings.ToLower(string(aBody))
		if aResp.StatusCode == 200 && strings.Contains(bodyLow, "django administration") {
			findings = append(findings, finding{
				name:     "Django Admin Panel Exposed",
				severity: "MEDIUM",
				cvss:     5.3,
				desc:     "The Django admin panel (/admin/) is publicly accessible. Exposure of the admin login interface increases the attack surface.",
			})
		}
	}

	// ── Probe 3: Django Debug Toolbar ────────────────────────────────────────
	dtResp, err := client.Get(baseURL + "/__debug__/")
	if err == nil {
		dtBody, _ := io.ReadAll(dtResp.Body)
		dtResp.Body.Close()
		bodyLow := strings.ToLower(string(dtBody))
		if dtResp.StatusCode == 200 && (strings.Contains(bodyLow, "djdt") || strings.Contains(bodyLow, "django debug toolbar")) {
			findings = append(findings, finding{
				name:     "Django Debug Toolbar Exposed",
				severity: "HIGH",
				cvss:     7.2,
				desc:     "The Django Debug Toolbar (/__debug__/) is accessible in production. It exposes SQL queries, request headers, session data, and performance profiling.",
			})
		}
	}

	// ── Probe 4: DRF Browsable API ───────────────────────────────────────────
	apiResp, err := client.Get(baseURL + "/api/?format=api")
	if err == nil {
		apiBody, _ := io.ReadAll(apiResp.Body)
		apiResp.Body.Close()
		bodyLow := strings.ToLower(string(apiBody))
		if apiResp.StatusCode == 200 && (strings.Contains(bodyLow, "django rest framework") || strings.Contains(bodyLow, "browsable")) {
			findings = append(findings, finding{
				name:     "Django REST Framework Browsable API Exposed",
				severity: "MEDIUM",
				cvss:     5.3,
				desc:     "The Django REST Framework Browsable API renderer is enabled in production. The full API schema and interactive forms are accessible without authentication.",
			})
		}
	}

	// ── Probe 5: API Schema / Docs Endpoint ──────────────────────────────────
	schemaEndpoints := []string{"/api/schema/", "/api/docs/", "/api/swagger/", "/schema/"}
	for _, ep := range schemaEndpoints {
		sResp, err := client.Get(baseURL + ep)
		if err == nil {
			sBody, _ := io.ReadAll(sResp.Body)
			sResp.Body.Close()
			bodyLow := strings.ToLower(string(sBody))
			if sResp.StatusCode == 200 && (strings.Contains(bodyLow, "openapi") || strings.Contains(bodyLow, "swagger") || strings.Contains(bodyLow, `"paths"`)) {
				findings = append(findings, finding{
					name:     "Django API Schema Publicly Exposed",
					severity: "MEDIUM",
					cvss:     5.3,
					desc:     fmt.Sprintf("The API schema endpoint (%s) is publicly accessible. Full endpoint listing and model structure are exposed.", ep),
				})
				break
			}
		}
	}

	// ── Probe 6: Static Directory Listing ────────────────────────────────────
	staticResp, err := client.Get(baseURL + "/static/")
	if err == nil {
		staticBody, _ := io.ReadAll(staticResp.Body)
		staticResp.Body.Close()
		bodyLow := strings.ToLower(string(staticBody))
		if staticResp.StatusCode == 200 && strings.Contains(bodyLow, "index of") {
			findings = append(findings, finding{
				name:     "Django Static Files Directory Listing",
				severity: "MEDIUM",
				cvss:     5.0,
				desc:     "Directory listing is enabled on /static/. Attackers can enumerate all static assets including JavaScript, CSS, and potentially sensitive files.",
			})
		}
	}

	// ── Aggregate & Return Highest Severity Finding ──────────────────────────
	if len(findings) == 0 {
		return nil
	}

	// Return the most severe finding; append all descriptions
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
		Name:        "Django Security Misconfiguration",
		Severity:    best.severity,
		CVSS:        best.cvss,
		Description: strings.Join(allDescs, "\n\n"),
		Solution:    "Set DEBUG=False in production. Restrict /admin/ to internal networks. Disable the Debug Toolbar in production. Remove browsable API renderer from REST_FRAMEWORK settings. Disable static file serving via Django in production (use a CDN or web server).",
		Reference:   "OWASP Security Misconfiguration / Django Deployment Checklist",
	}
}
