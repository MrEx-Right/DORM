package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

type AspNetCorePlugin struct{}

func (p *AspNetCorePlugin) Name() string { return "ASP.NET Core Security Misconfiguration Scanner" }

func (p *AspNetCorePlugin) Run(target models.ScanTarget) *models.Vulnerability {
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
	xAspNet := probeResp.Header.Get("X-AspNet-Version")
	server := probeResp.Header.Get("Server")
	bodyLow := strings.ToLower(string(probeBody))

	isAspNet := strings.Contains(xPowered, "ASP.NET") ||
		xAspNet != "" ||
		strings.Contains(server, "Microsoft-IIS") ||
		strings.Contains(server, "Kestrel") ||
		strings.Contains(bodyLow, "__requestverificationtoken") ||
		strings.Contains(bodyLow, "asp-validation")

	if !isAspNet {
		return nil
	}

	type finding struct {
		name     string
		severity string
		cvss     float64
		desc     string
	}
	var findings []finding

	// ── Probe 1: Developer Exception Page ────────────────────────────────────
	randResp, err := client.Get(baseURL + "/dorm-aspnet-probe-xyz-notfound")
	if err == nil {
		randBody, _ := io.ReadAll(randResp.Body)
		randResp.Body.Close()
		bodyStr := string(randBody)
		if strings.Contains(bodyStr, "Microsoft.AspNetCore.Diagnostics") ||
			strings.Contains(bodyStr, "DeveloperExceptionPage") ||
			strings.Contains(bodyStr, "at System.") ||
			strings.Contains(bodyStr, "at Microsoft.AspNetCore.") {
			findings = append(findings, finding{
				name:     "ASP.NET Core Developer Exception Page Enabled",
				severity: "HIGH",
				cvss:     7.5,
				desc:     "The DeveloperExceptionPageMiddleware is active in production. Full .NET stack traces, internal namespace structure, assembly names, and source file paths are exposed.",
			})
		}
	}

	// ── Probe 2: Trace.axd ───────────────────────────────────────────────────
	traceResp, err := client.Get(baseURL + "/Trace.axd")
	if err == nil {
		traceBody, _ := io.ReadAll(traceResp.Body)
		traceResp.Body.Close()
		if traceResp.StatusCode == 200 && strings.Contains(string(traceBody), "Application Trace") {
			findings = append(findings, finding{
				name:     "ASP.NET Trace.axd Exposed",
				severity: "HIGH",
				cvss:     7.2,
				desc:     "The ASP.NET Trace.axd diagnostic page is accessible. It displays a full history of HTTP requests including headers, session variables, and form data.",
			})
		}
	}

	// ── Probe 3: Elmah Error Log ─────────────────────────────────────────────
	elmahPaths := []string{"/elmah.axd", "/api/errors", "/errors"}
	for _, ep := range elmahPaths {
		elmahResp, err := client.Get(baseURL + ep)
		if err == nil {
			elmahBody, _ := io.ReadAll(elmahResp.Body)
			elmahResp.Body.Close()
			bodyStr := string(elmahBody)
			if elmahResp.StatusCode == 200 && (strings.Contains(bodyStr, "Error Log for") || strings.Contains(bodyStr, "ELMAH")) {
				findings = append(findings, finding{
					name:     "ASP.NET ELMAH Error Log Exposed",
					severity: "HIGH",
					cvss:     7.5,
					desc:     fmt.Sprintf("The ELMAH error log (%s) is publicly accessible. It contains detailed application error records including stack traces, request data, and potentially sensitive user information.", ep),
				})
				break
			}
		}
	}

	// ── Probe 4: web.config Backup Files ─────────────────────────────────────
	backupPaths := []string{"/web.config.bak", "/web.config.old", "/Web.config~", "/web.config.orig"}
	for _, bp := range backupPaths {
		bResp, err := client.Get(baseURL + bp)
		if err == nil {
			bBody, _ := io.ReadAll(bResp.Body)
			bResp.Body.Close()
			bodyStr := string(bBody)
			if bResp.StatusCode == 200 && (strings.Contains(bodyStr, "<configuration>") || strings.Contains(bodyStr, "connectionString") || strings.Contains(bodyStr, "appSettings")) {
				findings = append(findings, finding{
					name:     "ASP.NET web.config Backup File Exposed",
					severity: "CRITICAL",
					cvss:     9.1,
					desc:     fmt.Sprintf("A web.config backup file (%s) is publicly accessible. It may contain database connection strings, API keys, encryption keys, and other secrets.", bp),
				})
				break
			}
		}
	}

	// ── Probe 5: Blazor WASM Boot Manifest ───────────────────────────────────
	blazorResp, err := client.Get(baseURL + "/_framework/blazor.boot.json")
	if err == nil {
		blazorBody, _ := io.ReadAll(blazorResp.Body)
		blazorResp.Body.Close()
		if blazorResp.StatusCode == 200 && strings.Contains(string(blazorBody), `"assemblies"`) {
			findings = append(findings, finding{
				name:     "Blazor WebAssembly Boot Manifest Exposed",
				severity: "MEDIUM",
				cvss:     5.3,
				desc:     "The Blazor WASM boot manifest (/_framework/blazor.boot.json) reveals the full list of .NET assemblies used by the application. Attackers can use this to map the application's internal structure.",
			})
		}
	}

	// ── Probe 6: Swagger / OpenAPI ───────────────────────────────────────────
	swaggerPaths := []string{"/swagger", "/api-docs", "/swagger/index.html", "/swagger/v1/swagger.json"}
	for _, sp := range swaggerPaths {
		sResp, err := client.Get(baseURL + sp)
		if err == nil {
			sBody, _ := io.ReadAll(sResp.Body)
			sResp.Body.Close()
			bodyLow2 := strings.ToLower(string(sBody))
			if sResp.StatusCode == 200 && (strings.Contains(bodyLow2, `"openapi"`) || strings.Contains(bodyLow2, "swagger") || strings.Contains(bodyLow2, `"paths"`)) {
				findings = append(findings, finding{
					name:     "ASP.NET Swagger/OpenAPI UI Exposed in Production",
					severity: "MEDIUM",
					cvss:     5.3,
					desc:     fmt.Sprintf("Swagger/OpenAPI documentation (%s) is publicly accessible. Full API endpoint listing, request/response schemas, and authentication requirements are exposed.", sp),
				})
				break
			}
		}
	}

	// ── Probe 7: Health Check Endpoint ───────────────────────────────────────
	healthPaths := []string{"/health", "/health/ready", "/health/live", "/healthz"}
	for _, hp := range healthPaths {
		hResp, err := client.Get(baseURL + hp)
		if err == nil {
			hBody, _ := io.ReadAll(hResp.Body)
			hResp.Body.Close()
			bodyStr := string(hBody)
			bodyLow3 := strings.ToLower(bodyStr)
			if hResp.StatusCode == 200 && (strings.Contains(bodyLow3, "unhealthy") || strings.Contains(bodyLow3, "degraded") || strings.Contains(bodyLow3, "connectionstring") || strings.Contains(bodyLow3, "database") || strings.Contains(bodyLow3, "redis")) {
				findings = append(findings, finding{
					name:     "ASP.NET Health Check Reveals Internal Infrastructure",
					severity: "MEDIUM",
					cvss:     5.0,
					desc:     fmt.Sprintf("The health check endpoint (%s) exposes internal service names, database connection status, or infrastructure topology.", hp),
				})
				break
			}
		}
	}

	// ── Probe 8: SignalR Hub Negotiation ─────────────────────────────────────
	signalrPaths := []string{"/hub/negotiate", "/signalr/negotiate", "/chathub/negotiate"}
	for _, srp := range signalrPaths {
		srResp, err := client.Get(baseURL + srp)
		if err == nil {
			srBody, _ := io.ReadAll(srResp.Body)
			srResp.Body.Close()
			if srResp.StatusCode == 200 && strings.Contains(string(srBody), "connectionToken") {
				findings = append(findings, finding{
					name:     "SignalR Hub Negotiation Endpoint Exposed",
					severity: "MEDIUM",
					cvss:     4.3,
					desc:     fmt.Sprintf("The SignalR negotiate endpoint (%s) is publicly accessible and returns connection tokens. Unauthenticated access to real-time communication channels may be possible.", srp),
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
		Name:        "ASP.NET Core Security Misconfiguration",
		Severity:    best.severity,
		CVSS:        best.cvss,
		Description: strings.Join(allDescs, "\n\n"),
		Solution:    "Disable developer exception pages in production (app.UseExceptionHandler). Remove Trace.axd and ELMAH from public access. Delete backup configuration files. Restrict Swagger UI to development environments. Minimize health check response detail in production.",
		Reference:   "OWASP Security Misconfiguration / ASP.NET Core Security Best Practices",
	}
}
