package plugins

import (
	"DORM/models"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type NestJSPlugin struct{}

func (p *NestJSPlugin) Name() string { return "NestJS Security Misconfiguration Scanner" }

func (p *NestJSPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Fingerprint ──────────────────────────────────────────────────────────
	// NestJS typically runs on Express, exposes /api, and serves OpenAPI docs
	isNestJS := false

	// Check X-Powered-By: Express first
	probeResp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	probeBody, _ := io.ReadAll(probeResp.Body)
	probeResp.Body.Close()
	xPowered := probeResp.Header.Get("X-Powered-By")
	isExpress := strings.Contains(xPowered, "Express")

	if isExpress {
		// Try to confirm NestJS via OpenAPI endpoint
		apiResp, err := client.Get(baseURL + "/api-json")
		if err == nil {
			apiBody, _ := io.ReadAll(apiResp.Body)
			apiResp.Body.Close()
			bodyStr := string(apiBody)
			if apiResp.StatusCode == 200 && strings.Contains(bodyStr, `"openapi"`) {
				isNestJS = true
			}
		}
		if !isNestJS {
			apiResp2, err := client.Get(baseURL + "/api")
			if err == nil {
				apiBody2, _ := io.ReadAll(apiResp2.Body)
				apiResp2.Body.Close()
				bodyLow := strings.ToLower(string(apiBody2))
				if apiResp2.StatusCode == 200 && (strings.Contains(bodyLow, "nestjs") || strings.Contains(bodyLow, "swagger") || strings.Contains(bodyLow, `"openapi"`)) {
					isNestJS = true
				}
			}
		}
	}

	// Also check body for NestJS-specific error format
	if !isNestJS {
		bodyLow := strings.ToLower(string(probeBody))
		if strings.Contains(bodyLow, "nestjs") || strings.Contains(bodyLow, "@nestjs") {
			isNestJS = true
		}
	}

	if !isNestJS {
		return nil
	}

	type finding struct {
		name     string
		severity string
		cvss     float64
		desc     string
	}
	var findings []finding

	// ── Probe 1: Swagger / OpenAPI Exposure ───────────────────────────────────
	swaggerPaths := []string{"/api", "/api-docs", "/swagger", "/swagger-ui", "/api-json", "/api/swagger"}
	for _, sp := range swaggerPaths {
		sResp, err := client.Get(baseURL + sp)
		if err == nil {
			sBody, _ := io.ReadAll(sResp.Body)
			sResp.Body.Close()
			bodyStr := string(sBody)
			if sResp.StatusCode == 200 && (strings.Contains(bodyStr, `"openapi"`) || strings.Contains(bodyStr, `"paths"`) || strings.Contains(strings.ToLower(bodyStr), "swagger")) {
				findings = append(findings, finding{
					name:     "NestJS Swagger/OpenAPI Documentation Exposed",
					severity: "HIGH",
					cvss:     7.2,
					desc:     fmt.Sprintf("Swagger/OpenAPI documentation (%s) is publicly accessible. Full controller routes, request/response schemas, guards, and authentication requirements are exposed to unauthenticated users.", sp),
				})
				break
			}
		}
	}

	// ── Probe 2: Exception Filter Leak (Malformed JSON) ───────────────────────
	badPayload := []byte(`{"invalid": `)
	apiEndpoints := []string{"/api", "/api/auth/login", "/api/users"}
	for _, ep := range apiEndpoints {
		req, _ := http.NewRequest("POST", baseURL+ep, bytes.NewReader(badPayload))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)
			if strings.Contains(bodyStr, "@nestjs/") || strings.Contains(bodyStr, "TypeOrmModule") || strings.Contains(bodyStr, "Nest") {
				findings = append(findings, finding{
					name:     "NestJS Internal Module Names Disclosed",
					severity: "MEDIUM",
					cvss:     5.3,
					desc:     fmt.Sprintf("Sending a malformed JSON payload to %s causes NestJS to return internal module names in the error response (%s...). This reveals the application's internal architecture.", ep, bodyStr[:min(150, len(bodyStr))]),
				})
				break
			}
		}
	}

	// ── Probe 3: Health / Terminus Endpoint ───────────────────────────────────
	healthPaths := []string{"/health", "/health/ready", "/health/live", "/api/health"}
	for _, hp := range healthPaths {
		hResp, err := client.Get(baseURL + hp)
		if err == nil {
			hBody, _ := io.ReadAll(hResp.Body)
			hResp.Body.Close()
			bodyStr := string(hBody)
			bodyLow := strings.ToLower(bodyStr)
			if hResp.StatusCode == 200 && (strings.Contains(bodyLow, "database") || strings.Contains(bodyLow, "redis") || strings.Contains(bodyLow, "typeorm") || strings.Contains(bodyLow, "mongoose")) {
				findings = append(findings, finding{
					name:     "NestJS Health Endpoint Reveals Internal Services",
					severity: "MEDIUM",
					cvss:     5.0,
					desc:     fmt.Sprintf("The health check endpoint (%s) exposes internal service dependencies (database, Redis, ORM details) to unauthenticated users.", hp),
				})
				break
			}
		}
	}

	// ── Probe 4: Debug / Log Endpoints ───────────────────────────────────────
	debugPaths := []string{"/api/debug", "/api/logs", "/api/v1/debug", "/api/v1/logs"}
	for _, dp := range debugPaths {
		dResp, err := client.Get(baseURL + dp)
		if err == nil {
			dBody, _ := io.ReadAll(dResp.Body)
			dResp.Body.Close()
			bodyStr := string(dBody)
			if dResp.StatusCode == 200 && (strings.Contains(bodyStr, "[LOG]") || strings.Contains(bodyStr, "[DEBUG]") || strings.Contains(bodyStr, "[ERROR]") || strings.Contains(bodyStr, "NestFactory")) {
				findings = append(findings, finding{
					name:     "NestJS Debug/Log Endpoint Exposed",
					severity: "HIGH",
					cvss:     7.2,
					desc:     fmt.Sprintf("The debug or log endpoint (%s) is publicly accessible and returns application log data.", dp),
				})
				break
			}
		}
	}

	// ── Probe 5: Swagger Security Gaps (no security schemes on endpoints) ─────
	apiJsonResp, err := client.Get(baseURL + "/api-json")
	if err == nil {
		apiJsonBody, _ := io.ReadAll(apiJsonResp.Body)
		apiJsonResp.Body.Close()
		if apiJsonResp.StatusCode == 200 {
			var apiSpec map[string]interface{}
			if json.Unmarshal(apiJsonBody, &apiSpec) == nil {
				paths, _ := apiSpec["paths"].(map[string]interface{})
				unsecuredCount := 0
				for _, methods := range paths {
					methodMap, ok := methods.(map[string]interface{})
					if !ok {
						continue
					}
					for _, opDef := range methodMap {
						opMap, ok := opDef.(map[string]interface{})
						if !ok {
							continue
						}
						if _, hasSecurity := opMap["security"]; !hasSecurity {
							unsecuredCount++
						}
					}
				}
				if unsecuredCount > 3 {
					findings = append(findings, finding{
						name:     "NestJS API Endpoints Without Security Declarations",
						severity: "MEDIUM",
						cvss:     5.3,
						desc:     fmt.Sprintf("OpenAPI spec reveals %d endpoints with no security scheme declared. These routes may lack authentication guards.", unsecuredCount),
					})
				}
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
		Name:        "NestJS Security Misconfiguration",
		Severity:    best.severity,
		CVSS:        best.cvss,
		Description: strings.Join(allDescs, "\n\n"),
		Solution:    "Disable Swagger in production or protect it with authentication middleware. Implement a global exception filter that sanitizes error responses. Restrict health endpoints to internal networks. Apply AuthGuard globally and only whitelist public routes explicitly.",
		Reference:   "OWASP Security Misconfiguration / NestJS Security Best Practices",
	}
}
