package plugins

import (
	"DORM/models"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type FastAPIPlugin struct{}

func (p *FastAPIPlugin) Name() string { return "FastAPI Security Misconfiguration Scanner" }

func (p *FastAPIPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Fingerprint ──────────────────────────────────────────────────────────
	// Primary: Server: uvicorn or Server: gunicorn  +  /openapi.json exists
	// Secondary: /docs returns SwaggerUIBundle
	isFastAPI := false

	probeResp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	probeBody, _ := io.ReadAll(probeResp.Body)
	probeResp.Body.Close()

	server := probeResp.Header.Get("Server")
	bodyLow := strings.ToLower(string(probeBody))

	if strings.Contains(server, "uvicorn") || strings.Contains(server, "gunicorn") || strings.Contains(bodyLow, "fastapi") {
		isFastAPI = true
	}

	if !isFastAPI {
		openAPIResp, err := client.Get(baseURL + "/openapi.json")
		if err == nil {
			openAPIBody, _ := io.ReadAll(openAPIResp.Body)
			openAPIResp.Body.Close()
			if openAPIResp.StatusCode == 200 && strings.Contains(string(openAPIBody), `"openapi"`) {
				isFastAPI = true
			}
		}
	}

	if !isFastAPI {
		return nil
	}

	type finding struct {
		name     string
		severity string
		cvss     float64
		desc     string
	}
	var findings []finding

	// ── Probe 1: /docs (Swagger UI) ───────────────────────────────────────────
	docsResp, err := client.Get(baseURL + "/docs")
	if err == nil {
		docsBody, _ := io.ReadAll(docsResp.Body)
		docsResp.Body.Close()
		bodyStr := string(docsBody)
		if docsResp.StatusCode == 200 && (strings.Contains(bodyStr, "SwaggerUIBundle") || strings.Contains(bodyStr, "swagger-ui") || strings.Contains(strings.ToLower(bodyStr), "fastapi")) {
			findings = append(findings, finding{
				name:     "FastAPI Swagger UI Exposed",
				severity: "MEDIUM",
				cvss:     5.3,
				desc:     "The interactive Swagger UI (/docs) is publicly accessible. The full API schema including all endpoints, request models, and response structures is exposed.",
			})
		}
	}

	// ── Probe 2: /redoc ───────────────────────────────────────────────────────
	redocResp, err := client.Get(baseURL + "/redoc")
	if err == nil {
		redocBody, _ := io.ReadAll(redocResp.Body)
		redocResp.Body.Close()
		if redocResp.StatusCode == 200 && (strings.Contains(string(redocBody), "ReDoc") || strings.Contains(string(redocBody), "redoc-container")) {
			findings = append(findings, finding{
				name:     "FastAPI ReDoc Documentation Exposed",
				severity: "MEDIUM",
				cvss:     5.3,
				desc:     "The ReDoc API documentation (/redoc) is publicly accessible. Full API schema and endpoint documentation is visible to unauthenticated users.",
			})
		}
	}

	// ── Probe 3: /openapi.json ────────────────────────────────────────────────
	openAPIResp, err := client.Get(baseURL + "/openapi.json")
	if err == nil {
		openAPIBody, _ := io.ReadAll(openAPIResp.Body)
		openAPIResp.Body.Close()
		bodyStr := string(openAPIBody)
		if openAPIResp.StatusCode == 200 && strings.Contains(bodyStr, `"paths"`) {
			findings = append(findings, finding{
				name:     "FastAPI OpenAPI Schema Publicly Accessible",
				severity: "HIGH",
				cvss:     7.2,
				desc:     "The raw OpenAPI JSON schema (/openapi.json) is publicly accessible. All routes, request parameters, response models, and security requirements are exposed in machine-readable format.",
			})
		}
	}

	// ── Probe 4: Pydantic Validation Error Leak ───────────────────────────────
	// Send wrong type (string where int expected) to a typical endpoint
	badPayload := []byte(`{"username": 12345, "password": [1, 2, 3]}`)
	pydanticEndpoints := []string{"/api/auth/login", "/auth/login", "/login", "/api/login", "/token"}
	for _, ep := range pydanticEndpoints {
		req, _ := http.NewRequest("POST", baseURL+ep, bytes.NewReader(badPayload))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)
			// Pydantic v2 returns {"detail":[{"loc":[...],"msg":"...","type":"..."}]}
			if strings.Contains(bodyStr, `"loc"`) && strings.Contains(bodyStr, `"msg"`) && strings.Contains(bodyStr, `"type"`) {
				findings = append(findings, finding{
					name:     "FastAPI Pydantic Validation Error Details Exposed",
					severity: "MEDIUM",
					cvss:     5.0,
					desc:     fmt.Sprintf("The endpoint %s returns detailed Pydantic validation error objects including field locations, expected types, and validation constraints. This leaks the internal data model schema.", ep),
				})
				break
			}
		}
	}

	// ── Probe 5: Python Traceback in 500 ─────────────────────────────────────
	// Trigger a 500 by sending malformed data
	malformedPayload := []byte(`not-json-at-all{{{`)
	traceEndpoints := []string{"/api", "/api/v1", "/", "/query"}
	for _, ep := range traceEndpoints {
		req, _ := http.NewRequest("POST", baseURL+ep, bytes.NewReader(malformedPayload))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)
			if strings.Contains(bodyStr, "Traceback (most recent call last)") || strings.Contains(bodyStr, `File "`) && strings.Contains(bodyStr, "line ") {
				findings = append(findings, finding{
					name:     "FastAPI Python Traceback Exposed in Error Response",
					severity: "HIGH",
					cvss:     7.5,
					desc:     fmt.Sprintf("The endpoint %s returns a raw Python traceback on error. Internal file paths, class names, and source code context are exposed to unauthenticated users.", ep),
				})
				break
			}
		}
	}

	// ── Probe 6: Prometheus /metrics ─────────────────────────────────────────
	metricsResp, err := client.Get(baseURL + "/metrics")
	if err == nil {
		metricsBody, _ := io.ReadAll(metricsResp.Body)
		metricsResp.Body.Close()
		bodyStr := string(metricsBody)
		if metricsResp.StatusCode == 200 && (strings.Contains(bodyStr, "# HELP") || strings.Contains(bodyStr, "# TYPE")) {
			findings = append(findings, finding{
				name:     "FastAPI Prometheus Metrics Endpoint Exposed",
				severity: "MEDIUM",
				cvss:     5.0,
				desc:     "The Prometheus metrics endpoint (/metrics) is publicly accessible. It exposes request counts, latencies, and potentially internal service names.",
			})
		}
	}

	// ── Probe 7: CORS * + Credentials ────────────────────────────────────────
	corsReq, _ := http.NewRequest("GET", baseURL+"/", nil)
	corsReq.Header.Set("Origin", "http://evil-attacker.com")
	corsResp, err := client.Do(corsReq)
	if err == nil {
		acao := corsResp.Header.Get("Access-Control-Allow-Origin")
		acac := corsResp.Header.Get("Access-Control-Allow-Credentials")
		corsResp.Body.Close()
		if acao == "*" && acac == "true" {
			findings = append(findings, finding{
				name:     "FastAPI CORS Wildcard + Credentials Misconfiguration",
				severity: "HIGH",
				cvss:     7.5,
				desc:     "CORS is configured with allow_origins=['*'] and allow_credentials=True simultaneously. This combination allows any malicious website to make authenticated cross-origin requests on behalf of users.",
			})
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
		Name:        "FastAPI Security Misconfiguration",
		Severity:    best.severity,
		CVSS:        best.cvss,
		Description: strings.Join(allDescs, "\n\n"),
		Solution:    "Disable /docs and /redoc in production (docs_url=None, redoc_url=None). Add exception handlers to return sanitized error messages. Fix CORS configuration: never combine allow_origins=['*'] with allow_credentials=True. Protect /metrics with authentication.",
		Reference:   "OWASP Security Misconfiguration / FastAPI Security Documentation",
	}
}
