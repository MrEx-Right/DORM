package plugins

import (
	"DORM/models"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)


type NextJSPlugin struct{}

func (p *NextJSPlugin) Name() string { return "Next.js Security Misconfiguration Scanner" }

func (p *NextJSPlugin) Run(target models.ScanTarget) *models.Vulnerability {
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
	bodyStr := string(probeBody)

	xNextPage := probeResp.Header.Get("x-nextjs-page")
	isNextJS := strings.Contains(bodyStr, `__NEXT_DATA__`) ||
		strings.Contains(bodyStr, `/_next/static/`) ||
		xNextPage != ""

	if !isNextJS {
		return nil
	}

	type finding struct {
		name     string
		severity string
		cvss     float64
		desc     string
	}
	var findings []finding

	// ── Probe 1: __NEXT_DATA__ env/config leak ────────────────────────────────
	// Extract the JSON from <script id="__NEXT_DATA__" type="application/json">...</script>
	startTag := `<script id="__NEXT_DATA__" type="application/json">`
	endTag := `</script>`
	startIdx := strings.Index(bodyStr, startTag)
	if startIdx != -1 {
		jsonStart := startIdx + len(startTag)
		endIdx := strings.Index(bodyStr[jsonStart:], endTag)
		if endIdx != -1 {
			rawJSON := bodyStr[jsonStart : jsonStart+endIdx]
			var nextData map[string]interface{}
			if json.Unmarshal([]byte(rawJSON), &nextData) == nil {
				// Check for env / serverRuntimeConfig / publicRuntimeConfig keys
				envLeak := false
				envKeys := []string{"env", "serverRuntimeConfig", "runtimeConfig"}
				for _, key := range envLeak_keys(nextData, envKeys) {
					if key != "" {
						envLeak = true
						break
					}
				}
				if envLeak {
					findings = append(findings, finding{
						name:     "Next.js __NEXT_DATA__ Server Config Leaked to Client",
						severity: "HIGH",
						cvss:     7.5,
						desc:     "The __NEXT_DATA__ JSON blob contains server-side configuration keys (env, serverRuntimeConfig, runtimeConfig) that are visible in the page source. Sensitive values may be exposed to all visitors.",
					})
				}
			}
		}
	}

	// ── Probe 2: BUILD_ID ─────────────────────────────────────────────────────
	buildResp, err := client.Get(baseURL + "/_next/BUILD_ID")
	if err == nil {
		buildBody, _ := io.ReadAll(buildResp.Body)
		buildResp.Body.Close()
		buildID := strings.TrimSpace(string(buildBody))
		if buildResp.StatusCode == 200 && len(buildID) > 5 {
			findings = append(findings, finding{
				name:     "Next.js Build ID Exposed",
				severity: "LOW",
				cvss:     3.1,
				desc:     fmt.Sprintf("The deployment build ID is accessible at /_next/BUILD_ID: '%s'. This can be used to fingerprint specific deployments.", buildID),
			})
		}
	}

	// ── Probe 3: next.config.js ───────────────────────────────────────────────
	cfgResp, err := client.Get(baseURL + "/next.config.js")
	if err == nil {
		cfgBody, _ := io.ReadAll(cfgResp.Body)
		cfgResp.Body.Close()
		bodyStr2 := string(cfgBody)
		if cfgResp.StatusCode == 200 && (strings.Contains(bodyStr2, "module.exports") || strings.Contains(bodyStr2, "env:") || strings.Contains(bodyStr2, "nextConfig")) {
			findings = append(findings, finding{
				name:     "next.config.js Publicly Accessible",
				severity: "HIGH",
				cvss:     7.2,
				desc:     "The Next.js configuration file (next.config.js) is publicly accessible. It may expose environment variable names, allowed domains, redirect rules, and internal configuration.",
			})
		}
	}

	// ── Probe 4: Source Maps ──────────────────────────────────────────────────
	mapPaths := []string{
		"/_next/static/chunks/pages/_app.js.map",
		"/_next/static/chunks/main.js.map",
		"/_next/static/chunks/pages/index.js.map",
	}
	for _, mp := range mapPaths {
		mapResp, err := client.Get(baseURL + mp)
		if err == nil {
			mapBody, _ := io.ReadAll(mapResp.Body)
			mapResp.Body.Close()
			if mapResp.StatusCode == 200 && strings.Contains(string(mapBody), `"sources"`) {
				findings = append(findings, finding{
					name:     "Next.js JavaScript Source Map Exposed",
					severity: "HIGH",
					cvss:     7.0,
					desc:     fmt.Sprintf("A Next.js source map file (%s) is publicly accessible. Attackers can recover original TypeScript/React source code, revealing business logic and internal API routes.", mp),
				})
				break
			}
		}
	}

	// ── Probe 5: Unprotected API Routes ──────────────────────────────────────
	apiPaths := []string{"/api/env", "/api/config", "/api/admin", "/api/settings", "/api/debug"}
	for _, ap := range apiPaths {
		aResp, err := client.Get(baseURL + ap)
		if err == nil {
			aBody, _ := io.ReadAll(aResp.Body)
			aResp.Body.Close()
			bodyStr3 := string(aBody)
			if aResp.StatusCode == 200 && (strings.Contains(bodyStr3, "secret") || strings.Contains(bodyStr3, "password") || strings.Contains(bodyStr3, "token") || strings.Contains(bodyStr3, "key") || strings.Contains(bodyStr3, "database")) {
				findings = append(findings, finding{
					name:     fmt.Sprintf("Next.js Sensitive API Route Exposed (%s)", ap),
					severity: "HIGH",
					cvss:     7.5,
					desc:     fmt.Sprintf("The API route %s is publicly accessible and returns potentially sensitive data (secret/password/token/key/database fields detected in response).", ap),
				})
				break
			}
		}
	}

	// ── Probe 6: Middleware Bypass Header ────────────────────────────────────
	bypassReq, _ := client.Get(baseURL + "/admin")
	if bypassReq != nil {
		baseStatus := bypassReq.StatusCode
		bypassReq.Body.Close()

		bypassReq2, _ := newRequestWithHeader("GET", baseURL+"/admin", "x-middleware-subrequest", "middleware:middleware:middleware:middleware:middleware")
		if bypassReq2 != nil {
			resp2, err2 := client.Do(bypassReq2)
			if err2 == nil {
				resp2.Body.Close()
				// If the status changed from a redirect/forbidden to 200, middleware was bypassed
				if baseStatus != resp2.StatusCode && (resp2.StatusCode == 200 || resp2.StatusCode == 304) {
					findings = append(findings, finding{
						name:     "Next.js Middleware Authorization Bypass",
						severity: "HIGH",
						cvss:     7.5,
						desc:     fmt.Sprintf("The x-middleware-subrequest header altered the response for /admin (baseline: %d → bypass: %d). Next.js middleware-based authorization may be bypassable.", baseStatus, resp2.StatusCode),
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
		Name:        "Next.js Security Misconfiguration",
		Severity:    best.severity,
		CVSS:        best.cvss,
		Description: strings.Join(allDescs, "\n\n"),
		Solution:    "Never expose server-side secrets via publicRuntimeConfig or getServerSideProps pageProps. Disable source map generation in production (productionBrowserSourceMaps: false). Restrict next.config.js via web server rules. Implement proper server-side authorization beyond middleware. Protect sensitive API routes with authentication.",
		Reference:   "OWASP Security Misconfiguration / Next.js Security Best Practices",
	}
}

// envLeak_keys checks if any of the target keys exist and have non-empty values in a nested map
func envLeak_keys(data map[string]interface{}, keys []string) []string {
	var found []string
	for _, key := range keys {
		if val, ok := data[key]; ok {
			switch v := val.(type) {
			case map[string]interface{}:
				if len(v) > 0 {
					found = append(found, key)
				}
			case string:
				if v != "" {
					found = append(found, key)
				}
			}
		}
	}
	return found
}

// newRequestWithHeader creates a new GET request with a single custom header
func newRequestWithHeader(method, url, headerKey, headerValue string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(headerKey, headerValue)
	return req, nil
}
