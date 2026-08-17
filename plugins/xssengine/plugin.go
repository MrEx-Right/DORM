package xssengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ============================================================
//  XSS ENGINE — v5.0 "Phantom Injector"
//  Reflected · DOM · Context-Aware · WAF-Adaptive
// ============================================================

type XSSPlugin struct{}

func (p *XSSPlugin) Name() string { return "XSS (Next-Gen - Reflected & DOM)" }

func (p *XSSPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	canary := fmt.Sprintf("dormxss%d", time.Now().UnixNano()%99999)

	// Load WAF info from SharedData (set by WAF Engine)
	wafType := models.GetSharedString(fmt.Sprintf("waf_type_%s", target.IP))

	// ================================================================
	// PHASE 1: CHARACTER REFLECTION PROBE
	// ================================================================
	charProbe := fmt.Sprintf(`xss-probe-%s"'<>/&`, canary)

	endpoints := []string{
		"/", "/search", "/search.php", "/results.aspx", "/index.php",
		"/Search.aspx", "/find", "/lookup", "/query", "/filter",
	}
	params := []string{
		"q", "s", "search", "keyword", "query", "lang", "id", "msg",
		"term", "text", "name", "input", "value", "data", "url", "redirect",
		"callback", "next", "return", "page", "file", "path",
	}

	for _, ep := range endpoints {
		for _, param := range params {
			probeURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(charProbe))
			resp, err := client.Get(probeURL)
			if err != nil {
				continue
			}
			probeBody := models.ReadBody(resp, 32768)

			if strings.Contains(probeBody, `"`) && strings.Contains(probeBody, `<`) &&
				strings.Contains(probeBody, canary) {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Reflected XSS (Character Probe — Unfiltered)",
					Severity:    "HIGH",
					CVSS:        8.0,
					Description: fmt.Sprintf("Dangerous characters (< > \" ' /) are reflected unencoded in response body.\nThis confirms a strong XSS vulnerability without encoding protection.\nURL: %s?%s=%s\nParam: %s", baseURL+ep, param, charProbe, param),
					Solution:    "Apply context-aware output encoding. Use HTML entity encoding for HTML contexts, JS encoding for script contexts. Adopt a Content Security Policy (CSP).",
					Reference:   "https://owasp.org/www-community/attacks/xss/",
				}
			}
		}
	}

	// ================================================================
	// PHASE 2: REFLECTED XSS — WAF-Adaptive Payload Arsenal
	// ================================================================
	payloads := GetPayloads(canary, wafType)

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range payloads {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(payload))
				resp, err := client.Get(targetURL)
				if err != nil {
					continue
				}
				body := models.ReadBody(resp, 32768)

				if strings.Contains(body, canary) {
					if ContainsXSSIndicator(body) {
						return &models.Vulnerability{
							Target:      target,
							Name:        "Reflected XSS (Verified — Payload Executed)",
							Severity:    "HIGH",
							CVSS:        7.5,
							Description: fmt.Sprintf("XSS payload reflected and unencoded in response body.\nURL: %s\nParameter: %s\nPayload: %s", targetURL, param, payload),
							Solution:    "Implement context-aware output encoding. Deploy strict Content-Security-Policy headers.",
							Reference:   "https://owasp.org/www-community/attacks/xss/",
						}
					}
				}
			}
		}
	}

	// ================================================================
	// PHASE 3: SPIDER ENDPOINT INTEGRATION — GET & POST
	// ================================================================
	key := "endpoints_" + target.IP
	if existing, ok := models.SharedData.Load(key); ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if len(ep.Params) == 0 {
				continue
			}
			for _, param := range ep.Params {
				for _, payload := range payloads[:min(len(payloads), 20)] { // limit to first 20 payloads for spider
					var resp *http.Response
					var err error

					if ep.Method == "GET" {
						u, e := url.Parse(ep.URL)
						if e != nil {
							continue
						}
						q := u.Query()
						q.Set(param, payload)
						u.RawQuery = q.Encode()
						resp, err = client.Get(u.String())
					} else if ep.Method == "POST" {
						formData := url.Values{}
						formData.Set(param, payload)
						resp, err = client.PostForm(ep.URL, formData)
					}

					if err != nil || resp == nil {
						continue
					}
					body := models.ReadBody(resp, 32768)

					if strings.Contains(body, canary) && ContainsXSSIndicator(body) {
						return &models.Vulnerability{
							Target:      target,
							Name:        fmt.Sprintf("Reflected XSS (Spider-Discovered — %s)", ep.Method),
							Severity:    "HIGH",
							CVSS:        7.5,
							Description: fmt.Sprintf("XSS payload reflected on a %s parameter discovered by Spider.\nURL: %s\nParameter: %s\nPayload: %s", ep.Method, ep.URL, param, payload),
							Solution:    "Apply context-aware output encoding. Sanitize all user-controlled inputs server-side.",
							Reference:   "https://owasp.org/www-community/attacks/xss/",
						}
					}
				}
			}
		}
	}

	// ================================================================
	// PHASE 4: DOM XSS — Static JavaScript Bundle Analysis
	// ================================================================
	domResult := ScanDOMXSS(client, baseURL, target)
	if domResult != nil {
		return domResult
	}

	// ================================================================
	// PHASE 5: CONTEXT-AWARE INJECTION
	// ================================================================
	contextResult := RunContextAwareInjection(client, baseURL, target, canary, endpoints, params)
	if contextResult != nil {
		return contextResult
	}

	return nil
}

// ContainsXSSIndicator checks if the body contains unencoded XSS-relevant HTML.
func ContainsXSSIndicator(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<script") ||
		strings.Contains(lower, "<img") ||
		strings.Contains(lower, "<svg") ||
		strings.Contains(lower, "<iframe") ||
		strings.Contains(lower, "<details") ||
		strings.Contains(lower, "<body") ||
		strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "onload=") ||
		strings.Contains(lower, "ontoggle=") ||
		strings.Contains(lower, "onpageshow=") ||
		strings.Contains(lower, "onfocus=") ||
		strings.Contains(lower, "onmouseover=") ||
		strings.Contains(lower, "javascript:")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
