package plugins

import (
	"DORM/models"
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Any = interface{}

// ==========================================
// HELPER FUNCTIONS
// ==========================================
func isWebPort(port int) bool {
	return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 3000 || port == 5000 || port == 9090 ||
		port == 8000 || port == 8001 || port == 8081 || port == 8888 || port == 9000
}

func getURL(target models.ScanTarget, path string) string {
	proto := "http"
	if target.Port == 443 || target.Port == 8443 {
		proto = "https"
	}
	if !strings.HasPrefix(path, "/") && path != "" {
		path = "/" + path
	}
	return fmt.Sprintf("%s://%s:%d%s", proto, target.IP, target.Port, path)
}

// loadWordlistFile reads lines from wordlists/<filename>, filtering empty lines & comment lines starting with #
func loadWordlistFile(filename string) []string {
	filePath := filepath.Join("wordlists", filename)
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isVersionVulnerable compares the target version against the CISA models.Vulnerability description using NLP constraints.
func isVersionVulnerable(targetVersion, description string) bool {
	if targetVersion == "" {
		return false
	}

	descLower := strings.ToLower(description)

	if strings.Contains(descLower, targetVersion) {
		return true
	}

	re := regexp.MustCompile(`(?:prior to|before|through|up to|<|<=)\s*v?([0-9]+(?:\.[0-9]+)*)`)
	matches := re.FindAllStringSubmatch(descLower, -1)

	for _, m := range matches {
		if len(m) > 1 {
			limitVersion := m[1]

			if strings.Contains(m[0], "through") || strings.Contains(m[0], "up to") || strings.Contains(m[0], "<=") {

				if targetVersion == limitVersion || isVersionLessThan(targetVersion, limitVersion) {
					return true
				}
			} else {

				if isVersionLessThan(targetVersion, limitVersion) {
					return true
				}
			}
		}
	}

	return false
}

// isVersionLessThan performs a mathematical comparison between two semantic versions.
// Accurately evaluates constraints like "1.10.2 < 1.11.0" without lexicographical errors.
func isVersionLessThan(v1, v2 string) bool {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			_, _ = fmt.Sscanf(parts1[i], "%d", &n1)
		}
		if i < len(parts2) {
			_, _ = fmt.Sscanf(parts2[i], "%d", &n2)
		}

		if n1 < n2 {
			return true
		} else if n1 > n2 {
			return false
		}
	}
	return false
}

// ==========================================
// INVENTORY LIST FOR UI
// ==========================================
func GetPluginInventory() map[string][]string {
	return map[string][]string{
		"Recon & Info Gathering": {
			"Open Port Detection", "Service Banner Info", "Basic File Scan", "PHP Info Check", "WAF Detection",
			"CMS Detection", "Security.txt File", "Email Disclosure", "System Metrics Exposure", "Open Directory Listing",
			"Unnecessary Port Warning",
		},
		"Injection Vulnerabilities": {
			"SQL Injection Scanner", "XSS (Cross-Site Scripting)", "LFI (Local File Inclusion)", "Blind Command Injection (Time)",
			"XXE Injection", "CRLF Injection", "Java Deserialization Risk", "Node.js Prototype Pollution", "Directory Traversal",
			"Apache Struts RCE", "NoSQL Injection (MongoDB)",
		},
		"Misconfiguration & Exposure": {
			"Security Headers Analysis", "SSL Certificate Check", "CORS Misconfiguration", "Spring Boot Actuator",
			"Git Configuration", "Backup File", "Apache Server Status", "DS_Store Disclosure", "HTTP TRACE Method",
			"ENV File Disclosure", "Laravel Debug Mode", "Docker API Exposure", "WebDAV Methods", "Clickjacking Check",
			"GraphQL Schema Disclosure", "Swagger UI Detection", "Host Header Injection", "HSTS (HTTPS Enforcement)",
			"Editor/Config File Disclosure", "Config.json Disclosure", "Laravel .env Disclosure", "ColdFusion Debugging",
			"Nginx Alias Traversal", "Terraform State Exposure",
		},
		"Cloud & Infrastructure": {
			"S3 Bucket Detection", "Multi-Cloud Storage Exposure (Bucket/Blob Takeover)", "Kubernetes Kubelet API",
			"Docker Registry Exposure", "Redis Unauthorized Access",
			"MongoDB Unauthorized Access", "Elasticsearch Disclosure", "Memcached Stats", "Anonymous FTP", "SMTP Open Relay",
			"SSRF Cloud Metadata",
		},
		"AI & LLM Infrastructure": {
			"AI/Vector Database Unauthorized Access", "AI/LLM Prompt Injection Scanner",
		},
		"Authentication & Sessions": {
			"WordPress User Disclosure", "Open Redirect", "Cookie Security", "Tomcat Manager Panel", "Admin Panel Bypass (IP Spoof)",
			"IDOR / Unauthorized Access Test", "Jenkins Script Console", "Subdomain Takeover Risk", "ASP.NET ViewState Encryption",
			"GitLab User Enum", "JWT None Algorithm", "Shadow API Discovery", "Admin Panel Finder",
			"403/401 Authorization Bypass", "BFLA/BOLA — Broken Function & Object Level Authorization",
		},
		"Advanced Logic": {
			"SSTI Test", "Dangerous HTTP Methods", "HTTP Request Smuggling", "Race Condition Tester", "Web Cache Poisoning",
			"Web Cache Deception", "Arbitrary File Upload (RCE)", "IP Spoof — Rate-Limit & WAF Bypass",
		},
		"Vulnerability Checks": {
			"API Key in JS Files", "Webpack Source Map & Secret Harvester", "Weak TLS Cipher Suites Scanner",
			"WordPress Enumeration & CVE Scanner",
		},
	}
}

// readBody reads the response body up to maxBytes and closes it.
func readBody(resp *http.Response, maxBytes int64) string {
	if resp == nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return string(b)
}

func IsWebPort(port int) bool                             { return isWebPort(port) }
func GetURL(target models.ScanTarget, path string) string { return getURL(target, path) }
