package plugins

import (
	"DORM/models"
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 3000 || port == 5000 || port == 9090
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
	defer f.Close()

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
			fmt.Sscanf(parts1[i], "%d", &n1)
		}
		if i < len(parts2) {
			fmt.Sscanf(parts2[i], "%d", &n2)
		}

		if n1 < n2 {
			return true
		} else if n1 > n2 {
			return false
		}
	}
	return false
}

// ---------------------------------------------------------
// HELPER: HMAC-SHA256 SIGNER
// We implement this manually to avoid external dependencies like jwt-go
// ---------------------------------------------------------
func signHS256(header, payload string, secret []byte) string {
	unsignedToken := header + "." + payload
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(unsignedToken))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return unsignedToken + "." + signature
}

// ---------------------------------------------------------
// HELPER: JWT VALIDATOR & PARSER
// ---------------------------------------------------------
func parseAndValidateJWT(raw string) (header string, payload string, signature string, valid bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {

		headerBytes, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return "", "", "", false
		}
	}

	if !strings.Contains(string(headerBytes), `"alg"`) {
		return "", "", "", false
	}

	return parts[0], parts[1], parts[2], true
}

func findJWT(content string, headers http.Header) string {

	re := regexp.MustCompile(`ey[A-Za-z0-9-_]+\.ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*`)

	candidates := []string{}

	auth := headers.Get("Authorization")
	if len(auth) > 7 && strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		candidates = append(candidates, strings.TrimSpace(auth[7:]))
	}

	cookieHeader := headers.Get("Set-Cookie")
	matches := re.FindAllString(cookieHeader, -1)
	candidates = append(candidates, matches...)

	bodyMatches := re.FindAllString(content, -1)
	candidates = append(candidates, bodyMatches...)

	for _, c := range candidates {
		_, _, _, valid := parseAndValidateJWT(c)
		if valid {
			return c
		}
	}

	return ""
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
			"S3 Bucket Detection", "Kubernetes Kubelet API", "Docker Registry Exposure", "Redis Unauthorized Access",
			"MongoDB Unauthorized Access", "Elasticsearch Disclosure", "Memcached Stats", "Anonymous FTP", "SMTP Open Relay",
			"SSRF Cloud Metadata",
		},
		"Authentication & Sessions": {
			"WordPress User Disclosure", "Open Redirect", "Cookie Security", "Tomcat Manager Panel", "Admin Panel Bypass (IP Spoof)",
			"IDOR / Unauthorized Access Test", "Jenkins Script Console", "Subdomain Takeover Risk", "ASP.NET ViewState Encryption",
			"GitLab User Enum", "JWT None Algorithm", "Shadow API Discovery", "Admin Panel Finder",
			"403/401 Authorization Bypass", "BFLA/BOLA — Broken Function & Object Level Authorization",
		},
		"Advanced Logic": {
			"SSTI Test", "Dangerous HTTP Methods", "HTTP Request Smuggling", "Race Condition Tester", "Web Cache Poisoning",
			"Arbitrary File Upload (RCE)", "AI/LLM Prompt Injection Scanner", "IP Spoof — Rate-Limit & WAF Bypass",
		},
		"Vulnerability Checks": {
			"API Key in JS Files", "Weak TLS Cipher Suites Scanner", "WordPress Enumeration & CVE Scanner",
		},
	}
}

// readBody reads the response body up to maxBytes and closes it.
func readBody(resp *http.Response, maxBytes int64) string {
	if resp == nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return string(b)
}

// getSharedString reads a string value from models.SharedData
func getSharedString(key string) string {
	v, ok := models.SharedData.Load(key)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func IsWebPort(port int) bool                             { return isWebPort(port) }
func GetURL(target models.ScanTarget, path string) string { return getURL(target, path) }
