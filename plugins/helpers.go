package plugins

import (
	"DORM/models"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// getPostResponseLength sends a POST request with credentials and returns body size.
// This is used to detect Auth Bypass (e.g. if size changes drastically).
func getPostResponseLength(client *http.Client, urlStr, user, pass string) (int, error) {
	data := url.Values{}

	data.Set("username", user)
	data.Set("user", user)
	data.Set("email", user)
	data.Set("login", user)
	data.Set("txtUser", user)

	data.Set("password", pass)
	data.Set("pass", pass)
	data.Set("txtPassword", pass)

	req, err := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "DORM-Scanner/Enterprise")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	return len(bodyBytes), nil
}

// ==========================================
// INVENTORY LIST FOR UI
// ==========================================
func GetPluginInventory() []string {
	return []string{
		"Open Port Detection", "Service Banner Info", "Security Headers Analysis", "SSL Certificate Check", "Basic File Scan",
		"CORS Misconfiguration", "WordPress User Disclosure", "PHP Info Check", "WAF Detection", "Open Redirect",
		"SQL Injection Scanner", "XSS (Cross-Site Scripting)", "LFI (Local File Inclusion)", "Spring Boot Actuator",
		"Git Configuration", "Backup File", "Apache Server Status", "DS_Store Disclosure", "HTTP TRACE Method",
		"ENV File Disclosure", "CMS Detection", "Admin Panel Finder", "Shellshock models.Vulnerability", "Laravel Debug Mode",
		"Docker API Exposure", "Cookie Security", "Security.txt File", "WebDAV Methods", "Email Disclosure", "S3 Bucket Detection",
		"Clickjacking Check", "GraphQL Schema Disclosure", "Swagger UI Detection", "Host Header Injection",
		"System Metrics Exposure", "SSTI Test", "HSTS (HTTPS Enforcement)", "Tomcat Manager Panel",
		"Editor/Config File Disclosure", "Open Directory Listing", "Blind Command Injection (Time)",
		"XXE Injection", "Admin Panel Bypass (IP Spoof)", "CRLF Injection", "Dangerous HTTP Methods",
		"Java Deserialization Risk", "Node.js Prototype Pollution", "Directory Traversal", "Config.json Disclosure",
		"IDOR / Unauthorized Access Test", "Log4Shell (CVE-2021-44228)", "Kubernetes Kubelet API", "Docker Registry Exposure", "Spring Cloud Gateway RCE",
		"F5 BIG-IP TMUI RCE", "Jenkins Script Console", "Redis Unauthorized Access", "MongoDB Unauthorized Access", "Elasticsearch Disclosure",
		"Memcached Stats", "Anonymous FTP", "SMTP Open Relay", "API Key in JS Files", "Subdomain Takeover Risk",
		"ASP.NET ViewState Encryption", "Laravel .env Disclosure", "ColdFusion Debugging", "Drupalgeddon2 RCE", "GitLab User Enum", "Nginx Alias Traversal",
		"SSRF Cloud Metadata", "JWT None Algorithm", "Apache Struts RCE", "Citrix ADC Traversal", "NoSQL Injection (MongoDB)", "Atlassian Confluence RCE",
		"Terraform State Exposure", "WebSocket Hijacking", "TeamCity Auth Bypass", "Shadow API Discovery", "Fuzzer", "HTTP Request Smuggling", "Race Condition Tester",
		"Web Cache Poisoning", "Offline CVE Radar (Passive)", "Arbitrary File Upload (RCE)", "WordPress Enumeration & CVE Scanner",
		"Weak TLS Cipher Suites Scanner",
	}
}

func IsWebPort(port int) bool                             { return isWebPort(port) }
func GetURL(target models.ScanTarget, path string) string { return getURL(target, path) }
