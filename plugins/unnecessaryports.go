package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type UnnecessaryPortsPlugin struct{}

func (p *UnnecessaryPortsPlugin) Name() string { return "Unnecessary Port Warning" }

func (p *UnnecessaryPortsPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	port := target.Port

	// 1. Check for legacy/dangerous ports (HIGH severity)
	switch port {
	case 21:
		return &models.Vulnerability{
			Target:      target,
			Name:        "Unnecessary Port Exposed: FTP (21)",
			Severity:    "HIGH",
			CVSS:        7.5,
			Description: "File Transfer Protocol (FTP) is exposed on port 21. FTP transmits credentials and data in cleartext, making it highly vulnerable to sniffing and interception.",
			Solution:    "Disable the FTP service and use SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS/SSL) instead. Restrict port access using firewalls.",
			Reference:   "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
		}
	case 23:
		return &models.Vulnerability{
			Target:      target,
			Name:        "Unnecessary Port Exposed: Telnet (23)",
			Severity:    "HIGH",
			CVSS:        8.5,
			Description: "Telnet protocol is exposed on port 23. Telnet is obsolete and completely unencrypted, transmitting all data including administrative credentials in plaintext.",
			Solution:    "Disable Telnet immediately and use SSH (Secure Shell) on a secure port for remote administration.",
			Reference:   "https://www.sans.org/blog/why-telnet-must-die/",
		}
	case 445:
		return &models.Vulnerability{
			Target:      target,
			Name:        "Unnecessary Port Exposed: SMB (445)",
			Severity:    "HIGH",
			CVSS:        7.5,
			Description: "Server Message Block (SMB) is exposed on port 445. SMB is a high-risk file-sharing protocol frequently targeted by critical exploits (e.g., EternalBlue, WannaCry) and should never be exposed to external networks.",
			Solution:    "Block port 445 at the network perimeter firewall and only allow access over a secure local network or VPN.",
			Reference:   "https://support.microsoft.com/en-us/help/3185535/preventing-smb-traffic-from-lateral-connections-and-entering-or-leav",
		}
	case 3389:
		return &models.Vulnerability{
			Target:      target,
			Name:        "Unnecessary Port Exposed: RDP (3389)",
			Severity:    "MEDIUM",
			CVSS:        6.0,
			Description: "Remote Desktop Protocol (RDP) is exposed on port 3389. Exposing remote access services invites active brute-force login attempts and exploitation of known remote code execution vulnerabilities.",
			Solution:    "Disable RDP exposure to the public web. Restrict access behind a VPN or configure remote access gateways with Multi-Factor Authentication (MFA).",
			Reference:   "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-014a",
		}
	case 5900, 5901:
		return &models.Vulnerability{
			Target:      target,
			Name:        "Unnecessary Port Exposed: VNC (5900/5901)",
			Severity:    "MEDIUM",
			CVSS:        6.0,
			Description: fmt.Sprintf("Virtual Network Computing (VNC) is exposed on port %d. VNC is an unencrypted or weakly encrypted desktop sharing system prone to brute-forcing and session interception.", port),
			Solution:    "Close the exposed VNC port. Tunnel VNC connections securely over SSH or restrict VNC access behind a corporate VPN.",
			Reference:   "https://www.elastic.co/blog/detecting-vnc-exposure-with-elastic-security",
		}
	}

	// 2. Check for database engines (MEDIUM severity)
	dbEngines := map[int]string{
		1433:  "Microsoft SQL Server (MSSQL)",
		1521:  "Oracle Database",
		3306:  "MySQL Database",
		5432:  "PostgreSQL Database",
		6379:  "Redis In-Memory Store",
		9200:  "Elasticsearch",
		11211: "Memcached",
		27017: "MongoDB NoSQL Database",
	}
	if dbName, ok := dbEngines[port]; ok {
		return &models.Vulnerability{
			Target:      target,
			Name:        fmt.Sprintf("Exposed Database Port: %s (%d)", dbName, port),
			Severity:    "MEDIUM",
			CVSS:        5.0,
			Description: fmt.Sprintf("%s is exposed directly on port %d. Database services are critical backend assets and should never be accessible from the public Internet.", dbName, port),
			Solution:    "Configure the database service to bind only to localhost (127.0.0.1) or internal network interfaces. Restrict incoming network traffic via firewalls.",
			Reference:   "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
		}
	}

	// 3. Check for DevOps/Infrastructure APIs (MEDIUM severity)
	devopsApis := map[int]string{
		2375:  "Docker API (Plaintext)",
		2376:  "Docker API (TLS)",
		5672:  "RabbitMQ AMQP Protocol",
		6443:  "Kubernetes API Server",
		8500:  "HashiCorp Consul API",
		15672: "RabbitMQ Management Console",
	}
	if apiName, ok := devopsApis[port]; ok {
		return &models.Vulnerability{
			Target:      target,
			Name:        fmt.Sprintf("Exposed DevOps/Infrastructure API: %s (%d)", apiName, port),
			Severity:    "MEDIUM",
			CVSS:        6.5,
			Description: fmt.Sprintf("DevOps/Infrastructure service %s is exposed on port %d. Exposing control planes or message brokers allows potential attackers to manipulate container deployments, steal cloud metadata, or inject malware.", apiName, port),
			Solution:    "Configure strict firewall rules to block public access. Ensure proper authentication/authorization is enabled and enforce access via secure networks/bastion hosts.",
			Reference:   "https://kubernetes.io/docs/concepts/security/controlling-access/",
		}
	}

	// 4. Check alternative/development HTTP ports (LOW/MEDIUM severity via Active Check)
	altWebPorts := map[int]bool{
		80:   true,
		443:  true,
		3000: true,
		5000: true,
		8000: true,
		8001: true,
		8080: true,
		8081: true,
		8888: true,
		9000: true,
		9090: true,
	}

	if altWebPorts[port] {
		// Use HTTP client to probe and analyze if it represents an unnecessary dev/debug interface
		client := models.GetClient()
		if client == nil {
			// Fallback standard HTTP client if global client pointer not initialized
			client = &http.Client{
				Timeout: 3 * time.Second,
			}
		}

		scheme := "http"
		if port == 443 || port == 8443 || port == 8081 {
			scheme = "https"
		}

		targetURL := fmt.Sprintf("%s://%s:%d/", scheme, target.IP, port)
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return nil
		}
		// Set headers to prevent caching and simulate a normal browser
		req.Header.Set("User-Agent", "DORM-Scan-Agent/1.11.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			// If https failed on alternative ports, try HTTP as fallback
			if scheme == "https" {
				targetURL = fmt.Sprintf("http://%s:%d/", target.IP, port)
				req, _ = http.NewRequest("GET", targetURL, nil)
				req.Header.Set("User-Agent", "DORM-Scan-Agent/1.11.0")
				resp, err = client.Do(req)
				if err != nil {
					return nil
				}
			} else {
				return nil
			}
		}
		defer resp.Body.Close()

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 10240)) // limit read to 10KB
		bodyLower := strings.ToLower(string(bodyBytes))

		// Check response headers for development servers
		serverHeader := strings.ToLower(resp.Header.Get("Server"))
		xPoweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

		isDev := false
		devReason := ""

		// Inspect signatures of development servers
		devSignatures := map[string]string{
			"webpack-dev-server":         "Webpack Dev Server",
			"vite":                       "Vite Bundler",
			"werkzeug":                   "Python Werkzeug (Flask/Django Dev)",
			"django-debug-toolbar":       "Django Debug Toolbar",
			"laravel debugbar":           "Laravel Debugbar",
			"phpinfo":                    "PHP Info Screen",
			"hwt-module-replacement":     "Hot Module Replacement (HMR)",
			"browsersync":                "Browsersync tool",
			"express-status-monitor":     "Express Status Monitor",
			"fastapi documentation":      "FastAPI Docs / Swagger UI",
			"swagger ui":                 "Swagger UI / OpenAPI documentation",
			"redoc":                      "ReDoc API Docs",
			"django debug":               "Django Debug Mode Screen",
			"flask debug":                "Flask Debug Screen",
			"vue-devtools":               "Vue DevTools",
			"react-devtools":             "React DevTools",
			"x-source-map":               "Source Maps Enabled",
			"development server":         "Generic Development Server",
		}

		for sig, label := range devSignatures {
			if strings.Contains(bodyLower, sig) {
				isDev = true
				devReason = label
				break
			}
		}

		if !isDev {
			if strings.Contains(serverHeader, "werkzeug") || strings.Contains(serverHeader, "development") {
				isDev = true
				devReason = "Server Header: " + serverHeader
			} else if strings.Contains(xPoweredBy, "express") && (port == 3000 || port == 5000) {
				isDev = true
				devReason = "Express.js signature on a typical dev port"
			}
		}

		if isDev {
			return &models.Vulnerability{
				Target:      target,
				Name:        fmt.Sprintf("Exposed Development/Debug Service on Port %d", port),
				Severity:    "MEDIUM",
				CVSS:        6.0,
				Description: fmt.Sprintf("A development or debug-enabled web service was detected on port %d (Detected: %s). Development servers often have debugging utilities active, leak source code files, lack proper rate-limiting, and might contain interactive consoles permitting remote command execution.", port, devReason),
				Solution:    "Disable development debug features in production environments. Do not expose bundlers or live-reloading tooling to the public web. Ensure compilation output does not contain source maps or debug pages.",
				Reference:   "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
			}
		}

		// If it's a non-standard web port (> 1024 and not 80/443/8080/8443) and serves generic web content, warn about alternative HTTP service exposure
		if port != 80 && port != 443 && port != 8080 && port != 8443 {
			return &models.Vulnerability{
				Target:      target,
				Name:        fmt.Sprintf("Alternative HTTP Service Exposed: Port %d", port),
				Severity:    "LOW",
				CVSS:        3.5,
				Description: fmt.Sprintf("An alternative HTTP/HTTPS service is running and exposed on port %d. While not necessarily a vulnerability, alternative web ports often host administrative dashboards, developer consoles, or unmonitored legacy applications.", port),
				Solution:    "Verify the necessity of exposing this web service. If it is an admin panel or dev portal, restrict access using host-based firewalls, IP allowlists, or require authentication via a corporate VPN/reverse proxy.",
				Reference:   "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
			}
		}
	}

	return nil
}
