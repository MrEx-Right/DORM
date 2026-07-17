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

	// 1. Legacy/cleartext protocol ports — INFO level.
	//    Just because the port is open does NOT mean it is exploitable.
	//    Dedicated plugins (ftpanon.go, smtprelay.go, etc.) perform the real
	//    authentication/exploit checks and emit higher-severity findings when needed.
	switch port {
	case 21:
		return &models.Vulnerability{
			Target:      target,
			Name:        "Open Port: FTP (21)",
			Severity:    "INFO",
			CVSS:        0.0,
			Description: "File Transfer Protocol (FTP) is listening on port 21. FTP transmits credentials and data in cleartext. This is an informational finding; use the Anonymous FTP plugin result for exploitability context.",
			Solution:    "Where possible, replace FTP with SFTP or FTPS. Restrict port access via firewall and disable anonymous login.",
			Reference:   "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
		}
	case 23:
		// Telnet is genuinely dangerous — keep as MEDIUM but lower CVSS to reflect
		// that the port being open alone is not a confirmed vulnerability.
		return &models.Vulnerability{
			Target:      target,
			Name:        "Open Port: Telnet (23)",
			Severity:    "MEDIUM",
			CVSS:        5.3,
			Description: "Telnet is listening on port 23. Telnet is an obsolete, fully unencrypted protocol that transmits all data — including credentials — in plaintext over the network.",
			Solution:    "Disable Telnet and use SSH for remote administration.",
			Reference:   "https://www.sans.org/blog/why-telnet-must-die/",
		}
	case 445:
		// SMB exposure to the public internet is a genuine risk (EternalBlue, WannaCry),
		// but port presence alone is not a confirmed exploit — MEDIUM is appropriate.
		return &models.Vulnerability{
			Target:      target,
			Name:        "Open Port: SMB (445)",
			Severity:    "MEDIUM",
			CVSS:        5.3,
			Description: "Server Message Block (SMB) is listening on port 445. SMB is a high-risk file-sharing protocol historically associated with critical exploits (e.g., EternalBlue, WannaCry). It should never be exposed to external networks.",
			Solution:    "Block port 445 at the network perimeter firewall. Only allow access over a secure internal network or VPN.",
			Reference:   "https://support.microsoft.com/en-us/help/3185535/preventing-smb-traffic-from-lateral-connections-and-entering-or-leav",
		}
	case 3389:
		return &models.Vulnerability{
			Target:      target,
			Name:        "Open Port: RDP (3389)",
			Severity:    "LOW",
			CVSS:        3.5,
			Description: "Remote Desktop Protocol (RDP) is listening on port 3389. Exposing RDP to the public internet invites brute-force login attempts and exploitation of known RDP vulnerabilities.",
			Solution:    "Restrict RDP access behind a VPN or use an RDP gateway with Multi-Factor Authentication (MFA). Do not expose it directly to the internet.",
			Reference:   "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-014a",
		}
	case 5900, 5901:
		return &models.Vulnerability{
			Target:      target,
			Name:        "Open Port: VNC (5900/5901)",
			Severity:    "LOW",
			CVSS:        3.5,
			Description: fmt.Sprintf("Virtual Network Computing (VNC) is listening on port %d. VNC is an unencrypted or weakly encrypted desktop-sharing protocol prone to brute-forcing and session interception.", port),
			Solution:    "Close the exposed VNC port. Tunnel VNC over SSH or restrict access behind a corporate VPN.",
			Reference:   "https://www.elastic.co/blog/detecting-vnc-exposure-with-elastic-security",
		}
	}

	// 2. Database engine ports — INFO only.
	//    A listening database port does not imply unauthenticated access.
	//    Dedicated plugins (mongo.go, redis.go, elastic.go, etc.) perform real checks.
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
			Name:        fmt.Sprintf("Open Port: %s (%d)", dbName, port),
			Severity:    "INFO",
			CVSS:        0.0,
			Description: fmt.Sprintf("%s is listening on port %d. Database services should not be directly reachable from the public internet. This is informational — dedicated scan modules will test for unauthenticated access.", dbName, port),
			Solution:    "Bind the database to localhost or internal network interfaces only. Enforce firewall rules to block public access.",
			Reference:   "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
		}
	}

	// 3. DevOps / Infrastructure API ports — LOW severity.
	//    Exposure is noteworthy but does not confirm misconfiguration on its own.
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
			Name:        fmt.Sprintf("Open Port: %s (%d)", apiName, port),
			Severity:    "LOW",
			CVSS:        3.1,
			Description: fmt.Sprintf("%s is listening on port %d. Exposing infrastructure control-plane services may allow attackers to manipulate deployments, access secrets, or inject malicious workloads if authentication is misconfigured.", apiName, port),
			Solution:    "Enforce strict firewall rules. Enable authentication/TLS and restrict access to trusted networks or bastion hosts only.",
			Reference:   "https://kubernetes.io/docs/concepts/security/controlling-access/",
		}
	}

	// 4. Alternative / development HTTP ports — active probe to confirm risk.
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
		client := models.GetClient()
		if client == nil {
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
		req.Header.Set("User-Agent", "DORM-Scan-Agent/1.11.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
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

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
		bodyLower := strings.ToLower(string(bodyBytes))

		serverHeader := strings.ToLower(resp.Header.Get("Server"))
		xPoweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

		isDev := false
		devReason := ""

		devSignatures := map[string]string{
			"webpack-dev-server":     "Webpack Dev Server",
			"vite":                   "Vite Bundler",
			"werkzeug":               "Python Werkzeug (Flask/Django Dev)",
			"django-debug-toolbar":   "Django Debug Toolbar",
			"laravel debugbar":       "Laravel Debugbar",
			"phpinfo":                "PHP Info Screen",
			"hwt-module-replacement": "Hot Module Replacement (HMR)",
			"browsersync":            "Browsersync tool",
			"express-status-monitor": "Express Status Monitor",
			"fastapi documentation":  "FastAPI Docs / Swagger UI",
			"swagger ui":             "Swagger UI / OpenAPI documentation",
			"redoc":                  "ReDoc API Docs",
			"django debug":           "Django Debug Mode Screen",
			"flask debug":            "Flask Debug Screen",
			"vue-devtools":           "Vue DevTools",
			"react-devtools":         "React DevTools",
			"x-source-map":           "Source Maps Enabled",
			"development server":     "Generic Development Server",
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
				Description: fmt.Sprintf("A development or debug-enabled web service was detected on port %d (Detected: %s). Development servers often have debugging utilities active, leak source code files, lack proper rate-limiting, and might expose interactive consoles permitting remote command execution.", port, devReason),
				Solution:    "Disable development debug features in production environments. Do not expose bundlers or live-reloading tooling to the public web. Ensure compilation output does not contain source maps or debug pages.",
				Reference:   "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
			}
		}

		// Non-standard web port serves generic content — informational notice only.
		if port != 80 && port != 443 && port != 8080 && port != 8443 {
			return &models.Vulnerability{
				Target:      target,
				Name:        fmt.Sprintf("Alternative HTTP Service on Port %d", port),
				Severity:    "INFO",
				CVSS:        0.0,
				Description: fmt.Sprintf("An HTTP/HTTPS service is running on the non-standard port %d. While not a vulnerability on its own, alternative web ports may host administrative dashboards, developer consoles, or unmonitored legacy applications.", port),
				Solution:    "Verify whether this service needs to be publicly accessible. Restrict access with firewall rules, IP allowlists, or require authentication via a reverse proxy/VPN.",
				Reference:   "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
			}
		}
	}

	return nil
}
