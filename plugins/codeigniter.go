package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

type CodeIgniterPlugin struct{}

func (p *CodeIgniterPlugin) Name() string { return "CodeIgniter Security Misconfiguration Scanner" }

func (p *CodeIgniterPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Fingerprint ──────────────────────────────────────────────────────────
	// ci_session cookie, CodeIgniter keyword in body, /index.php/ URL pattern
	isCI := false

	probeResp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	probeBody, _ := io.ReadAll(probeResp.Body)
	probeResp.Body.Close()

	setCookie := probeResp.Header.Get("Set-Cookie")
	bodyLow := strings.ToLower(string(probeBody))

	if strings.Contains(setCookie, "ci_session") || strings.Contains(bodyLow, "codeigniter") {
		isCI = true
	}

	if !isCI {
		// Try /index.php/ pattern
		idxResp, err := client.Get(baseURL + "/index.php/welcome")
		if err == nil {
			idxBody, _ := io.ReadAll(idxResp.Body)
			idxResp.Body.Close()
			bodyLow2 := strings.ToLower(string(idxBody))
			if idxResp.StatusCode == 200 && strings.Contains(bodyLow2, "codeigniter") {
				isCI = true
			}
		}
	}

	if !isCI {
		return nil
	}

	type finding struct {
		name     string
		severity string
		cvss     float64
		desc     string
	}
	var findings []finding

	// ── Probe 1: PHP Error Display ────────────────────────────────────────────
	errResp, err := client.Get(baseURL + "/dorm-ci-probe-notfound-xyz")
	if err == nil {
		errBody, _ := io.ReadAll(errResp.Body)
		errResp.Body.Close()
		bodyStr := string(errBody)
		if strings.Contains(bodyStr, "A PHP Error was encountered") ||
			strings.Contains(bodyStr, "CI Error") ||
			strings.Contains(bodyStr, "Severity: Notice") ||
			strings.Contains(bodyStr, "Severity: Warning") {
			findings = append(findings, finding{
				name:     "CodeIgniter PHP Error Display Enabled",
				severity: "HIGH",
				cvss:     7.2,
				desc:     "CodeIgniter is displaying raw PHP error messages to users. Internal file paths, class names, and line numbers are visible in error responses.",
			})
		}
	}

	// ── Probe 2: database.php config file ────────────────────────────────────
	dbConfigPaths := []string{
		"/application/config/database.php",
		"/app/Config/Database.php",
		"/system/database/database.php",
	}
	for _, dp := range dbConfigPaths {
		dbResp, err := client.Get(baseURL + dp)
		if err == nil {
			dbBody, _ := io.ReadAll(dbResp.Body)
			dbResp.Body.Close()
			bodyStr := string(dbBody)
			if dbResp.StatusCode == 200 && (strings.Contains(bodyStr, "$db") || strings.Contains(bodyStr, "hostname") || strings.Contains(bodyStr, "password") || strings.Contains(bodyStr, "database")) {
				findings = append(findings, finding{
					name:     fmt.Sprintf("CodeIgniter Database Configuration File Exposed (%s)", dp),
					severity: "CRITICAL",
					cvss:     9.8,
					desc:     fmt.Sprintf("The database configuration file (%s) is publicly accessible. It contains database hostnames, usernames, passwords, and database names.", dp),
				})
				break
			}
		}
	}

	// ── Probe 3: config.php ───────────────────────────────────────────────────
	cfgPaths := []string{"/application/config/config.php", "/app/Config/App.php"}
	for _, cp := range cfgPaths {
		cfgResp, err := client.Get(baseURL + cp)
		if err == nil {
			cfgBody, _ := io.ReadAll(cfgResp.Body)
			cfgResp.Body.Close()
			bodyStr := string(cfgBody)
			if cfgResp.StatusCode == 200 && (strings.Contains(bodyStr, "$config") || strings.Contains(bodyStr, "encryption_key") || strings.Contains(bodyStr, "base_url")) {
				findings = append(findings, finding{
					name:     fmt.Sprintf("CodeIgniter Application Config File Exposed (%s)", cp),
					severity: "CRITICAL",
					cvss:     9.1,
					desc:     fmt.Sprintf("The application configuration file (%s) is publicly accessible. It may contain the encryption key, base URL, session driver config, and other security-sensitive settings.", cp),
				})
				break
			}
		}
	}

	// ── Probe 4: Application/System Directory Listing ─────────────────────────
	dirPaths := []string{"/application/", "/system/", "/app/"}
	for _, dp := range dirPaths {
		dirResp, err := client.Get(baseURL + dp)
		if err == nil {
			dirBody, _ := io.ReadAll(dirResp.Body)
			dirResp.Body.Close()
			bodyLow3 := strings.ToLower(string(dirBody))
			if dirResp.StatusCode == 200 && strings.Contains(bodyLow3, "index of") {
				findings = append(findings, finding{
					name:     fmt.Sprintf("CodeIgniter Directory Listing Enabled (%s)", dp),
					severity: "HIGH",
					cvss:     7.5,
					desc:     fmt.Sprintf("Directory listing is enabled for %s. Attackers can browse the application directory structure and download source files.", dp),
				})
				break
			}
		}
	}

	// ── Probe 5: phpinfo.php / info.php ──────────────────────────────────────
	phpinfoPaths := []string{"/phpinfo.php", "/info.php", "/php_info.php", "/index.php/debug/info"}
	for _, pp := range phpinfoPaths {
		ppResp, err := client.Get(baseURL + pp)
		if err == nil {
			ppBody, _ := io.ReadAll(ppResp.Body)
			ppResp.Body.Close()
			bodyStr := string(ppBody)
			if ppResp.StatusCode == 200 && (strings.Contains(bodyStr, "phpinfo()") || strings.Contains(bodyStr, "PHP Version") && strings.Contains(bodyStr, "php.ini")) {
				findings = append(findings, finding{
					name:     fmt.Sprintf("phpinfo() Page Accessible (%s)", pp),
					severity: "HIGH",
					cvss:     7.2,
					desc:     fmt.Sprintf("A phpinfo() page (%s) is publicly accessible. It exposes PHP version, loaded modules, server paths, environment variables, and php.ini configuration.", pp),
				})
				break
			}
		}
	}

	// ── Probe 6: ci_session Cookie Security Flags ─────────────────────────────
	cookieHeader := probeResp.Header.Get("Set-Cookie")
	if strings.Contains(cookieHeader, "ci_session") {
		missingFlags := []string{}
		if !strings.Contains(strings.ToLower(cookieHeader), "httponly") {
			missingFlags = append(missingFlags, "HttpOnly")
		}
		if !strings.Contains(strings.ToLower(cookieHeader), "secure") {
			missingFlags = append(missingFlags, "Secure")
		}
		if !strings.Contains(strings.ToLower(cookieHeader), "samesite") {
			missingFlags = append(missingFlags, "SameSite")
		}
		if len(missingFlags) > 0 {
			findings = append(findings, finding{
				name:     "CodeIgniter Session Cookie Missing Security Flags",
				severity: "MEDIUM",
				cvss:     5.3,
				desc:     fmt.Sprintf("The ci_session cookie is missing security flags: %s. This may expose the session to XSS theft or CSRF attacks.", strings.Join(missingFlags, ", ")),
			})
		}
	}

	// ── Probe 7: Spark CLI / Debug Endpoint ───────────────────────────────────
	sparkPaths := []string{"/spark", "/index.php/spark", "/cli", "/index.php/debug"}
	for _, sp := range sparkPaths {
		sparkResp, err := client.Get(baseURL + sp)
		if err == nil {
			sparkBody, _ := io.ReadAll(sparkResp.Body)
			sparkResp.Body.Close()
			bodyStr := string(sparkBody)
			if sparkResp.StatusCode == 200 && (strings.Contains(bodyStr, "CodeIgniter") || strings.Contains(bodyStr, "Spark") || strings.Contains(bodyStr, "CLI")) {
				findings = append(findings, finding{
					name:     fmt.Sprintf("CodeIgniter CLI/Spark Endpoint Accessible via Web (%s)", sp),
					severity: "HIGH",
					cvss:     7.2,
					desc:     fmt.Sprintf("The CodeIgniter CLI or Spark command endpoint (%s) is accessible via HTTP. Command-line tools exposed through the web server may allow unauthorized actions.", sp),
				})
				break
			}
		}
	}

	if len(findings) == 0 {
		return nil
	}

	best := findings[0]
	for _, f := range findings[1:] {
		if f.cvss > best.cvss {
			best = f
		}
	}

	var allDescs []string
	for _, f := range findings {
		allDescs = append(allDescs, fmt.Sprintf("[%s] %s: %s", f.severity, f.name, f.desc))
	}

	return &models.Vulnerability{
		Target:      target,
		Name:        "CodeIgniter Security Misconfiguration",
		Severity:    best.severity,
		CVSS:        best.cvss,
		Description: strings.Join(allDescs, "\n\n"),
		Solution:    "Set error_reporting(0) in production. Block web access to /application/ and /system/ directories. Remove phpinfo files. Set HttpOnly, Secure, and SameSite flags on the session cookie. Set a strong encryption_key. Restrict CLI access to server-only execution.",
		Reference:   "OWASP Security Misconfiguration / CodeIgniter Security Guidelines",
	}
}
