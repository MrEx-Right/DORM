package plugins

import (
	"DORM/models"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
	"golang.org/x/crypto/ssh"
)

// ==================================================
// BRUTE FORCE — v2.0 "Hydra Elite"
// SSH, FTP, Telnet, HTTP Basic Auth
// 100+ default credential, concurrent goroutine
// ==================================================
type BruteForcePlugin struct{}

func (p *BruteForcePlugin) Name() string { return "Mini-Hydra (SSH/FTP/Telnet/HTTP Brute Force)" }

// defaultCreds — List of 100+ most common default credentials
var defaultCreds = []struct{ User, Pass string }{
	// ── Generic / Universal ──────────────────────────────────────────────
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "1234"},
	{"admin", "12345"},
	{"admin", "123456"},
	{"admin", "admin123"},
	{"admin", "Admin123"},
	{"admin", "Admin@123"},
	{"admin", "Pass@123"},
	{"admin", ""},
	{"admin", "administrator"},
	{"administrator", "administrator"},
	{"administrator", "password"},
	{"administrator", "admin"},
	{"administrator", "1234"},
	{"root", "root"},
	{"root", "toor"},
	{"root", "password"},
	{"root", "123456"},
	{"root", "pass"},
	{"root", ""},
	{"user", "user"},
	{"user", "password"},
	{"user", "1234"},
	{"user", "12345"},
	{"test", "test"},
	{"test", "password"},
	{"demo", "demo"},
	{"guest", "guest"},
	{"guest", "password"},
	{"guest", ""},
	// ── Router / Network / IoT ───────────────────────────────────────────
	{"ubnt", "ubnt"},
	{"netgear", "netgear"},
	{"dlink", "dlink"},
	{"admin", "1111"},
	{"admin", "0000"},
	{"admin", "9999"},
	{"admin", "default"},
	{"admin", "setup"},
	{"cusadmin", "highspeed"},
	{"support", "support"},
	{"support", "1234"},
	{"service", "service"},
	{"tech", "tech"},
	{"default", "default"},
	// ── Linux / Unix / Cloud VMs ─────────────────────────────────────────
	{"ubuntu", "ubuntu"},
	{"pi", "raspberry"},
	{"debian", "debian"},
	{"centos", "centos"},
	{"kali", "kali"},
	{"ec2-user", "ec2-user"},
	{"oracle", "oracle"},
	{"fedora", "fedora"},
	{"arch", "arch"},
	// ── Cloud / DevOps ───────────────────────────────────────────────────
	{"vagrant", "vagrant"},
	{"deploy", "deploy"},
	{"git", "git"},
	{"gitlab", "gitlab"},
	{"ansible", "ansible"},
	{"docker", "docker"},
	{"jenkins", "jenkins"},
	{"chef", "chef"},
	{"puppet", "puppet"},
	{"terraform", "terraform"},
	{"kubernetes", "kubernetes"},
	{"k8s", "k8s"},
	// ── Database defaults ────────────────────────────────────────────────
	{"sa", "sa"},
	{"sa", ""},
	{"postgres", "postgres"},
	{"mysql", "mysql"},
	{"redis", "redis"},
	{"mongo", "mongo"},
	{"elastic", "elastic"},
	{"couchdb", "couchdb"},
	{"cassandra", "cassandra"},
	{"neo4j", "neo4j"},
	{"influxdb", "influxdb"},
	// ── VPN / Network appliances ─────────────────────────────────────────
	{"cisco", "cisco"},
	{"cisco", ""},
	{"enable", "enable"},
	{"vpn", "vpn"},
	{"pix", "pix"},
	{"fortinet", "fortinet"},
	{"juniper", "juniper"},
	{"mikrotik", "mikrotik"},
	{"mikrotik", ""},
	{"admin", "fortinet"},
	// ── Application panels ───────────────────────────────────────────────
	{"webmaster", "webmaster"},
	{"manager", "manager"},
	{"ftp", "ftp"},
	{"backup", "backup"},
	{"login", "login"},
	// ── Generic brute ────────────────────────────────────────────────────
	{"master", "master"},
	{"changeme", "changeme"},
	{"letmein", "letmein"},
	{"welcome", "welcome"},
	{"pass", "pass"},
	{"1234", "1234"},
	{"admin", "qwerty"},
	{"admin", "letmein"},
	{"admin", "welcome"},
	{"admin", "changeme"},
	{"admin", "master"},
}

// httpBasicEndpoints — Endpoints to try for web panel brute forcing
var httpBasicEndpoints = []string{
	"/", "/admin", "/admin/", "/administrator",
	"/wp-admin", "/wp-login.php",
	"/manager", "/manager/html",
	"/phpmyadmin", "/phpMyAdmin",
	"/panel", "/cpanel", "/whm",
	"/login", "/signin",
	"/secure", "/private",
	"/api", "/api/v1",
	"/console", "/dashboard",
}

func (p *BruteForcePlugin) Run(target models.ScanTarget) *models.Vulnerability {
	switch target.Port {
	case 22:
		return bruteSSH(target)
	case 21:
		return bruteFTP(target)
	case 23:
		return bruteTelnet(target)
	case 80, 443, 8080, 8443:
		return bruteHTTPBasic(target)
	}
	return nil
}

// ── SSH Brute Force ───────────────────────────────────────────────────────────

func bruteSSH(target models.ScanTarget) *models.Vulnerability {
	type result struct {
		cred string
	}
	found := make(chan result, 1)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // max 5 concurrent

	for _, c := range defaultCreds {
		wg.Add(1)
		go func(user, pass string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Stop sinyali
			select {
			case <-found:
				found <- result{}
				return
			default:
			}

			cfg := &ssh.ClientConfig{
				User: user,
				Auth: []ssh.AuthMethod{ssh.Password(pass)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         2 * time.Second,
			}
			client, err := ssh.Dial("tcp", net.JoinHostPort(target.IP, fmt.Sprintf("%d", target.Port)), cfg)
			if err == nil {
				client.Close()
				select {
				case found <- result{fmt.Sprintf("User: '%s'  Pass: '%s'", user, pass)}:
				default:
				}
			}
		}(c.User, c.Pass)
	}

	go func() { wg.Wait(); close(found) }()

	for r := range found {
		if r.cred != "" {
			return &models.Vulnerability{
				Target:      target,
				Name:        "Brute Force: SSH Default Credentials",
				Severity:    "CRITICAL",
				CVSS:        10.0,
				Description: fmt.Sprintf("SSH service accepted login with default credentials.\n%s\nPort: %d", r.cred, target.Port),
				Solution:    "Change all default passwords immediately. Use SSH key-based authentication and disable password login (PasswordAuthentication no).",
				Reference:   "CWE-521: Weak Password Requirements",
			}
		}
	}
	return nil
}

// ── FTP Brute Force ───────────────────────────────────────────────────────────

func bruteFTP(target models.ScanTarget) *models.Vulnerability {
	for _, c := range defaultCreds {
		conn, err := ftp.Dial(
			net.JoinHostPort(target.IP, fmt.Sprintf("%d", target.Port)),
			ftp.DialWithTimeout(2*time.Second),
		)
		if err != nil {
			continue
		}
		err = conn.Login(c.User, c.Pass)
		if err == nil {
			conn.Logout()
			conn.Quit()
			return &models.Vulnerability{
				Target:      target,
				Name:        "Brute Force: FTP Default Credentials",
				Severity:    "CRITICAL",
				CVSS:        10.0,
				Description: fmt.Sprintf("FTP service accepted login with default credentials.\nUser: '%s'  Pass: '%s'\nPort: %d", c.User, c.Pass, target.Port),
				Solution:    "Change default FTP credentials. If possible, use SFTP instead of FTP.",
				Reference:   "CWE-521: Weak Password Requirements",
			}
		}
		conn.Quit()
	}
	return nil
}

// ── Telnet Banner + Brute Force ───────────────────────────────────────────────

func bruteTelnet(target models.ScanTarget) *models.Vulnerability {
	addr := net.JoinHostPort(target.IP, fmt.Sprintf("%d", target.Port))

	// Read the banner first — is the service Telnet?
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	banner := make([]byte, 256)
	n, _ := conn.Read(banner)
	conn.Close()

	bannerStr := string(banner[:n])
	// Telnet validation: Must contain IAC (0xFF) or "login:" / "Password:"
	isTelnet := len(bannerStr) > 0 && (bannerStr[0] == 0xFF ||
		containsAny(bannerStr, "login:", "Login:", "Password:", "ogin", "assword", "Telnet", "telnet"))

	if !isTelnet {
		return nil
	}

	// Credential attempt (simple — full Telnet protocol automation is complex,
	// at this stage open port + banner = HIGH finding)
	return &models.Vulnerability{
		Target:      target,
		Name:        "Brute Force: Telnet Service Exposed",
		Severity:    "CRITICAL",
		CVSS:        9.0,
		Description: fmt.Sprintf("Active Telnet service detected on port %d.\nBanner: %q\nTelnet transmits credentials in cleartext. Vulnerable to brute force and MitM attacks.", target.Port, bannerStr),
		Solution:    "Disable the Telnet service and replace it with SSH. If mandatory, implement strong passwords and IP restriction.",
		Reference:   "CWE-319: Cleartext Transmission of Sensitive Information",
	}
}

// ── HTTP Basic Auth Brute Force ───────────────────────────────────────────────

func bruteHTTPBasic(target models.ScanTarget) *models.Vulnerability {
	client := models.GetClient()
	baseURL := getURL(target, "")

	// First find endpoints returning 401
	var protectedEndpoints []string
	for _, ep := range httpBasicEndpoints {
		resp, err := client.Get(baseURL + ep)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 401 {
			protectedEndpoints = append(protectedEndpoints, ep)
		}
	}

	if len(protectedEndpoints) == 0 {
		return nil
	}

	// Try credentials on 401 endpoints
	for _, ep := range protectedEndpoints {
		targetURL := baseURL + ep
		for _, c := range defaultCreds {
			token := base64.StdEncoding.EncodeToString([]byte(c.User + ":" + c.Pass))
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Basic "+token)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			// 200 + "admin" content or not a redirect
			if resp.StatusCode == 200 && !containsAny(string(body), "Invalid", "Unauthorized", "denied", "Wrong") {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Brute Force: HTTP Basic Auth Bypass",
					Severity:    "CRITICAL",
					CVSS:        9.8,
					Description: fmt.Sprintf("HTTP Basic Auth was cracked with default credentials.\nEndpoint: %s\nUser: '%s'  Pass: '%s'", targetURL, c.User, c.Pass),
					Solution:    "Change default passwords. Consider using token-based auth instead of HTTP Basic Auth.",
					Reference:   "CWE-521: Weak Password Requirements",
				}
			}
		}
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
