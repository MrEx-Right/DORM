package plugins

import (
	"DORM/models"
	"fmt"
	"net"
	"strings"
	"time"
)

// SERVICE FINGERPRINT
type FingerprintPlugin struct{}

func (p *FingerprintPlugin) Name() string { return "Service & Version Detection" }

func (p *FingerprintPlugin) Run(target models.ScanTarget) *models.Vulnerability {

	knownPorts := map[int]string{80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 3306: "MySQL"}
	if _, ok := knownPorts[target.Port]; !ok {
		return nil
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 2*time.Second)
	if err != nil {
		return nil
	}
	conn.Close()

	if target.Port == 80 || target.Port == 443 || target.Port == 8080 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	banner := string(buf[:n])

	detected := ""
	if strings.Contains(banner, "OpenSSH") {
		detected = "OpenSSH (" + strings.Split(banner, "\n")[0] + ")"
	} else if strings.Contains(banner, "Apache/") {

		parts := strings.Split(banner, "Server: ")
		if len(parts) > 1 {
			detected = strings.Split(parts[1], "\r\n")[0]
		}
	} else if strings.Contains(banner, "nginx/") {
		detected = "Nginx"
	} else if strings.Contains(banner, "Microsoft-IIS") {
		detected = "Microsoft IIS"
	}

	if detected != "" {
		return &models.Vulnerability{
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
