package plugins

import (
	"DORM/models"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type EDBPlugin struct{}

func (p *EDBPlugin) Name() string { return "Exploit-DB Scanner" }

func (p *EDBPlugin) Run(target models.ScanTarget) *models.Vulnerability {

	portStr := strconv.Itoa(target.Port)
	address := net.JoinHostPort(target.IP, portStr)

	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if target.Port == 80 || target.Port == 443 || target.Port == 8080 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	if n == 0 {
		return nil
	}
	banner := string(buf[:n])

	lines := strings.Split(banner, "\n")
	cleanBanner := ""

	for _, line := range lines {

		if strings.Contains(line, "Server:") || strings.Contains(line, "SSH") || strings.Contains(line, "FTP") {
			cleanBanner = line
			break
		}
	}

	if cleanBanner == "" && len(lines) > 0 {
		cleanBanner = lines[0]
	}

	cleanBanner = strings.ReplaceAll(cleanBanner, "Server:", "")
	cleanBanner = strings.TrimSpace(cleanBanner)

	cleanBanner = strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 {
			return r
		}
		return -1
	}, cleanBanner)

	if len(cleanBanner) < 4 {
		return nil
	}

	results := models.SearchExploitDB(cleanBanner)

	if len(results) > 0 {
		return &models.Vulnerability{
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
