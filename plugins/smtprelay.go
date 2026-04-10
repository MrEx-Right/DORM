package plugins

import (
	"DORM/models"
	"fmt"
	"net"
	"strings"
	"time"
)

// 62. SMTP OPEN RELAY
type SMTPRelayPlugin struct{}

func (p *SMTPRelayPlugin) Name() string { return "SMTP Open Relay" }

func (p *SMTPRelayPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 25 && target.Port != 587 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	conn.Read(buf)
	conn.Write([]byte("HELO dorm.com\r\n"))
	conn.Read(buf)
	conn.Write([]byte("MAIL FROM:<test@dorm.com>\r\n"))
	conn.Read(buf)

	conn.Write([]byte("RCPT TO:<victim@evil.com>\r\n"))
	n, _ := conn.Read(buf)

	if strings.Contains(string(buf[:n]), "250") {
		return &models.Vulnerability{
			Target: target, Name: "SMTP Open Relay", Severity: "CRITICAL", CVSS: 9.0,
			Description: "Server can be used to send spam.",
			Solution:    "Configure relay restrictions.",
			Reference:   "",
		}
	}
	return nil
}
