package plugins

import (
	"DORM/models"
	"fmt"
	"net"
	"strings"
	"time"
)

// 61. ANONYMOUS FTP
type FTPAnonPlugin struct{}

func (p *FTPAnonPlugin) Name() string { return "Anonymous FTP" }

func (p *FTPAnonPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 21 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	conn.Read(buf)

	conn.Write([]byte("USER anonymous\r\n"))
	conn.Read(buf)
	conn.Write([]byte("PASS anonymous@dorm.com\r\n"))
	n, _ := conn.Read(buf)

	if strings.Contains(string(buf[:n]), "230") {
		return &models.Vulnerability{
			Target: target, Name: "FTP Anonymous Login", Severity: "HIGH", CVSS: 7.5,
			Description: "FTP login allowed without password.",
			Solution:    "Disable anonymous access.",
			Reference:   "",
		}
	}
	return nil
}
