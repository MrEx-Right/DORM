package plugins

import (
	"DORM/models"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// 4. SSL CHECK
type SSLCheckPlugin struct{}

func (p *SSLCheckPlugin) Name() string { return "SSL Certificate Check" }

func (p *SSLCheckPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 443 {
		return nil
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 4 * time.Second}, "tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	defer conn.Close()
	if time.Now().After(conn.ConnectionState().PeerCertificates[0].NotAfter) {
		return &models.Vulnerability{Target: target, Name: "Expired SSL Certificate", Severity: "MEDIUM", CVSS: 5.0, Description: "Certificate has expired.", Solution: "Renew certificate.", Reference: ""}
	}
	return nil
}
