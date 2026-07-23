package plugins

import (
	"DORM/models"
	"crypto/tls"
	"fmt"
	"time"
)

// WEAK TLS/SSL CIPHERS (POODLE / BEAST)
type TLSCheckPlugin struct{}

func (p *TLSCheckPlugin) Name() string { return "Weak SSL/TLS Protocols" }

func (p *TLSCheckPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 443 && target.Port != 8443 {
		return nil
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
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
			// Verify connection is truly established by sending an HTTP request and reading application data
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: DORM-Scanner\r\n\r\n", target.IP)
			_, writeErr := conn.Write([]byte(req))
			if writeErr == nil {
				buf := make([]byte, 1)
				n, readErr := conn.Read(buf)
				if readErr == nil && n > 0 {
					return &models.Vulnerability{
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
		}
	}
	return nil
}
