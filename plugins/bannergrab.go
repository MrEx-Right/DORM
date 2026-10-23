package plugins

import (
	"DORM/models"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

// 2. SERVICE BANNER
type BannerGrabPlugin struct{}

func (p *BannerGrabPlugin) Name() string { return "Service Banner Info" }

func (p *BannerGrabPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	address := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	var conn net.Conn
	var err error
	if target.Port == 443 || target.Port == 8443 {
		// Plain text to a TLS port only gets the server's "400 Bad Request:
		// plain HTTP request sent to HTTPS port", which is not a banner.
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true, ServerName: target.IP}) // #nosec G402 -- banner grab, not trust
	} else {
		conn, err = net.DialTimeout("tcp", address, 3*time.Second)
	}
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", target.IP, models.GetScanUserAgent())
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		return &models.Vulnerability{Target: target, Name: "Service Banner", Severity: "INFO", CVSS: 0.0, Description: fmt.Sprintf("Banner: %s", string(buf[:min(n, 50)])), Solution: "Hide banner.", Reference: ""}
	}
	return nil
}
