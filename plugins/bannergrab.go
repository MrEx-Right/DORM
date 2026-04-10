package plugins

import (
	"DORM/models"
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
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		return &models.Vulnerability{Target: target, Name: "Service Banner", Severity: "LOW", CVSS: 2.0, Description: fmt.Sprintf("Banner: %s", string(buf[:min(n, 50)])), Solution: "Hide banner.", Reference: ""}
	}
	return nil
}
