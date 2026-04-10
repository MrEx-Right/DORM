package plugins

import (
	"DORM/models"
	"fmt"
	"net"
	"strings"
	"time"
)

// 60. MEMCACHED STATS UDP/TCP
type MemcachedPlugin struct{}

func (p *MemcachedPlugin) Name() string { return "Memcached Stats" }

func (p *MemcachedPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 11211 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.Write([]byte("stats\r\n"))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "STAT pid") {
		return &models.Vulnerability{
			Target: target, Name: "Memcached Info Disclosure", Severity: "MEDIUM", CVSS: 5.0,
			Description: "Stats command enabled, can be used for DDoS.",
			Solution:    "Disable UDP, listen only on localhost.",
			Reference:   "",
		}
	}
	return nil
}
