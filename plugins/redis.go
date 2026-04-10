package plugins

import (
	"DORM/models"
	"fmt"
	"net"
	"strings"
	"time"
)

// 57. REDIS UNAUTH (TCP)
type RedisPlugin struct{}

func (p *RedisPlugin) Name() string { return "Redis Unauthorized Access" }

func (p *RedisPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 6379 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.Write([]byte("PING\r\n"))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "PONG") {
		return &models.Vulnerability{
			Target: target, Name: "Unprotected Redis Server", Severity: "CRITICAL", CVSS: 9.0,
			Description: "Redis server has no password, DB can be stolen.",
			Solution:    "Use 'requirepass' directive.",
			Reference:   "",
		}
	}
	return nil
}
