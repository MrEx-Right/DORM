package plugins

import (
	"DORM/models"
	"fmt"
	"net"
	"strconv"
	"time"
)

// 1. OPEN PORT DETECTION
type PortCheckPlugin struct{}

func (p *PortCheckPlugin) Name() string { return "Open Port Detection" }

func (p *PortCheckPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	address := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil
	}
	conn.Close()
	return &models.Vulnerability{Target: target, Name: "Open TCP Port", Severity: "INFO", CVSS: 0.0, Description: fmt.Sprintf("Port %d is open.", target.Port), Solution: "Close if not required.", Reference: ""}
}
