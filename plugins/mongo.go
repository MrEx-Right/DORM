package plugins

import (
	"DORM/models"
	"fmt"
	"net"
	"time"
)

// 58. MONGODB NO-AUTH (TCP)
type MongoPlugin struct{}

func (p *MongoPlugin) Name() string { return "MongoDB Unauthorized Access" }

func (p *MongoPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 27017 {
		return nil
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	return &models.Vulnerability{
		Target: target, Name: "Open MongoDB Port", Severity: "MEDIUM", CVSS: 5.0,
		Description: "Port 27017 is open, check auth.",
		Solution:    "Restrict via IP whitelist.",
		Reference:   "",
	}
}
