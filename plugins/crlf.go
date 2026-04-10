package plugins

import (
	"DORM/models"
	"strings"
)

// 44. CRLF INJECTION (HTTP Response Splitting)
type CRLFPlugin struct{}

func (p *CRLFPlugin) Name() string { return "CRLF Injection" }

func (p *CRLFPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	payload := "/%0d%0aSet-Cookie:DORM=Hacked"
	resp, err := models.GetClient().Get(getURL(target, payload))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if strings.Contains(resp.Header.Get("Set-Cookie"), "DORM=Hacked") {
		return &models.Vulnerability{
			Target: target, Name: "CRLF Injection / Response Splitting", Severity: "MEDIUM", CVSS: 6.5,
			Description: "HTTP response can be split.",
			Solution:    "Encode URL inputs.",
			Reference:   "",
		}
	}
	return nil
}
