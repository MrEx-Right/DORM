package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 27. SECURITY.TXT CHECK
type SecurityTxtPlugin struct{}

func (p *SecurityTxtPlugin) Name() string { return "Security.txt File" }

func (p *SecurityTxtPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/.well-known/security.txt"))
	if err != nil {
		return nil
	}
	if resp.StatusCode != 200 {
		_ = resp.Body.Close()
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	// RFC 9116 requires a "Contact:" field — a bare 200 alone (e.g. a SPA
	// catch-all router) doesn't confirm this is a real security.txt.
	if strings.Contains(string(body), "Contact:") {
		return &models.Vulnerability{Target: target, Name: "Security.txt Found", Severity: "INFO", CVSS: 0.0, Description: "Security contact info available.", Solution: "Informational.", Reference: ""}
	}
	return nil
}
