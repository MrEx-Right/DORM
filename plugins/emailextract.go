package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 29. EMAIL EXTRACTOR (Simple OSINT)
type EmailExtractPlugin struct{}

func (p *EmailExtractPlugin) Name() string { return "Email Disclosure" }

func (p *EmailExtractPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	if strings.Contains(content, "mailto:") {
		return &models.Vulnerability{Target: target, Name: "Email Address Found", Severity: "INFO", CVSS: 0.0, Description: "Email address found in source (Spam/Phishing risk).", Solution: "-", Reference: ""}
	}
	return nil
}
