package plugins

import (
	"DORM/models"
	"strings"
)

// 3. HTTP HEADER ANALYSIS (V2 - SECURITY FOCUSED)
type HTTPHeaderPlugin struct{}

func (p *HTTPHeaderPlugin) Name() string { return "Security Headers Analysis" }

func (p *HTTPHeaderPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	missing := []string{}

	headers := map[string]string{
		"Strict-Transport-Security": "HSTS missing, MITM attack possible.",
		"Content-Security-Policy":   "CSP missing, vulnerable to XSS.",
		"X-Content-Type-Options":    "Sniffing protection (nosniff) missing.",
		"Referrer-Policy":           "Referrer information might leak.",
	}

	for h, desc := range headers {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h+": "+desc)
		}
	}

	if len(missing) > 0 {
		return &models.Vulnerability{
			Target: target, Name: "Missing Security Headers", Severity: "LOW", CVSS: 3.5,
			Description: strings.Join(missing, "\n"),
			Solution:    "Add recommended HTTP headers to server configuration.",
		}
	}
	return nil
}
