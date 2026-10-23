package plugins

import (
	"DORM/models"
	"strings"
)

// 31. CLICKJACKING (X-Frame-Options)
type ClickjackingPlugin struct{}

func (p *ClickjackingPlugin) Name() string { return "Clickjacking Check" }

func (p *ClickjackingPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	resp, ok := fetchRenderedPage(target)
	if !ok {
		return nil
	}
	// Only CSP's frame-ancestors directive restricts framing; a CSP without
	// it (script-src only, say) leaves the page frameable.
	csp := strings.ToLower(resp.Header.Get("Content-Security-Policy"))
	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		return &models.Vulnerability{
			Target: target, Name: "Clickjacking Risk", Severity: "INFO", CVSS: 0.0,
			Description: "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive is set on " + resp.Request.URL.String() + ".",
			Solution:    "Add X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors 'none'/'self'.",
			Reference:   "OWASP Clickjacking",
		}
	}
	return nil
}
