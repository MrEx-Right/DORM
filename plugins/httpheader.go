package plugins

import (
	"DORM/models"
	"strings"
)

// 3. HTTP HEADER ANALYSIS (V2 - SECURITY FOCUSED)
type HTTPHeaderPlugin struct{}

func (p *HTTPHeaderPlugin) Name() string { return "Security Headers Analysis" }

// securityHeaders is ordered (a map's random order made the same finding
// read differently on every scan).
var securityHeaders = []struct{ name, desc string }{
	{"Strict-Transport-Security", "HSTS missing, MITM attack possible."},
	{"Content-Security-Policy", "CSP missing, no second line of defence against XSS."},
	{"X-Content-Type-Options", "Sniffing protection (nosniff) missing."},
	{"Referrer-Policy", "Referrer information might leak."},
}

func (p *HTTPHeaderPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, ok := fetchRenderedPage(target)
	if !ok {
		return nil
	}
	overHTTPS := resp.Request.URL.Scheme == "https"

	missing := []string{}
	for _, h := range securityHeaders {
		// Browsers ignore HSTS received over plain HTTP (RFC 6797 §8.1).
		if h.name == "Strict-Transport-Security" && !overHTTPS {
			continue
		}
		if resp.Header.Get(h.name) == "" {
			missing = append(missing, h.name+": "+h.desc)
		}
	}

	if len(missing) > 0 {
		return &models.Vulnerability{
			Target: target, Name: "Missing Security Headers", Severity: "INFO", CVSS: 0.0,
			Description: strings.Join(missing, "\n"),
			Solution:    "Add recommended HTTP headers to server configuration.",
		}
	}
	return nil
}
