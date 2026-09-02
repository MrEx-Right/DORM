package plugins

import (
	"DORM/models"
	"io"
	"net/http"
	"strings"
)

// 19. TRACE METHOD
type TraceMethodPlugin struct{}

func (p *TraceMethodPlugin) Name() string { return "HTTP TRACE Method" }

func (p *TraceMethodPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, _ := http.NewRequest("TRACE", getURL(target, ""), nil)
	req.Header.Set("X-Dorm-Trace-Canary", "dorm_trace_check")
	resp, err := models.GetClient().Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	// A genuinely TRACE-vulnerable server echoes the request back verbatim
	// (that echo IS the XST attack surface) — a bare 200 alone just means
	// something answered, e.g. a catch-all router that 200s every method.
	if resp.StatusCode == 200 && strings.Contains(string(body), "dorm_trace_check") {
		return &models.Vulnerability{Target: target, Name: "TRACE Method Enabled", Severity: "MEDIUM", CVSS: 4.5, Description: "Vulnerable to XST attacks.", Solution: "Set TraceEnable Off.", Reference: ""}
	}
	return nil
}
