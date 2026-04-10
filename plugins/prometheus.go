package plugins

import (
	"DORM/models"
	"strings"
)

// 35. PROMETHEUS METRICS
type PrometheusPlugin struct{}

func (p *PrometheusPlugin) Name() string { return "Prometheus Metrics Exposure" }

func (p *PrometheusPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/metrics"))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		buf := make([]byte, 500)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "go_goroutines") || strings.Contains(string(buf), "process_cpu_seconds") {
			return &models.Vulnerability{
				Target: target, Name: "System Metrics Exposure", Severity: "MEDIUM", CVSS: 5.0,
				Description: "/metrics endpoint is open.",
				Solution:    "Restrict access.",
				Reference:   "",
			}
		}
	}
	return nil
}
