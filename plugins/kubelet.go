package plugins

import (
	"DORM/models"
	"strings"
)

// 52. KUBERNETES KUBELET API (Unauth Access)
type KubeletPlugin struct{}

func (p *KubeletPlugin) Name() string { return "Kubernetes Kubelet API" }

func (p *KubeletPlugin) Run(target models.ScanTarget) *models.Vulnerability {

	if target.Port != 10250 {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/pods"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)

		if strings.Contains(string(buf), "\"kind\":\"PodList\"") {
			return &models.Vulnerability{
				Target: target, Name: "Kubelet API Exposure", Severity: "CRITICAL", CVSS: 10.0,
				Description: "Kubernetes pod list accessible without auth.",
				Solution:    "Disable Anonymous auth.",
				Reference:   "",
			}
		}
	}
	return nil
}
