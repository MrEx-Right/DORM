package plugins

import "DORM/models"

// 77. CITRIX ADC / NETSCALER TRAVERSAL (CVE-2019-19781)
type CitrixPlugin struct{}

func (p *CitrixPlugin) Name() string { return "Citrix ADC Traversal" }

func (p *CitrixPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	targetURL := getURL(target, "/vpn/../vpns/portal/scripts/newbm.pl")
	resp, err := models.GetClient().Get(targetURL)

	if err == nil {
		defer resp.Body.Close()

		if resp.StatusCode == 200 && resp.Header.Get("Smb-Conf") != "" {
			return &models.Vulnerability{
				Target: target, Name: "Citrix ADC RCE (Mashable)", Severity: "CRITICAL", CVSS: 9.8,
				Description: "Directory traversal in Citrix ADC allows arbitrary code execution.",
				Solution:    "Apply Citrix mitigation or patch immediately.", Reference: "CVE-2019-19781",
			}
		}
	}
	return nil
}
