// ==================================================
// SSTI ENGINE — v3.1 "Template Terminator" (PEP 2.2)
// 15+ payload · Framework Fingerprint
// RCE Escalation · POST Fuzzing · Error Detection
// ==================================================
package sstiengine

import "DORM/models"

type SSTIPlugin struct{}

func (p *SSTIPlugin) Name() string { return "SSTI (Template Terminator v3)" }

func (p *SSTIPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	if vuln := RunStaticFuzz(client, baseURL, target); vuln != nil {
		return vuln
	}

	if vuln := RunSpiderFuzz(client, target); vuln != nil {
		return vuln
	}

	return nil
}
