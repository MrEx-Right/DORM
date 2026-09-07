// ==============================================================
// BLIND RCE ENGINE — v3.1 (PEP 2.2)
// ==============================================================
package blindrceengine

import "DORM/models"

type BlindRCEPlugin struct{}

func (p *BlindRCEPlugin) Name() string { return "Blind Command Injection (Phantom Strike v3)" }

func (p *BlindRCEPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	// Pre-generate both probe sets (2s and 7s)
	probes2 := GenerateRCEPayloads(2)
	probes7 := GenerateRCEPayloads(7)

	if vuln := RunStaticFuzz(client, baseURL, target, probes2, probes7); vuln != nil {
		return vuln
	}

	if vuln := RunSpiderFuzz(client, target, probes2, probes7); vuln != nil {
		return vuln
	}

	return nil
}
