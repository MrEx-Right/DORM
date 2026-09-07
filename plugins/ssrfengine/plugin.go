// ==================================================
// SSRF ENGINE — v2.1 "Cloud Phantom" (PEP 2.2)
// Cloud Metadata · Gopher/Dict · Internal Probe
// DNS Rebinding · Alt IP Formats · OOB Collaborator
// Spider Integration
// ==================================================
package ssrfengine

import "DORM/models"

type SSRFMetadataPlugin struct{}

func (p *SSRFMetadataPlugin) Name() string { return "SSRF Omni-Hunter v2 (Cloud/Gopher/OOB)" }

func (p *SSRFMetadataPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	for _, param := range Params {
		for _, group := range AllGroups() {
			for _, pl := range group {
				if vuln := Probe(client, baseURL, target, param, pl.URL, pl.Sig, pl.Desc, pl.CVSS); vuln != nil {
					return vuln
				}
			}
		}
	}

	if vuln := RunLocalhostBypass(client, baseURL, target, Params); vuln != nil {
		return vuln
	}

	if vuln := RunOOBCheck(client, baseURL, target, Params); vuln != nil {
		return vuln
	}

	if vuln := RunSpiderIntegration(client, baseURL, target); vuln != nil {
		return vuln
	}

	return nil
}
