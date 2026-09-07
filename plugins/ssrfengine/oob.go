package ssrfengine

import (
	"DORM/models"
	"fmt"
	"net/http"
)

// RunOOBCheck attempts an Out-of-Band collaborator confirmation.
//
// NOTE (carried forward from the pre-PEP-2.2 plugins.SSRFMetadataPlugin,
// verified still true at split time): nothing in this repository ever
// Stores a "collab_url" or "collab_hit" key into models.SharedData — there
// is no OOB collaborator subsystem wired up today. This whole check is
// unreachable dead code until such a subsystem exists; it's kept here
// rather than deleted so the intended mechanism (and its shape) survives
// for whoever eventually builds that subsystem.
func RunOOBCheck(client *http.Client, baseURL string, target models.ScanTarget, params []string) *models.Vulnerability {
	collabURL := ""
	if val, ok := models.SharedData.Load("collab_url"); ok {
		if s, ok := val.(string); ok && s != "" {
			collabURL = s
		}
	}

	if collabURL == "" {
		return nil
	}

	for _, param := range params[:5] { // First 5 parameters are sufficient
		attackURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, collabURL)
		req, err := http.NewRequest("GET", attackURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()

		// OOB callback check: If request comes to collaborator server,
		// the external service performing this check writes "collab_hit" to SharedData
		if hitVal, hit := models.SharedData.Load("collab_hit"); hit {
			if hitParam, ok := hitVal.(string); ok && hitParam != "" {
				return &models.Vulnerability{
					Target:   target,
					Name:     "SSRF: OOB Callback Confirmed (DORM Collaborator)",
					Severity: "CRITICAL",
					CVSS:     10.0,
					Description: fmt.Sprintf(
						"SSRF definitively confirmed via Out-of-Band (OOB) callback.\nCallback received at collaborator URL.\nParam: %s\nCollaborator: %s\nProof: %s",
						param, collabURL, hitParam,
					),
					Solution:  "Filter outgoing HTTP requests based on a whitelist. Disable all external URL schemas.",
					Reference: "CWE-918: Server-Side Request Forgery",
				}
			}
		}
	}

	return nil
}
