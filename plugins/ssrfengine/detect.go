package ssrfengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"strings"
)

// controlURL is a harmless value for the probed parameter: an address that
// cannot resolve, so a server that really fetches it gets nothing back.
const controlURL = "http://dorm-ssrf-control.invalid/"

// controlBody fetches the same parameter with controlURL. A signature that
// is already in this response (the "220" of a CSS hsl(220, ...), an API
// that answers everything the same way) is the page itself, not an
// internal resource the payload pulled in.
func controlBody(client *http.Client, baseURL, param string) (string, bool) {
	resp, err := client.Get(fmt.Sprintf("%s/?%s=%s", baseURL, param, controlURL))
	if err != nil {
		return "", false
	}
	return models.ReadBody(resp, 16384), true
}

// Probe fires a single payload-param combination and checks for a direct
// content-signature hit or a cloud-metadata header-error leak.
func Probe(client *http.Client, baseURL string, target models.ScanTarget, param, payloadURL, sig, desc string, cvss float64) *models.Vulnerability {
	attackURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, payloadURL)
	resp, err := client.Get(attackURL)
	if err != nil {
		return nil
	}
	body := models.ReadBody(resp, 16384)

	// Direct hit
	if resp.StatusCode == 200 && strings.Contains(body, sig) {
		if control, ok := controlBody(client, baseURL, param); !ok || strings.Contains(control, sig) {
			return nil
		}
		// A page with random content (a CSRF token) can hold a short signature
		// by chance once; a fetched resource holds it every time.
		again, err := client.Get(attackURL)
		if err != nil || !strings.Contains(models.ReadBody(again, 16384), sig) {
			return nil
		}
		return &models.Vulnerability{
			Target:   target,
			Name:     "SSRF Detected: " + desc,
			Severity: "CRITICAL",
			CVSS:     cvss,
			Description: fmt.Sprintf(
				"Server retrieved internal resource via '%s' parameter.\nPayload: %s\nProof: '%s' was found in the response.",
				param, payloadURL, sig,
			),
			Solution:  "Validate URL inputs against a whitelist. Disable file://, gopher://, dict:// schemas. Use IMDSv2 in cloud environments.",
			Reference: "CWE-918: Server-Side Request Forgery",
		}
	}

	// Cloud metadata error leak (GCP/Azure header missing error)
	if (resp.StatusCode == 400 || resp.StatusCode == 403) &&
		(strings.Contains(body, "Metadata-Flavor") || strings.Contains(body, "Required HTTP header")) {
		if control, ok := controlBody(client, baseURL, param); !ok ||
			strings.Contains(control, "Metadata-Flavor") || strings.Contains(control, "Required HTTP header") {
			return nil
		}
		bodyPreview := body
		if len(bodyPreview) > 100 {
			bodyPreview = bodyPreview[:100]
		}
		return &models.Vulnerability{
			Target:   target,
			Name:     "SSRF Detected (Cloud Metadata Error Leak)",
			Severity: "HIGH",
			CVSS:     8.5,
			Description: fmt.Sprintf(
				"Server attempted to access cloud metadata endpoint (missing header error leaked).\nPayload: %s\nError Preview: %s",
				payloadURL, bodyPreview,
			),
			Solution:  "Block outgoing internal IP requests to the 169.254.x.x range. Harden metadata access with IMDSv2.",
			Reference: "CWE-918: Server-Side Request Forgery",
		}
	}
	return nil
}

// AllGroups returns every payload group probed against every parameter.
func AllGroups() [][]SSRFPayload {
	return [][]SSRFPayload{
		CloudPayloads,
		AWSBypass,
		DNSBypass,
		FilePayloads,
		InternalPayloads,
		GopherPayloads,
	}
}
