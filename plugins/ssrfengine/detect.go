package ssrfengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// controlURL is a harmless value for the probed parameter: an address that
// cannot resolve, so a server that really fetches it gets nothing back.
const controlURL = "http://dorm-ssrf-control.invalid/"

// Injector builds the request URL that carries value in the probed
// parameter.
type Injector func(value string) string

// RootParam injects into param on the site root, the guessed parameter
// names probed on every target.
func RootParam(baseURL, param string) Injector {
	return func(value string) string {
		return fmt.Sprintf("%s/?%s=%s", baseURL, param, value)
	}
}

// EndpointParam injects into param on a discovered endpoint, keeping its
// path and its other parameters.
func EndpointParam(endpointURL, param string) Injector {
	return func(value string) string {
		u, err := url.Parse(endpointURL)
		if err != nil {
			return endpointURL
		}
		q := u.Query()
		q.Set(param, value)
		u.RawQuery = q.Encode()
		return u.String()
	}
}

// fetchBody GETs the URL that inject builds for value.
func fetchBody(client *http.Client, inject Injector, value string, maxBytes int64) (int, string, bool) {
	resp, err := client.Get(inject(value))
	if err != nil {
		return 0, "", false
	}
	return resp.StatusCode, models.ReadBody(resp, maxBytes), true
}

// controlBody fetches the same parameter with controlURL. A signature that
// is already in this response (the "220" of a CSS hsl(220, ...), an API
// that answers everything the same way) is the page itself, not an
// internal resource the payload pulled in.
func controlBody(client *http.Client, inject Injector) (string, bool) {
	_, body, ok := fetchBody(client, inject, controlURL, 16384)
	return body, ok
}

// Probe fires a single payload-param combination and checks for a direct
// content-signature hit or a cloud-metadata header-error leak.
func Probe(client *http.Client, inject Injector, target models.ScanTarget, param, payloadURL, sig, desc string, cvss float64) *models.Vulnerability {
	attackURL := inject(payloadURL)
	resp, err := client.Get(attackURL)
	if err != nil {
		return nil
	}
	body := models.ReadBody(resp, 16384)

	// Direct hit
	if resp.StatusCode == 200 && strings.Contains(body, sig) {
		if control, ok := controlBody(client, inject); !ok || strings.Contains(control, sig) {
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
				"Server retrieved internal resource via '%s' parameter.\nRequest: %s\nPayload: %s\nProof: '%s' was found in the response.",
				param, attackURL, payloadURL, sig,
			),
			Solution:  "Validate URL inputs against a whitelist. Disable file://, gopher://, dict:// schemas. Use IMDSv2 in cloud environments.",
			Reference: "CWE-918: Server-Side Request Forgery",
		}
	}

	// Cloud metadata error leak (GCP/Azure header missing error)
	if (resp.StatusCode == 400 || resp.StatusCode == 403) &&
		(strings.Contains(body, "Metadata-Flavor") || strings.Contains(body, "Required HTTP header")) {
		if control, ok := controlBody(client, inject); !ok ||
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
				"Server attempted to access cloud metadata endpoint (missing header error leaked).\nRequest: %s\nPayload: %s\nError Preview: %s",
				attackURL, payloadURL, bodyPreview,
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
