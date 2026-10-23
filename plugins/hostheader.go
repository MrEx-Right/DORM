package plugins

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// 34. HOST HEADER INJECTION
//
// The request goes out with a random, unresolvable Host on a client that does
// NOT follow redirects. The shared client follows them, so a plain
// "http -> https://<Host>/" redirect used to send DORM to the real evil.com,
// whose own page contains "evil.com" — a finding on every port-80 target, and
// off-scope traffic to a third party.
type HostHeaderPlugin struct{}

func (p *HostHeaderPlugin) Name() string { return "Host Header Injection" }

func (p *HostHeaderPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	canary := "dorm-" + models.RandomToken() + ".invalid"

	req, err := http.NewRequest("GET", getURL(target, "/"), nil)
	if err != nil {
		return nil
	}
	req.Host = canary
	resp, err := models.NoRedirectClient().Do(req)
	if err != nil {
		return nil
	}
	body := readBody(resp, 262144)

	// Poisoning: the application builds absolute URLs (links, scripts, form
	// actions, canonical, password-reset style links) from the Host header.
	// An error page that merely prints the unknown host as text does not count.
	absURL := regexp.MustCompile(`(?i)(?:https?:)?//` + regexp.QuoteMeta(canary) + `\b`)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if loc := absURL.FindStringIndex(body); loc != nil {
			return &models.Vulnerability{
				Target: target, Name: "Host Header Injection", Severity: "MEDIUM", CVSS: 5.4,
				Description: fmt.Sprintf(
					"The application builds absolute URLs from the Host header.\nSent Host: %s\nReflected in the %d response body: ...%s...\n\nIf such a page is cached, or a link like this is emailed (password reset), an attacker controls where it points.",
					canary, resp.StatusCode, snippetAround(body, loc[0], loc[1], 60),
				),
				Solution:  "Build absolute URLs from a configured canonical host, not from the request's Host header; reject requests whose Host is not on an allow-list.",
				Reference: "PortSwigger: HTTP Host header attacks / CWE-644",
			}
		}
	}

	// Redirect reflection: typical of an http->https or canonical-host
	// redirect. A victim's browser never sends an attacker-chosen Host, so on
	// its own this is informational.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if u, err := url.Parse(resp.Header.Get("Location")); err == nil && strings.EqualFold(u.Hostname(), canary) {
			return &models.Vulnerability{
				Target: target, Name: "Host Header Reflected in Redirect", Severity: "INFO", CVSS: 0.0,
				Description: fmt.Sprintf(
					"The %d redirect builds its Location from the Host header.\nSent Host: %s\nLocation: %s\n\nNot exploitable by itself (a browser does not send an attacker-chosen Host); it matters only together with a cache that stores the redirect under an unkeyed header.",
					resp.StatusCode, canary, resp.Header.Get("Location"),
				),
				Solution:  "Redirect to a configured canonical host instead of echoing the request's Host header.",
				Reference: "PortSwigger: HTTP Host header attacks",
			}
		}
	}
	return nil
}

// snippetAround returns body[start:end] with up to pad bytes of context on
// each side, newlines flattened.
func snippetAround(body string, start, end, pad int) string {
	from, to := max(0, start-pad), min(len(body), end+pad)
	return strings.Join(strings.Fields(body[from:to]), " ")
}
