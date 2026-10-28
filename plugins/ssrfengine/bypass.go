package ssrfengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// volatileRe matches the parts of a response that change on every request
// (ids, tokens, timestamps, counters), masked before a body is compared
// with the control's.
var volatileRe = regexp.MustCompile(`[0-9a-fA-F-]{8,}|[0-9]+`)

// closedPort returns u with port 1 on the same host spelling: nothing
// listens there, so a server that really fetches it gets a refused
// connection, and a filter treats it exactly like u.
func closedPort(u string) string {
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return u
	}
	host, path, _ := strings.Cut(rest, "/")
	return scheme + "://" + host + ":1/" + path
}

// authority returns the host[:port] part of a payload URL.
func authority(u string) string {
	_, rest, _ := strings.Cut(u, "://")
	host, _, _ := strings.Cut(rest, "/")
	return host
}

// maskReflection removes every spelling of the injected URLs (as sent, once
// decoded, query-escaped, JSON-escaped, and their bare host) and the
// volatile parts from body, so a page that only echoes its input, or an
// error naming the host it could not reach, compares equal for both.
func maskReflection(body string, injected ...string) string {
	var forms []string
	for _, u := range injected {
		dec, err := url.QueryUnescape(u)
		if err != nil {
			dec = u
		}
		for _, v := range []string{u, dec} {
			forms = append(forms, v, url.QueryEscape(v), strings.ReplaceAll(v, "/", `\/`), authority(v))
		}
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	for _, f := range forms {
		if f != "" {
			body = strings.ReplaceAll(body, f, "§")
		}
	}
	return volatileRe.ReplaceAllString(body, "#")
}

// RunLocalhostBypass tries every localhost-spelling payload. Nothing on
// localhost answers with a known string, so the proof is a differential: the
// payload's host on its own port returns 200 and a non-empty body that
// isn't the target site's own HTML page, while the same host spelling on a
// closed port returns something else. A filter blocks both alike, a server
// that echoes its input or reports a failed fetch answers both alike once
// the injected URL is masked; only a fetch that reached a listening service
// on localhost tells them apart. The hit must repeat with the same body.
func RunLocalhostBypass(client *http.Client, baseURL string, target models.ScanTarget, params []string) *models.Vulnerability {
	for _, param := range params {
		inject := RootParam(baseURL, param)
		for _, pl := range LocalhostBypass {
			status, body, ok := fetchBody(client, inject, pl.URL, 8192)
			// 200 + non-empty content + not the target site's own content
			if !ok || status != 200 || len(body) <= 50 || strings.Contains(body, "<html") {
				continue
			}
			closed := closedPort(pl.URL)
			_, control, ok := fetchBody(client, inject, closed, 8192)
			if !ok {
				continue
			}
			masked := maskReflection(body, pl.URL, closed)
			if masked == maskReflection(control, pl.URL, closed) {
				continue
			}
			status2, again, ok := fetchBody(client, inject, pl.URL, 8192)
			if !ok || status2 != 200 || maskReflection(again, pl.URL, closed) != masked {
				continue
			}
			return &models.Vulnerability{
				Target:   target,
				Name:     "SSRF: Localhost Bypass Detected",
				Severity: "CRITICAL",
				CVSS:     pl.CVSS,
				Description: fmt.Sprintf(
					"SSRF confirmed via localhost bypass technique.\nTechnique: %s\nPayload: %s\nParam: %s\nResponse Size: %d bytes\nProof: the same host on a closed port (%s) returned a different response.",
					pl.Desc, pl.URL, param, len(body), closed,
				),
				Solution:  "Block 127.0.0.1, 0.0.0.0, [::1] and all encoding variants except whitelisted ones.",
				Reference: "CWE-918: Server-Side Request Forgery",
			}
		}
	}
	return nil
}
