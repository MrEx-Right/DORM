package ssrfengine

import (
	"DORM/models"
	"net/http"
	"strings"
)

// containsAny is a local copy of plugins.containsAny (plugins/bruteforce.go)
// — that helper is unexported and bruteforce.go isn't being converted to an
// engine, so ssrfengine can't import it directly.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// RunSpiderIntegration replays the most critical cloud-metadata payloads
// against spider-discovered GET endpoints whose parameter names look
// SSRF-sensitive.
func RunSpiderIntegration(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if !ok {
		return nil
	}
	spiderEndpoints := existing.([]models.Endpoint)

	for _, ep := range spiderEndpoints {
		if ep.Method != "GET" || len(ep.Params) == 0 {
			continue
		}
		for _, param := range ep.Params {
			// Is it an SSRF-sensitive parameter?
			if !containsAny(strings.ToLower(param),
				"url", "uri", "link", "dest", "redirect", "src", "source",
				"file", "fetch", "load", "open", "image", "proxy", "host") {
				continue
			}
			// Try the most critical payloads
			for _, pl := range CloudPayloads[:3] {
				if vuln := Probe(client, baseURL, target, param, pl.URL, pl.Sig, pl.Desc+" (Spider)", pl.CVSS); vuln != nil {
					vuln.Name += " (Spider-Discovered)"
					return vuln
				}
			}
		}
	}

	return nil
}
