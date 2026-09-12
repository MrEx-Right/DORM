package plugins

import (
	"DORM/models"
	"DORM/sitemapper"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// ==================================================
// WEBPACK / JS SOURCE MAP & SECRET HARVESTER
// Reuses JS files already discovered by the spider/DOM-crawler
// (sitemapper.SiteMap.JSFiles), probes each for a matching .js.map
// source map, and regex+entropy-scans both the raw JS bundle and any
// recovered source-map content for leaked credentials.
// ==================================================
type SecretHarvesterPlugin struct{}

func (p *SecretHarvesterPlugin) Name() string { return "Webpack Source Map & Secret Harvester" }

// sourceMapJSON is the minimal shape of a webpack/standard source map we
// need — we only care about the recovered original source content.
type sourceMapJSON struct {
	Version        int      `json:"version"`
	File           string   `json:"file"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

type secretRule struct {
	Name string
	Re   *regexp.Regexp
}

var secretRules = []secretRule{
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws(.{0,20})?secret(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`)},
	{"GitHub Classic Token", regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`)},
	{"GitHub Fine-Grained Token", regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{20,}`)},
	{"GitHub OAuth/App Token", regexp.MustCompile(`gh[ousr]_[0-9a-zA-Z]{36,}`)},
	{"Stripe Live Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"Stripe Restricted Key", regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`)},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{20,}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z-]{10,72}`)},
	{"OpenAI API Key", regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"Generic JWT", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)},
	{"Generic Secret Assignment", regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)['"]?\s*[:=]\s*['"][0-9a-zA-Z_\-]{16,}['"]`)},
}

// highEntropyTokenRe catches bare quoted strings that look like a secret
// (base64/hex-ish charset, 24-100 chars) even when no named rule matches.
var highEntropyTokenRe = regexp.MustCompile(`['"]([A-Za-z0-9+/_=-]{24,100})['"]`)

// shannonEntropy returns the Shannon entropy (bits/char) of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	n := float64(len(s))
	for _, c := range freq {
		pr := float64(c) / n
		entropy -= pr * math.Log2(pr)
	}
	return entropy
}

// maskSecret reveals only a short prefix/suffix of a secret so the full,
// usable credential never lands in the scan's Description/SQLite history.
func maskSecret(s string) string {
	head, tail := 6, 4
	if len(s) < 10 {
		head = len(s) / 3
		tail = len(s) / 3
	}
	if head+tail >= len(s) {
		return strings.Repeat("*", len(s))
	}
	return s[:head] + strings.Repeat("*", len(s)-head-tail) + s[len(s)-tail:]
}

// scanForSecrets runs the regex corpus + entropy filter over body, returning
// masked hit descriptions. `seen` dedupes identical matches across files.
func scanForSecrets(body, sourceLabel string, seen map[string]bool) (hits []string, foundKnown bool) {
	for _, rule := range secretRules {
		for _, m := range rule.Re.FindAllString(body, -1) {
			key := rule.Name + ":" + m
			if seen[key] {
				continue
			}
			seen[key] = true
			hits = append(hits, fmt.Sprintf("[%s] %s (in %s)", rule.Name, maskSecret(m), sourceLabel))
			if rule.Name != "Generic Secret Assignment" {
				foundKnown = true
			}
		}
	}
	for _, m := range highEntropyTokenRe.FindAllStringSubmatch(body, -1) {
		token := m[1]
		if shannonEntropy(token) < 4.0 {
			continue
		}
		key := "entropy:" + token
		if seen[key] {
			continue
		}
		seen[key] = true
		hits = append(hits, fmt.Sprintf("[High-Entropy Token] %s (in %s)", maskSecret(token), sourceLabel))
	}
	return hits, foundKnown
}

var sourceMappingURLRe = regexp.MustCompile(`(?://|/\*)#\s*sourceMappingURL=(\S+?)(?:\*/)?\s*$`)
var scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js[^"']*)["']`)

// resolveJSURL turns a possibly-relative script src into an absolute URL
// against the scan target.
func resolveJSURL(target models.ScanTarget, raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if strings.HasPrefix(raw, "/") {
		return getURL(target, raw)
	}
	return getURL(target, "/"+raw)
}

func (p *SecretHarvesterPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// Piggyback on JS files the spider/DOM-crawler already discovered
	// during pre-scan — no independent crawl needed.
	var jsURLs []string
	if sm := sitemapper.GetSiteMap(target.IP); sm != nil {
		for _, jf := range sm.JSFiles {
			jsURLs = append(jsURLs, jf.URL)
		}
	}
	if len(jsURLs) == 0 {
		// Fallback: no sitemap data (pre-scan timeout / non-HTML target) —
		// do a minimal discovery pass ourselves.
		resp, err := models.GetClient().Get(getURL(target, "/"))
		if err == nil {
			body := readBody(resp, 65536)
			for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
				jsURLs = append(jsURLs, resolveJSURL(target, m[1]))
			}
		}
	}
	if len(jsURLs) == 0 {
		return nil
	}
	if len(jsURLs) > 20 {
		jsURLs = jsURLs[:20]
	}

	seen := map[string]bool{}
	var allHits []string
	foundKnownSecret := false

	for _, jsURL := range jsURLs {
		resp, err := models.GetClient().Get(jsURL)
		if err != nil {
			continue
		}
		jsBody := readBody(resp, 262144)

		hits, known := scanForSecrets(jsBody, jsURL, seen)
		allHits = append(allHits, hits...)
		foundKnownSecret = foundKnownSecret || known

		mapURL := jsURL + ".map"
		if m := sourceMappingURLRe.FindStringSubmatch(jsBody); m != nil {
			mapURL = resolveJSURL(target, m[1])
		}

		mapResp, err := models.GetClient().Get(mapURL)
		if err != nil {
			continue
		}
		mapBody := readBody(mapResp, 524288)
		if !strings.Contains(mapBody, `"sources"`) || !strings.Contains(mapBody, `"version"`) {
			continue
		}
		var sm sourceMapJSON
		if err := json.Unmarshal([]byte(mapBody), &sm); err != nil {
			continue
		}
		if len(sm.SourcesContent) > 0 {
			combined := strings.Join(sm.SourcesContent, "\n")
			hits, known := scanForSecrets(combined, mapURL+" (sourcesContent)", seen)
			allHits = append(allHits, hits...)
			foundKnownSecret = foundKnownSecret || known
		}
	}

	if len(allHits) == 0 {
		return nil
	}

	severity := "HIGH"
	cvss := 7.5
	if foundKnownSecret {
		severity = "CRITICAL"
		cvss = 9.6
	}

	desc := fmt.Sprintf(
		"Harvested %d potential secret(s) from JS bundles and/or recovered source maps:\n%s\n\nNote: values are masked (first/last few characters only) — rotate any matching live credential immediately.",
		len(allHits), strings.Join(allHits, "\n"),
	)

	return &models.Vulnerability{
		Target:      target,
		Name:        "Exposed Secrets in JS Bundle / Source Map",
		Severity:    severity,
		CVSS:        cvss,
		Description: desc,
		Solution:    "Remove hardcoded secrets from client-side code and source maps. Rotate any exposed keys immediately. Disable source map generation for production builds, or restrict .map file access to authenticated developers only.",
		Reference:   "CWE-540: Inclusion of Sensitive Information in Source Code",
	}
}
