package plugins

import (
	"DORM/models"
	"DORM/sitemapper"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
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
	// Prefixes, when set, make the rule a prefixed key: the match must start
	// a standalone token and the part after the prefix must look random
	// (see secretfilter.go). Longer prefixes first.
	Prefixes []string
}

var secretRules = []secretRule{
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), nil},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws(.{0,20})?secret(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`), nil},
	{"GitHub Classic Token", regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), []string{"ghp_"}},
	{"GitHub Fine-Grained Token", regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{20,}`), []string{"github_pat_"}},
	{"GitHub OAuth/App Token", regexp.MustCompile(`gh[ousr]_[0-9a-zA-Z]{36,}`), []string{"gho_", "ghu_", "ghs_", "ghr_"}},
	{"Stripe Live Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), []string{"sk_live_"}},
	{"Stripe Restricted Key", regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`), []string{"rk_live_"}},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{20,}`), nil},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z-]{10,72}`), []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"}},
	{"OpenAI API Key", regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), []string{"sk-"}},
	{"OpenAI Project/Service Key", regexp.MustCompile(`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}`), []string{"sk-proj-", "sk-svcacct-", "sk-admin-"}},
	{"Anthropic API Key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`), []string{"sk-ant-api03-", "sk-ant-admin01-", "sk-ant-"}},
	{"Hugging Face Token", regexp.MustCompile(`hf_[A-Za-z0-9]{34,}`), []string{"hf_"}},
	{"Replicate API Token", regexp.MustCompile(`r8_[A-Za-z0-9]{20,}`), []string{"r8_"}},
	{"Groq API Key", regexp.MustCompile(`gsk_[A-Za-z0-9]{20,}`), []string{"gsk_"}},
	{"Perplexity API Key", regexp.MustCompile(`pplx-[A-Za-z0-9]{20,}`), []string{"pplx-"}},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), []string{"AIza"}},
	{"Generic JWT", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`), nil},
	{"Generic Secret Assignment", regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)['"]?\s*[:=]\s*['"][0-9a-zA-Z_\-]{16,}['"]`), nil},
}

// assignedValueRe pulls the quoted value out of a Generic Secret Assignment match.
var assignedValueRe = regexp.MustCompile(`['"]([0-9a-zA-Z_\-]{16,})['"]$`)

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
// foundKnown: a named key format matched; foundAssign: a `secret = "..."`
// style assignment matched. Hits beyond those are entropy-only candidates.
func scanForSecrets(body, sourceLabel string, seen map[string]bool) (hits []string, foundKnown, foundAssign bool) {
	for _, rule := range secretRules {
		var matches []string
		if len(rule.Prefixes) > 0 {
			matches = findKeys(rule.Re, body, rule.Prefixes...)
		} else {
			matches = rule.Re.FindAllString(body, -1)
		}
		for _, m := range matches {
			// `password: "password_confirmation_field"` is a field name, not
			// a secret: the assigned value has to look like key material too.
			if rule.Name == "Generic Secret Assignment" {
				if v := assignedValueRe.FindStringSubmatch(m); v == nil || !plausibleKey(v[1]) {
					continue
				}
			}
			key := rule.Name + ":" + m
			if seen[key] {
				continue
			}
			seen[key] = true
			hits = append(hits, fmt.Sprintf("[%s] %s (in %s)", rule.Name, maskSecret(m), sourceLabel))
			if rule.Name != "Generic Secret Assignment" {
				foundKnown = true
			} else {
				foundAssign = true
			}
		}
	}
	for _, m := range highEntropyTokenRe.FindAllStringSubmatch(body, -1) {
		token := m[1]
		if !plausibleEntropyToken(token) {
			continue
		}
		key := "entropy:" + token
		if seen[key] {
			continue
		}
		seen[key] = true
		hits = append(hits, fmt.Sprintf("[High-Entropy Token] %s (in %s)", maskSecret(token), sourceLabel))
	}
	return hits, foundKnown, foundAssign
}

// harvestedJS records "scanID|jsURL" for JS files already scanned in a scan.
var harvestedJS sync.Map

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
	sm := sitemapper.GetSiteMap(target.IP)
	if sm != nil {
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
	// Every web port of a host runs this plugin, and an HTTP site that
	// redirects to HTTPS hands :80 and :443 the same bundles, so each hit was
	// reported twice. The first port to take a file in this scan owns it.
	if sm != nil && sm.ScanID != "" {
		owned := jsURLs[:0]
		for _, u := range jsURLs {
			if _, taken := harvestedJS.LoadOrStore(sm.ScanID+"|"+u, true); !taken {
				owned = append(owned, u)
			}
		}
		jsURLs = owned
	}
	if len(jsURLs) == 0 {
		return nil
	}
	if len(jsURLs) > 20 {
		jsURLs = jsURLs[:20]
	}

	seen := map[string]bool{}
	var allHits []string
	foundKnownSecret, foundAssignment := false, false

	for _, jsURL := range jsURLs {
		resp, err := models.GetClient().Get(jsURL)
		if err != nil {
			continue
		}
		jsBody := readBody(resp, 262144)

		hits, known, assign := scanForSecrets(jsBody, jsURL, seen)
		allHits = append(allHits, hits...)
		foundKnownSecret = foundKnownSecret || known
		foundAssignment = foundAssignment || assign

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
			hits, known, assign := scanForSecrets(combined, mapURL+" (sourcesContent)", seen)
			allHits = append(allHits, hits...)
			foundKnownSecret = foundKnownSecret || known
			foundAssignment = foundAssignment || assign
		}
	}

	if len(allHits) == 0 {
		return nil
	}

	// Entropy alone is a lead, not a leak: report it LOW until a named key
	// format or a secret assignment backs it up.
	severity := "LOW"
	cvss := 3.7
	switch {
	case foundKnownSecret:
		severity = "CRITICAL"
		cvss = 9.6
	case foundAssignment:
		severity = "HIGH"
		cvss = 7.5
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
