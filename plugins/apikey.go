package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"regexp"
)

// 63. API KEY LEAK (JS SCAN)
type APIKeyPlugin struct{}

func (p *APIKeyPlugin) Name() string { return "API Key in JS Files" }

type apiKeyPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    string
	CVSS        float64
	Description string // %s placeholder for the masked matched key
	// Prefixes: the match must start a standalone token and the part after
	// the prefix must look random (secretfilter.go). Longer prefixes first.
	Prefixes []string
}

// apiKeyPatterns is checked in order — first match wins, mirroring the
// original AWS-then-Google if/else-if precedence. AWS/Google patterns are
// tightened from bare substring checks to the real key shape to cut false
// positives while still matching everything the old checks matched.
var apiKeyPatterns = []apiKeyPattern{
	{"AWS API Key Leak", regexp.MustCompile(`AKIA[A-Z0-9]{16}`), "CRITICAL", 9.5,
		"AWS access key (%s) found in source code.", nil}, // base32 IDs often carry 0-1 digits: boundary check only
	{"Google API Key Leak", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), "MEDIUM", 5.0,
		"Google API key (%s) found in source code.", []string{"AIza"}},
	// Anthropic before OpenAI: `sk-ant-...` also matches the OpenAI pattern.
	{"Anthropic API Key Leak", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`), "CRITICAL", 9.3,
		"Anthropic API key (%s) found in source code. This key can be used to consume the account's paid API credits.", []string{"sk-ant-api03-", "sk-ant-admin01-", "sk-ant-"}},
	{"OpenAI API Key Leak", regexp.MustCompile(`sk-(proj-)?[A-Za-z0-9_\-]{20,}`), "CRITICAL", 9.3,
		"OpenAI API key (%s) found in source code. This key can be used to consume the account's paid API credits or access any data it has scoped access to.", []string{"sk-proj-", "sk-svcacct-", "sk-admin-", "sk-"}},
	{"HuggingFace API Token Leak", regexp.MustCompile(`hf_[A-Za-z0-9]{34,}`), "HIGH", 8.1,
		"Hugging Face access token (%s) found in source code. This token may allow access to private models/datasets or Inference API usage billed to the account.", []string{"hf_"}},
	{"Replicate API Token Leak", regexp.MustCompile(`r8_[A-Za-z0-9]{20,}`), "HIGH", 8.1,
		"Replicate API token (%s) found in source code. This token can be used to run models and consume the account's paid compute credits.", []string{"r8_"}},
	{"Groq API Key Leak", regexp.MustCompile(`gsk_[A-Za-z0-9]{20,}`), "HIGH", 8.1,
		"Groq API key (%s) found in source code. This key can be used to consume the account's paid API credits.", []string{"gsk_"}},
	{"Perplexity API Key Leak", regexp.MustCompile(`pplx-[A-Za-z0-9]{20,}`), "HIGH", 8.1,
		"Perplexity API key (%s) found in source code. This key can be used to consume the account's paid API credits.", []string{"pplx-"}},
}

// maskKey redacts the middle of a matched secret so the finding is useful
// for triage without dumping the full live credential into the report.
func maskKey(k string) string {
	if len(k) <= 10 {
		return "****"
	}
	return k[:6] + "..." + k[len(k)-4:]
}

func (p *APIKeyPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	resp, err := models.GetClient().Get(getURL(target, "/"))
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	bodyBytes, _ := io.ReadAll(resp.Body)
	// The URL after redirects: "/" often lands on a login page.
	return apiKeyFinding(target, string(bodyBytes), resp.Request.URL.String())
}

// apiKeyFinding reports the first key in body, in apiKeyPatterns order. A
// Plesk telemetry key (models.PleskUATKey) is not the site's credential: it
// is reported as an outdated-Plesk INFO, and only when the page has no
// other key.
func apiKeyFinding(target models.ScanTarget, body, pageURL string) *models.Vulnerability {
	pleskKey, pleskVersion := "", ""
	for _, pat := range apiKeyPatterns {
		for _, loc := range findKeyIndexes(pat.Regex, body, pat.Prefixes...) {
			m := body[loc[0]:loc[1]]
			if version, ok := models.PleskUATKey(body, loc[0]); ok {
				if pleskKey == "" {
					pleskKey, pleskVersion = m, version
				}
				continue
			}
			return &models.Vulnerability{
				Target:      target,
				Name:        pat.Name,
				Severity:    pat.Severity,
				CVSS:        pat.CVSS,
				Description: fmt.Sprintf(pat.Description, maskKey(m)) + " URL: " + pageURL,
				Solution:    "Rotate and revoke the exposed key immediately. Remove it from client-side/publicly served code and load secrets server-side from a vault or environment variable.",
				Reference:   "CWE-798: Use of Hard-coded Credentials",
			}
		}
	}
	if pleskKey == "" {
		return nil
	}
	if pleskVersion == "" {
		pleskVersion = "(version not shown)"
	}
	return &models.Vulnerability{
		Target:   target,
		Name:     "Outdated Plesk Exposes Vendor Telemetry Key",
		Severity: "INFO",
		CVSS:     0.0,
		Description: fmt.Sprintf("The Plesk %s page at %s embeds Plesk's own AWS Kinesis Firehose telemetry key (%s) in its Jsw.UAT.init block. "+
			"The key belongs to the vendor, not to this site, so there is nothing to rotate here. "+
			"Newer Plesk releases send this telemetry through uat-proxy.plesk.com and no longer ship a key. "+
			"The page also shows that the Plesk panel is reachable from the internet.",
			pleskVersion, pageURL, maskKey(pleskKey)),
		Solution:  "Update Plesk to the current release. Restrict the Plesk panel (port 8443) to trusted IP addresses.",
		Reference: "CWE-1104: Use of Unmaintained Third Party Components",
	}
}
