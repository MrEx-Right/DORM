package wafengine

import (
	"io"
	"net/http"
	"strings"
)

// ============================================================
//  CDN DETECTOR — Distinguish CDN-only from CDN+WAF setups
// ============================================================

// CDNSignature holds patterns to identify a CDN provider.
type CDNSignature struct {
	Name           string
	HeaderPatterns []headerPattern
	HasWAF         bool // true if this CDN also provides WAF capabilities
}

var cdnSignatures = []CDNSignature{
	{
		Name: "Cloudflare",
		HeaderPatterns: []headerPattern{
			{"Server", "cloudflare"},
			{"CF-RAY", ""},
		},
		HasWAF: true, // Cloudflare is both CDN and WAF
	},
	{
		Name: "AWS CloudFront",
		HeaderPatterns: []headerPattern{
			{"Via", "cloudfront"},
			{"X-Amz-Cf-Pop", ""},
			{"X-Cache", "from cloudfront"},
		},
		HasWAF: true, // CloudFront can have WAF rules attached
	},
	{
		Name: "Akamai",
		HeaderPatterns: []headerPattern{
			{"X-Akamai-Transformed", ""},
			{"Server", "akamai"},
		},
		HasWAF: true,
	},
	{
		Name: "Fastly",
		HeaderPatterns: []headerPattern{
			{"X-Served-By", "cache-"},
			{"X-Fastly-Request-ID", ""},
		},
		HasWAF: false, // Fastly CDN without WAF by default
	},
	{
		Name: "Varnish",
		HeaderPatterns: []headerPattern{
			{"Via", "varnish"},
			{"X-Varnish", ""},
		},
		HasWAF: false,
	},
	{
		Name: "KeyCDN",
		HeaderPatterns: []headerPattern{
			{"Server", "keycdn"},
			{"X-Edge-Location", ""},
		},
		HasWAF: false,
	},
	{
		Name: "StackPath",
		HeaderPatterns: []headerPattern{
			{"X-SP-URL", ""},
			{"X-SP-Edge-Host", ""},
		},
		HasWAF: true,
	},
	{
		Name: "Edgecast (Verizon)",
		HeaderPatterns: []headerPattern{
			{"Server", "ecs"},
			{"X-EC-Custom-Error", ""},
		},
		HasWAF: false,
	},
	{
		Name: "Azure CDN",
		HeaderPatterns: []headerPattern{
			{"X-MSEdge-Ref", ""},
			{"X-Azure-Ref", ""},
		},
		HasWAF: true,
	},
	{
		Name: "Google CDN",
		HeaderPatterns: []headerPattern{
			{"Via", "google"},
			{"Server", "gws"},
		},
		HasWAF: true,
	},
	{
		Name: "Netlify",
		HeaderPatterns: []headerPattern{
			{"Server", "netlify"},
			{"X-Nf-Request-ID", ""},
		},
		HasWAF: false,
	},
	{
		Name: "Vercel",
		HeaderPatterns: []headerPattern{
			{"Server", "vercel"},
			{"X-Vercel-Id", ""},
		},
		HasWAF: false,
	},
}

// DetectCDN checks if the target is behind a CDN and whether it's CDN-only (no WAF).
// Returns the CDN name and whether it's CDN-only (no WAF capability).
func DetectCDN(client *http.Client, baseURL string) (cdnName string, isCDNOnly bool) {
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 1024)) // drain

	bestScore := 0
	bestCDN := ""
	bestHasWAF := false

	for _, sig := range cdnSignatures {
		score := 0
		for _, hp := range sig.HeaderPatterns {
			headerVal := resp.Header.Get(hp.Header)
			if headerVal == "" {
				continue
			}
			if hp.Value == "" || strings.Contains(strings.ToLower(headerVal), strings.ToLower(hp.Value)) {
				score++
			}
		}

		if score > bestScore {
			bestScore = score
			bestCDN = sig.Name
			bestHasWAF = sig.HasWAF
		}
	}

	if bestScore == 0 {
		return "", false
	}

	return bestCDN, !bestHasWAF
}
