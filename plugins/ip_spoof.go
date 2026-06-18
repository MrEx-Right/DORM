package plugins

// ============================================================
//  IP SPOOF — Rate-Limit & WAF Bypass Tester (V1.0)
//  OWASP API Security: A4:2023 — Unrestricted Resource Consumption
//
//  SAFE DESIGN PRINCIPLES (concurrent engine awareness):
//  1. Passive-First:   Inspect existing response headers before any active probing
//  2. Max 3 Probes:    At most 3 requests to confirm rate-limiting — never flood
//  3. 8s Delay:        Allow other plugins (SQLi, XSS, Spider) to complete first
//  4. Ban Sentinel:    Any connection error during probing → immediate abort
//  5. Minimal Bypass:  One request per header in bypass phase — no loops
// ============================================================

import (
	"DORM/models"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type IPSpoofPlugin struct{}

func (p *IPSpoofPlugin) Name() string {
	return "IP Spoof — Rate-Limit & WAF Bypass"
}

// ============================================================
// IP SPOOF HEADER MATRIX (12 headers)
// ============================================================
var spoofHeaders = []struct {
	Name  string
	Value string
}{
	// Standard Proxy Headers
	{"X-Forwarded-For", "127.0.0.1"},
	{"X-Real-IP", "127.0.0.1"},
	{"X-Originating-IP", "127.0.0.1"},
	{"X-Remote-IP", "127.0.0.1"},
	{"X-Remote-Addr", "127.0.0.1"},
	{"X-Client-IP", "127.0.0.1"},
	// CDN / Cloud Specific
	{"True-Client-IP", "127.0.0.1"},       // Akamai, Cloudflare Enterprise
	{"CF-Connecting-IP", "127.0.0.1"},     // Cloudflare
	{"Fastly-Client-IP", "127.0.0.1"},     // Fastly CDN
	{"X-Azure-ClientIP", "127.0.0.1"},     // Azure Front Door
	{"X-Cluster-Client-IP", "127.0.0.1"}, // Cluster / ELB
	// RFC 7239 Standard
	{"Forwarded", "for=127.0.0.1;proto=http;by=127.0.0.1"},
}

// Alternative IP addresses rotated through bypass attempts
var spoofIPs = []string{
	"127.0.0.1",
	"::1",
	"10.0.0.1",
	"10.0.0.100",
	"172.16.0.1",
	"192.168.1.1",
	"192.168.0.1",
	"localhost",
}

// Rate-limit response header signatures used for passive detection
var rateLimitHeaderSigs = []string{
	"x-ratelimit-limit",
	"x-ratelimit-remaining",
	"x-ratelimit-reset",
	"ratelimit-limit",
	"ratelimit-remaining",
	"ratelimit-reset",
	"x-rate-limit-limit",
	"x-rate-limit-remaining",
	"retry-after",
	"x-retry-after",
}

// WAF block signatures found in response bodies or headers
var wafBodySigs = []string{
	"cloudflare", "access denied", "blocked", "security check",
	"ddos protection", "firewall", "bot protection",
	"rate limit exceeded", "too many requests",
	"request rejected", "forbidden by waf",
}

// Lightweight probe endpoints used for rate-limit detection
var rateLimitProbeEndpoints = []string{
	"/api/health",
	"/api/ping",
	"/health",
	"/ping",
	"/api/v1/health",
	"/api/status",
	"/",
}

// ============================================================
// MAIN RUN
// ============================================================
func (p *IPSpoofPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// RULE 3: Allow other critical plugins (Spider, SQLi, XSS) to issue their
	// initial requests before this plugin begins. Running last reduces the risk
	// of being blocked and disrupting the rest of the concurrent scan.
	time.Sleep(8 * time.Second)

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ==================================================================
	// PHASE 1: PASSIVE HEADER SCAN (zero active probing)
	// Read rate-limit headers from a single existing response
	// ==================================================================
	passiveResult := passiveRateLimitDetect(client, baseURL, target)
	if passiveResult != nil {
		// Rate-limiting confirmed passively — attempt bypass before reporting
		bypassResult := testHeaderSpoofBypass(client, baseURL, target, passiveResult.rateLimitEndpoint, passiveResult.rateLimitHeader)
		if bypassResult != nil {
			return bypassResult
		}
		// Bypass unsuccessful — report as MEDIUM (rate-limit present but resilient)
		return &models.Vulnerability{
			Target:   target,
			Name:     "MEDIUM — Rate-Limit Detected (Bypass Unsuccessful)",
			Severity: "MEDIUM",
			CVSS:     4.3,
			Description: fmt.Sprintf(
				"🟡 A rate-limiting mechanism was detected but could not be bypassed via IP header spoofing.\n\n"+
					"Detection Method: Passive response header analysis (no active flooding performed)\n"+
					"Rate-Limit Header Observed: %s\n"+
					"Endpoint: %s\n\n"+
					"The system is actively enforcing rate-limiting and appears resilient against header-based spoofing.\n"+
					"This is a positive security indicator.",
				passiveResult.rateLimitHeader, baseURL+passiveResult.rateLimitEndpoint,
			),
			Solution:  "The current rate-limit configuration appears adequate. Ensure that forwarding headers such as X-Forwarded-For are only trusted when originating from verified, internal reverse-proxies.",
			Reference: "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
		}
	}

	// ==================================================================
	// PHASE 2: MINIMAL ACTIVE PROBE (≤3 requests)
	// Only executed when no rate-limit header was found passively
	// ==================================================================
	activeResult := minimalActiveProbe(client, baseURL, target)
	if activeResult == nil {
		// No rate-limiting detected — nothing to bypass
		return nil
	}

	// ==================================================================
	// PHASE 3: HEADER SPOOF BYPASS TEST
	// Rate-limit confirmed — test whether it can be circumvented via IP spoofing
	// ==================================================================
	bypassResult := testHeaderSpoofBypass(client, baseURL, target, activeResult.endpoint, "")
	if bypassResult != nil {
		return bypassResult
	}

	// ==================================================================
	// PHASE 4: COMPOUND MULTI-HEADER ATTACK
	// Send all spoof headers simultaneously — some systems parse only the first match
	// ==================================================================
	return testCompoundHeaderAttack(client, baseURL, target, activeResult.endpoint)
}

// ============================================================
// PHASE 1: PASSIVE HEADER SCAN
// ============================================================

type passiveDetectResult struct {
	rateLimitHeader   string
	rateLimitEndpoint string
}

func passiveRateLimitDetect(client *http.Client, baseURL string, target models.ScanTarget) *passiveDetectResult {
	// Issue a single request to one lightweight probe endpoint
	probeURL := ""
	for _, ep := range rateLimitProbeEndpoints {
		req, err := http.NewRequest("GET", baseURL+ep, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "DORM-IPSpoof-Probe/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Passively scan all response headers for rate-limit signatures
		for _, sig := range rateLimitHeaderSigs {
			for headerName := range resp.Header {
				if strings.EqualFold(headerName, sig) {
					val := resp.Header.Get(headerName)
					if val != "" {
						// Rate-limit header confirmed — store result in SharedData for other plugins
						models.SharedData.Store("rate_limit_"+target.IP, true)
						return &passiveDetectResult{
							rateLimitHeader:   fmt.Sprintf("%s: %s", headerName, val),
							rateLimitEndpoint: ep,
						}
					}
				}
			}
		}

		probeURL = ep
		break // Stop after the first successful response
	}

	// Secondary check: WAF/block body signature on the same probe endpoint
	if probeURL != "" {
		req, err := http.NewRequest("GET", baseURL+probeURL, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", "DORM-IPSpoof-Probe/1.0")
		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		body := readBody(resp, 4096)
		lowerBody := strings.ToLower(body)
		for _, sig := range wafBodySigs {
			if strings.Contains(lowerBody, sig) {
				models.SharedData.Store("waf_detected_"+target.IP, true)
				return &passiveDetectResult{
					rateLimitHeader:   "WAF/Block signature: " + sig,
					rateLimitEndpoint: probeURL,
				}
			}
		}
	}

	return nil
}

// ============================================================
// PHASE 2: MINIMAL ACTIVE PROBE (max 3 requests)
// ============================================================

type activeProbeResult struct {
	endpoint   string
	statusCode int
}

func minimalActiveProbe(client *http.Client, baseURL string, target models.ScanTarget) *activeProbeResult {
	// RULE 2: Send at most 3 requests per endpoint — just enough to confirm a 429, never to flood
	for _, ep := range rateLimitProbeEndpoints {
		fullURL := baseURL + ep
		probeCount := 0
		endpointReachable := false

		for probeCount < 3 {
			// RULE 4: Ban sentinel — any connection error triggers immediate abort
			req, err := http.NewRequest("GET", fullURL, nil)
			if err != nil {
				return nil
			}
			req.Header.Set("User-Agent", "DORM-IPSpoof-Probe/1.0")

			resp, err := client.Do(req)
			if err != nil {
				// Connection error likely indicates IP-level blocking — stop immediately
				return nil
			}

			if resp.StatusCode == 429 {
				resp.Body.Close()
				// Rate-limit confirmed via 429 — proceed to bypass phase
				return &activeProbeResult{endpoint: ep, statusCode: 429}
			}

			// Check for WAF block signals (403 + WAF body signature)
			if resp.StatusCode == 403 {
				body := readBody(resp, 2048)
				lowerBody := strings.ToLower(body)
				for _, sig := range wafBodySigs {
					if strings.Contains(lowerBody, sig) {
						return &activeProbeResult{endpoint: ep, statusCode: 403}
					}
				}
			}

			// Mark endpoint as reachable on any 2xx/3xx response
			if resp.StatusCode < 400 {
				endpointReachable = true
			}

			resp.Body.Close()
			probeCount++

			// Brief inter-request delay to avoid appearing aggressive
			time.Sleep(200 * time.Millisecond)
		}

		// Only commit to this endpoint if it actually responded with a valid status.
		// If the endpoint returned 404/410 for all probes, continue to the next
		// candidate so we don't miss a reachable endpoint further down the list.
		if endpointReachable {
			break
		}
	}

	return nil
}

// ============================================================
// PHASE 3: HEADER SPOOF BYPASS TEST
// ============================================================
func testHeaderSpoofBypass(client *http.Client, baseURL string, target models.ScanTarget, endpoint, detectedHeader string) *models.Vulnerability {
	fullURL := baseURL + endpoint

	for _, sh := range spoofHeaders {
		// RULE 5: One request per header — no retry loops
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "DORM-IPSpoof-Probe/1.0")
		req.Header.Set(sh.Name, sh.Value)

		// RULE 4: Ban sentinel — connection error means stop
		resp, err := client.Do(req)
		if err != nil {
			// Connection error may indicate an IP-level ban — abort the entire phase
			return nil
		}

		body := readBody(resp, 4096)
		lowerBody := strings.ToLower(body)

		// Determine whether the response is still blocked by WAF
		isBlocked := false
		for _, sig := range wafBodySigs {
			if strings.Contains(lowerBody, sig) {
				isBlocked = true
				break
			}
		}

		// Bypass successful: server returned 200 and no WAF block signature
		if resp.StatusCode == 200 && !isBlocked {
			headerContext := detectedHeader
			if headerContext == "" {
				headerContext = "Confirmed via active probe (HTTP 429/403 observed)"
			}

			return &models.Vulnerability{
				Target:   target,
				Name:     "HIGH — Rate-Limit/WAF Bypassed via IP Header Spoofing",
				Severity: "HIGH",
				CVSS:     7.5,
				Description: fmt.Sprintf(
					"🟠 HIGH: The rate-limiting or WAF protection was successfully bypassed by injecting a spoofed IP header.\n\n"+
						"Bypass Header Used: %s: %s\n"+
						"Target Endpoint: %s\n"+
						"HTTP Status After Bypass: %d\n"+
						"Detection Context: %s\n\n"+
						"The server applies rate-limit/WAF rules based on the IP value in this header rather than the real\n"+
						"connection IP. An attacker can trivially rotate the header value to reset rate-limit counters\n"+
						"or circumvent IP-based block rules without any infrastructure.",
					sh.Name, sh.Value, fullURL, resp.StatusCode, headerContext,
				),
				Solution:  "Only trust IP-forwarding headers (X-Forwarded-For, CF-Connecting-IP, etc.) when they originate from verified, internal reverse-proxies. On origin servers receiving direct internet traffic, these headers must be ignored entirely. For CDN setups, restrict CF-Connecting-IP trust to the CDN's published IP ranges only.",
				Reference: "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
			}
		}

		// Brief delay between per-header bypass attempts
		time.Sleep(150 * time.Millisecond)
	}

	return nil
}

// ============================================================
// PHASE 4: COMPOUND MULTI-HEADER ATTACK
// All spoof headers sent simultaneously — some parsers act on the first match
// ============================================================
func testCompoundHeaderAttack(client *http.Client, baseURL string, target models.ScanTarget, endpoint string) *models.Vulnerability {
	fullURL := baseURL + endpoint

	// RULE 5: Single request with all headers combined
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "DORM-IPSpoof-Probe/1.0")

	// Attach all spoof headers simultaneously
	for _, sh := range spoofHeaders {
		req.Header.Set(sh.Name, sh.Value)
	}

	// RULE 4: Ban sentinel
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	body := readBody(resp, 4096)
	lowerBody := strings.ToLower(body)

	isBlocked := false
	for _, sig := range wafBodySigs {
		if strings.Contains(lowerBody, sig) {
			isBlocked = true
			break
		}
	}

	if resp.StatusCode == 200 && !isBlocked {
		return &models.Vulnerability{
			Target:   target,
			Name:     "MEDIUM — Rate-Limit Bypassed via Compound Header Attack",
			Severity: "MEDIUM",
			CVSS:     5.8,
			Description: fmt.Sprintf(
				"🟡 MEDIUM: The rate-limit or WAF protection was bypassed when multiple IP spoof headers were sent simultaneously.\n\n"+
					"Technique: Compound Multi-Header Attack\n"+
					"Number of Headers Injected: %d\n"+
					"Target Endpoint: %s\n"+
					"HTTP Status After Bypass: %d\n\n"+
					"The server behaves inconsistently when multiple conflicting IP headers are present.\n"+
					"Ambiguity in header precedence parsing allows rate-limit counters to be reset\n"+
					"by an attacker who sends all known IP headers in a single request.",
				len(spoofHeaders), fullURL, resp.StatusCode,
			),
			Solution:  "When multiple IP-forwarding headers are present in a single request, reject the request or use only the server-side connection IP. Implement a strict, single-source-of-truth policy for the client IP used in rate-limiting decisions.",
			Reference: "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
		}
	}

	return nil
}
