package wafengine

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ============================================================
//  BEHAVIOR PROBE — Active WAF detection via malicious payloads
// ============================================================

// BehaviorProbe sends known-malicious payloads and analyzes the response
// to determine if a WAF is actively blocking requests.
func BehaviorProbe(client *http.Client, baseURL string) (wafName, confidence, details string) {
	// Step 1: Baseline — clean request
	baseResp, err := client.Get(baseURL + "/")
	if err != nil {
		return "", "", ""
	}
	baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 32768))
	baseResp.Body.Close()
	baseStatus := baseResp.StatusCode
	baseSize := len(baseBody)

	// Step 2: Send a series of malicious probes
	probes := []struct {
		Name    string
		Payload string
		Via     string // "query", "path", "header"
	}{
		// XSS probe
		{"XSS Probe", `<script>alert(1)</script>`, "query"},
		// SQLi probe
		{"SQLi Probe", `' OR 1=1 --`, "query"},
		// Path traversal probe
		{"Path Traversal", `../../etc/passwd`, "path"},
		// Command injection probe
		{"CMDi Probe", `; cat /etc/passwd`, "query"},
		// User-Agent header probe
		{"UA SQLi Probe", `' OR '1'='1`, "header"},
		// Protocol attack probe
		{"Protocol Attack", `%00<script>alert(1)</script>`, "query"},
	}

	var blockEvents []string

	for _, probe := range probes {
		var resp *http.Response
		var err error

		switch probe.Via {
		case "query":
			probeURL := fmt.Sprintf("%s/?dorm_test=%s", baseURL, url.QueryEscape(probe.Payload))
			resp, err = client.Get(probeURL)

		case "path":
			probeURL := fmt.Sprintf("%s/%s", baseURL, url.PathEscape(probe.Payload))
			resp, err = client.Get(probeURL)

		case "header":
			req, reqErr := http.NewRequest("GET", baseURL+"/", nil)
			if reqErr != nil {
				continue
			}
			req.Header.Set("User-Agent", probe.Payload)
			resp, err = client.Do(req)
		}

		if err != nil {
			continue
		}

		probeBody, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()
		probeStatus := resp.StatusCode
		probeSize := len(probeBody)

		// Detect blocking behavior
		isBlocked := false

		// Status code change (200 → 403/406/429/503)
		if baseStatus == 200 && (probeStatus == 403 || probeStatus == 406 || probeStatus == 429 || probeStatus == 503) {
			isBlocked = true
		}

		// Significant size reduction (WAF replaced page with block message)
		if probeSize < baseSize/3 && probeStatus >= 400 {
			isBlocked = true
		}

		if isBlocked {
			blockEvents = append(blockEvents, fmt.Sprintf("• %s → HTTP %d (baseline: %d) — Size: %d vs %d",
				probe.Name, probeStatus, baseStatus, probeSize, baseSize))

			// Try to identify the specific WAF from the block page
			detectedWAF, _ := AnalyzeBlockPage(resp, string(probeBody))
			if detectedWAF != "" {
				wafName = detectedWAF
			}
		}
	}

	if len(blockEvents) == 0 {
		return "", "", ""
	}

	detailStr := strings.Join(blockEvents, "\n")

	if wafName == "" {
		wafName = "Unknown WAF (Behavioral Detection)"
	}

	// Confidence based on how many probes were blocked
	switch {
	case len(blockEvents) >= 4:
		confidence = "HIGH"
	case len(blockEvents) >= 2:
		confidence = "MEDIUM"
	default:
		confidence = "LOW"
	}

	return wafName, confidence, detailStr
}
