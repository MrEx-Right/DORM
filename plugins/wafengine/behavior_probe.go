package wafengine

import (
	"DORM/models"
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
	// fetch returns the status and body size of a GET, or ok=false.
	fetch := func(u string) (status, size int, ok bool) {
		resp, err := client.Get(u)
		if err != nil {
			return 0, 0, false
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		_ = resp.Body.Close()
		return resp.StatusCode, len(body), true
	}

	// Step 1: Baselines — one clean request per injection point. A probe is
	// compared with the same request carrying a harmless value, not with the
	// home page: a path that climbs above the web root gets nginx's own 400
	// and a missing file gets Apache's 404, both much smaller than the home
	// page, with or without an attack string in them.
	baseStatus, baseSize, ok := fetch(baseURL + "/")
	if !ok {
		return "", "", ""
	}
	queryStatus, querySize, ok := fetch(baseURL + "/?dorm_test=dormsafe")
	if !ok {
		queryStatus, querySize = baseStatus, baseSize
	}
	pathStatus, pathSize, ok := fetch(fmt.Sprintf("%s/%s", baseURL, url.PathEscape("../../dorm-safe/dormsafe")))
	if !ok {
		pathStatus, pathSize = baseStatus, baseSize
	}

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
			resp, err = client.Do(models.KeepUserAgent(req)) // the payload IS the User-Agent
		}

		if err != nil {
			continue
		}

		probeBody, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		_ = resp.Body.Close()
		probeStatus := resp.StatusCode
		probeSize := len(probeBody)

		ctlStatus, ctlSize := baseStatus, baseSize
		switch probe.Via {
		case "query":
			ctlStatus, ctlSize = queryStatus, querySize
		case "path":
			ctlStatus, ctlSize = pathStatus, pathSize
		}

		// Detect blocking behavior: only an answer the harmless control
		// did not get counts.
		isBlocked := false

		// Status code change (2xx/3xx → 403/406/429/503)
		if ctlStatus < 400 && (probeStatus == 403 || probeStatus == 406 || probeStatus == 429 || probeStatus == 503) {
			isBlocked = true
		}

		// Significant size reduction (WAF replaced page with block message)
		if ctlStatus < 400 && probeStatus >= 400 && probeSize < ctlSize/3 {
			isBlocked = true
		}

		if isBlocked {
			blockEvents = append(blockEvents, fmt.Sprintf("• %s → HTTP %d (harmless control: %d) — Size: %d vs %d",
				probe.Name, probeStatus, ctlStatus, probeSize, ctlSize))

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
