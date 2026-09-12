package plugins

import (
	"DORM/models"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// ==================================================
// WEB CACHE DECEPTION (WCD)
// Distinct from Web Cache Poisoning (unkeyed-header reflection): here the
// CDN/reverse-proxy is tricked into caching a dynamic/authenticated path by
// appending a fake static-looking extension, and an anonymous request to
// the same normalized cache key then reads the cached dynamic content.
// ==================================================
type WCDPlugin struct{}

func (p *WCDPlugin) Name() string { return "Web Cache Deception" }

var wcdBasePaths = []string{
	"/api/user/profile", "/account/settings", "/dashboard/info", "/user/me", "/api/v1/profile", "/settings",
}

var wcdSuffixes = []func(string) string{
	func(p string) string { return p + "/test.css" },
	func(p string) string { return p + "/test.js" },
	func(p string) string { return p + ";.css" },
	func(p string) string { return p + "%0a.png" },
	func(p string) string { return p + "#test.css" },
	func(p string) string { return p + "/nonexistent.css" },
}

func (p *WCDPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	baseURL := getURL(target, "")
	authedClient := models.GetClient()
	anonClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	for _, basePath := range wcdBasePaths {
		// Baseline: what does the real dynamic path actually return?
		baselineResp, err := authedClient.Get(baseURL + basePath)
		if err != nil {
			continue
		}
		baselineBody := readBody(baselineResp, 32768)
		if len(baselineBody) < 20 {
			continue // too small/empty to be a meaningful fingerprint
		}

		// Negative control: if a guaranteed-nonexistent path returns the
		// exact same content as our "dynamic" basePath, this server has no
		// real per-path differentiation (e.g. everything falls through to a
		// catch-all router/page) — basePath isn't a meaningful WCD candidate,
		// so skip it rather than risk a false positive.
		bogusPath := fmt.Sprintf("/dorm-nonexistent-%d-xyz", time.Now().UnixNano())
		if controlResp, err := authedClient.Get(baseURL + bogusPath); err == nil {
			if readBody(controlResp, 32768) == baselineBody {
				continue
			}
		}

		for _, suffixFn := range wcdSuffixes {
			crafted := suffixFn(basePath)
			cacheBuster := fmt.Sprintf("?dormcb=%d", time.Now().UnixNano())
			fullURL := baseURL + crafted + cacheBuster

			// Request A: "victim" visits the deceptive, cacheable-looking URL.
			reqA, _ := http.NewRequest("GET", fullURL, nil)
			respA, err := authedClient.Do(reqA)
			if err != nil {
				continue
			}
			bodyA := readBody(respA, 32768)
			if bodyA != baselineBody {
				continue // backend did NOT collapse the fake extension onto the real route
			}

			// Request B: same cache-busted URL, but a bare anonymous client —
			// no auth header, no cookies.
			reqB, _ := http.NewRequest("GET", fullURL, nil)
			respB, err := anonClient.Do(reqB)
			if err != nil {
				continue
			}
			bodyB := readBody(respB, 32768)
			if bodyB != baselineBody {
				continue // anonymous request did not receive the same dynamic content
			}

			isCached := false
			cacheEvidence := ""
			for _, ch := range []string{"X-Cache", "CF-Cache-Status", "X-Varnish", "Age"} {
				if val := respB.Header.Get(ch); val != "" {
					isCached = true
					cacheEvidence = fmt.Sprintf("%s: %s", ch, val)
					break
				}
			}

			severity := "HIGH"
			cvss := 8.1
			desc := fmt.Sprintf(
				"Web Cache Deception confirmed.\nDynamic path: %s\nDeceptive URL: %s\n\nThe backend routed the fake-static-extension URL to the exact same content as the real dynamic path, and an anonymous request (no auth/cookie header) to that same URL received identical content.",
				basePath, crafted,
			)
			if isCached {
				desc += fmt.Sprintf("\n\nConfirmation: explicit cache header found on the anonymous response -> %s", cacheEvidence)
				severity = "CRITICAL"
				cvss = 9.2
			} else {
				desc += "\n\nNote: no explicit CDN cache header found on this response, but the routing-collision behavior itself was confirmed via a 3-way baseline/authenticated/anonymous comparison."
			}

			return &models.Vulnerability{
				Target:      target,
				Name:        "Web Cache Deception",
				Severity:    severity,
				CVSS:        cvss,
				Description: desc,
				Solution:    "Configure the cache/CDN to key on the full request path (including query string), not just the file extension, and explicitly exclude dynamic/authenticated routes from caching. Ensure the backend rejects or 404s requests where a static-looking segment is appended to a dynamic route rather than silently routing them the same.",
				Reference:   "PortSwigger: Web Cache Deception / CWE-524",
			}
		}
	}

	return nil
}
