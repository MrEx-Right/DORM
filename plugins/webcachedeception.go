package plugins

import (
	"DORM/models"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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

// cacheHitEvidence returns the response header that shows it was served from
// a cache. The header merely being present is not enough: "X-Cache: Miss from
// cloudfront" or "Age: 0" says the opposite.
func cacheHitEvidence(h http.Header) string {
	for _, name := range []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status", "X-Proxy-Cache"} {
		if v := h.Get(name); strings.Contains(strings.ToLower(v), "hit") {
			return name + ": " + v
		}
	}
	if age, err := strconv.Atoi(strings.TrimSpace(h.Get("Age"))); err == nil && age > 0 {
		return fmt.Sprintf("Age: %d", age)
	}
	if v := h.Get("X-Varnish"); len(strings.Fields(v)) >= 2 { // "<this req> <cached req>"
		return "X-Varnish: " + v
	}
	return ""
}

// Run needs content that differs per user. The scan's auth header makes the
// "victim" request; a client without it is the attacker. If the attacker
// already sees the same page on the real path, nothing private can leak
// through the cache — that was the 2026-10-22 dynatrace.com FP: a public
// page, no auth configured, and "authed" and "anonymous" were the same request.
func (p *WCDPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	baseURL := getURL(target, "")
	// Neither client follows redirects: a dynamic path that sends the
	// anonymous user to /login must not be compared as the login page.
	authedClient := models.NoRedirectClient()
	anonClient := &http.Client{ // no scan auth header, same route and persona
		Timeout:       10 * time.Second,
		Transport:     models.GetScanTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	get := func(c *http.Client, u string) (int, http.Header, string, bool) {
		resp, err := c.Get(u)
		if err != nil {
			return 0, nil, "", false
		}
		return resp.StatusCode, resp.Header, readBody(resp, 32768), true
	}

	for _, basePath := range wcdBasePaths {
		// Baseline: what does the real dynamic path return to the victim?
		status, _, baselineBody, ok := get(authedClient, baseURL+basePath)
		if !ok || status != http.StatusOK || len(baselineBody) < 20 {
			continue
		}

		// The attacker must not already see it on the real path.
		if _, _, anonBody, ok := get(anonClient, baseURL+basePath); !ok || anonBody == baselineBody {
			continue
		}

		// Negative control: if a guaranteed-nonexistent path returns the
		// exact same content as our "dynamic" basePath, this server has no
		// real per-path differentiation (e.g. everything falls through to a
		// catch-all router/page) — basePath isn't a meaningful WCD candidate.
		bogusPath := fmt.Sprintf("/dorm-nonexistent-%d-xyz", time.Now().UnixNano())
		if _, _, controlBody, ok := get(authedClient, baseURL+bogusPath); ok && controlBody == baselineBody {
			continue
		}

		for _, suffixFn := range wcdSuffixes {
			crafted := suffixFn(basePath)
			cacheBuster := fmt.Sprintf("?dormcb=%d", time.Now().UnixNano())
			fullURL := baseURL + crafted + cacheBuster

			// Request A: the victim visits the deceptive, cacheable-looking URL.
			statusA, _, bodyA, ok := get(authedClient, fullURL)
			if !ok || statusA != http.StatusOK || bodyA != baselineBody {
				continue // backend did NOT collapse the fake extension onto the real route
			}

			// Request B: the attacker requests the same cache-busted URL.
			statusB, headersB, bodyB, ok := get(anonClient, fullURL)
			if !ok || statusB != http.StatusOK || bodyB != baselineBody {
				continue // the victim's page was not served to the attacker
			}

			severity, cvss := "HIGH", 8.1
			desc := fmt.Sprintf(
				"Web Cache Deception confirmed.\nDynamic path: %s\nDeceptive URL: %s\n\nThe authenticated page differs from what an unauthenticated client gets on the real path, yet after the authenticated request to the deceptive URL, an unauthenticated request to that same URL received the authenticated page.",
				basePath, crafted,
			)
			if evidence := cacheHitEvidence(headersB); evidence != "" {
				desc += "\n\nCache hit on the unauthenticated response -> " + evidence
				severity, cvss = "CRITICAL", 9.2
			} else {
				desc += "\n\nNo cache-hit header on the unauthenticated response; the leak itself was observed."
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
