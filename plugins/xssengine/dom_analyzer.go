package xssengine

import (
	"DORM/models"
	"fmt"
	"regexp"
	"strings"
	"net/http"
)

// ============================================================
//  DOM XSS ANALYZER — Static JavaScript Bundle Analysis
//  Source→Sink taint tracking with multi-hop support
// ============================================================

// Precompile DOM XSS sink/source detection patterns
var (
	// Sources: things that read attacker-controlled input
	domXSSSourcePattern = regexp.MustCompile(
		`(?i)(location\.(hash|search|pathname|href)|document\.URL|document\.referrer|` +
			`window\.name|document\.cookie|localStorage\.|sessionStorage\.|` +
			`URLSearchParams|\.searchParams|postMessage|MessageEvent)`)

	// Sinks: dangerous functions/properties that can cause XSS
	domXSSSinkPattern = regexp.MustCompile(
		`(?i)(document\.write\s*\(|document\.writeln\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|` +
			`eval\s*\(|setTimeout\s*\(|setInterval\s*\(|new\s+Function\s*\(|` +
			`\.src\s*=|\.href\s*=|\.action\s*=|import\s*\(|` +
			`\.insertAdjacentHTML\s*\(|\.setAttribute\s*\(\s*["']on|` +
			`\$\s*\(\s*location|jQuery\s*\(\s*location|` +
			`\.html\s*\(|\.append\s*\(|\.prepend\s*\(|` +
			`\.after\s*\(|\.before\s*\(|\.replaceWith\s*\(|` +
			`\.wrap\s*\(|\.wrapAll\s*\(|` +
			`React\.createElement|dangerouslySetInnerHTML|` +
			`v-html|ng-bind-html)`)

	// JS file detection pattern
	jsFilePattern = regexp.MustCompile(`(?i)href=["']([^"']+\.js[^"']*?)["']|src=["']([^"']+\.js[^"']*?)["']`)

	// Variable assignment pattern for multi-hop tracking
	varAssignPattern = regexp.MustCompile(`(?i)\b(var|let|const)\s+(\w+)\s*=`)
)

// ScanDOMXSS fetches the target page, discovers JS files, and statically
// analyses them for unsafe source-to-sink data flows.
func ScanDOMXSS(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	// Step 1: Fetch root page to discover linked JS files
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	rootHTML := models.ReadBody(resp, 102400) // 100KB

	// Collect JS file URLs from the page
	jsURLs := extractJSURLs(rootHTML, baseURL)
	if len(jsURLs) == 0 {
		return nil
	}

	// Limit to first 15 JS files
	if len(jsURLs) > 15 {
		jsURLs = jsURLs[:15]
	}

	for _, jsURL := range jsURLs {
		resp2, err2 := client.Get(jsURL)
		if err2 != nil {
			continue
		}
		jsSource := models.ReadBody(resp2, 524288) // 512KB

		// Perform line-by-line source → sink analysis
		finding := analyzeJSForDOMXSS(jsSource, jsURL, target)
		if finding != nil {
			return finding
		}
	}

	return nil
}

// analyzeJSForDOMXSS performs static taint analysis on a JavaScript source.
func analyzeJSForDOMXSS(source, jsURL string, target models.ScanTarget) *models.Vulnerability {
	lines := strings.Split(source, "\n")

	// Phase 1: Direct source→sink on same line or nearby lines
	for i, line := range lines {
		sourceMatch := domXSSSourcePattern.FindString(line)
		if sourceMatch == "" {
			continue
		}

		// Check same line for a sink
		sinkMatch := domXSSSinkPattern.FindString(line)
		if sinkMatch != "" {
			snippet := strings.TrimSpace(line)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			return buildDOMXSSVuln(target, jsURL, sourceMatch, sinkMatch, i+1, snippet)
		}

		// Check surrounding lines (±5 lines) for proximity analysis
		startCtx := i - 5
		if startCtx < 0 {
			startCtx = 0
		}
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

	// Phase 2: Multi-hop taint tracking (variable assignment chain)
	taintedVars := make(map[string]int) // var name → line number

	for i, line := range lines {
		sourceMatch := domXSSSourcePattern.FindString(line)
		if sourceMatch != "" {
			// Check if the source is assigned to a variable
			varMatches := varAssignPattern.FindStringSubmatch(line)
			if len(varMatches) >= 3 {
				taintedVars[varMatches[2]] = i
			}
		}
	}

	// Check if any tainted variable flows into a sink
	for varName, sourceLine := range taintedVars {
		for i, line := range lines {
			if i <= sourceLine {
				continue
			}
			if strings.Contains(line, varName) {
				sinkMatch := domXSSSinkPattern.FindString(line)
				if sinkMatch != "" {
					snippet := fmt.Sprintf("Source (line %d): %s\n... flows to ...\nSink (line %d): %s",
						sourceLine+1, strings.TrimSpace(lines[sourceLine]),
						i+1, strings.TrimSpace(line))
					if len(snippet) > 400 {
						snippet = snippet[:400] + "..."
					}
					return &models.Vulnerability{
						Target:   target,
						Name:     "DOM XSS — Multi-Hop Taint Flow (Static Analysis)",
						Severity: "HIGH",
						CVSS:     7.5,
						Description: fmt.Sprintf(
							"Static analysis detected a multi-hop taint flow from attacker-controlled source through variable '%s' to a dangerous sink.\n\n"+
								"📄 File: %s\n"+
								"🔴 Tainted Variable: %s\n"+
								"🎯 Sink: %s\n\n"+
								"Data Flow:\n%s",
							varName, jsURL, varName, sinkMatch, snippet,
						),
						Solution:  "Never pass user-controlled input through variables to DOM manipulation functions. Use textContent instead of innerHTML.",
						Reference: "https://owasp.org/www-community/attacks/DOM_Based_XSS",
					}
				}
			}
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
