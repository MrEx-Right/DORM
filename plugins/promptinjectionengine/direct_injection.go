package promptinjectionengine

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// candidateEndpoints — 15 hardcoded chatbot/LLM endpoint candidates.
var candidateEndpoints = []string{
	"/chat",
	"/api/chat",
	"/bot",
	"/ask",
	"/completion",
	"/api/completion",
	"/api/v1/chat/completions",
	"/prompt",
	"/ai",
	"/query",
	"/api/query",
	"/llm",
	"/gpt",
	"/assistant",
	"/api/assistant",
}

// htmlStripRe removes all HTML tags from the response body before grepping.
var htmlStripRe = regexp.MustCompile(`<[^>]*>`)

// wsCollapseRe collapses repeated whitespace after HTML stripping.
var wsCollapseRe = regexp.MustCompile(`\s+`)

// stripHTML removes HTML markup and normalises whitespace for reliable grepping.
func stripHTML(raw string) string {
	plain := htmlStripRe.ReplaceAllString(raw, " ")
	plain = wsCollapseRe.ReplaceAllString(plain, " ")
	return strings.TrimSpace(plain)
}

// containsFeedbackSignal scans the plain-text body for a compliance signal.
// canaryWords (DORM-controlled, near-zero false-positive risk) are checked
// first as a "high" confidence match; genericFeedbackWords (plain English
// phrases that could coincide with legitimate content) are checked only as
// a fallback "moderate" confidence match. Returns ("", "") if nothing matched.
func containsFeedbackSignal(body string) (matched string, confidence string) {
	lower := strings.ToLower(body)
	for _, word := range canaryWords {
		if strings.Contains(lower, strings.ToLower(word)) {
			return word, "high"
		}
	}
	for _, word := range genericFeedbackWords {
		if strings.Contains(lower, word) {
			return word, "moderate"
		}
	}
	return "", ""
}

// urlParamEncode performs minimal URL encoding for query parameters.
func urlParamEncode(str string) string {
	r := strings.NewReplacer(
		" ", "%20",
		"\"", "%22",
		"'", "%27",
		"\n", "%0A",
		"\r", "%0D",
		"{", "%7B",
		"}", "%7D",
		"[", "%5B",
		"]", "%5D",
		"<", "%3C",
		">", "%3E",
	)
	return r.Replace(str)
}

// RunDirectInjection is the GET-based candidate-endpoint fuzzing phase:
// for each live candidate endpoint, stuff every payload into 4 common
// chatbot query params at once and grep the response for a compliance signal.
func RunDirectInjection(client *http.Client, target models.ScanTarget, payloads []string) *models.Vulnerability {
	for _, endpoint := range candidateEndpoints {
		// Liveness check — skip endpoints that return 404
		checkReq, _ := http.NewRequest("GET", models.GetURL(target, endpoint), nil)
		checkResp, err := client.Do(checkReq)
		if err != nil {
			continue
		}
		liveStatus := checkResp.StatusCode
		_ = checkResp.Body.Close()
		if liveStatus == 404 {
			continue
		}

		for _, payload := range payloads {
			// Build GET URL (covers simple chatbot APIs and parameter-based bots)
			reqURL := models.GetURL(target, endpoint) +
				"?message=" + urlParamEncode(payload) +
				"&q=" + urlParamEncode(payload) +
				"&prompt=" + urlParamEncode(payload) +
				"&input=" + urlParamEncode(payload)

			req, _ := http.NewRequest("GET", reqURL, nil)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/plain, */*")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			// ── Body analysis — STATUS CODE IS IGNORED ──
			// Read the full response body regardless of HTTP status.
			rawBytes, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			plainText := stripHTML(string(rawBytes))

			if matched, confidence := containsFeedbackSignal(plainText); matched != "" {
				return &models.Vulnerability{
					Target:   target,
					Name:     "AI/LLM Prompt Injection",
					Severity: "HIGH",
					CVSS:     8.1,
					Description: fmt.Sprintf(
						"Prompt Injection vulnerability confirmed at endpoint '%s'.\n\n"+
							"Payload: %s\n\n"+
							"Feedback Signal Detected: \"%s\" (confidence: %s)\n\n"+
							"The server's AI/LLM model echoed back an instruction-compliance signal, "+
							"indicating that externally supplied user input successfully overrode the "+
							"system prompt or safety guardrails.",
						endpoint, payload, matched, confidence,
					),
					Solution:  "Implement strict input/output guardrails. Sanitize user input before it reaches the LLM context. Use a dedicated prompt firewall (e.g., Rebuff, Vigil) and apply output filtering to block compliance-signal leakage.",
					Reference: "OWASP Top 10 for LLMs 2025 - LLM01: Prompt Injection | MITRE ATLAS AML.T0051",
				}
			}
		}
	}

	return nil
}
