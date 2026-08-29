package wafengine

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ============================================================
//  HEADER ANALYZER — Passive WAF detection via HTTP headers
// ============================================================

// AnalyzeHeaders performs passive WAF detection by examining response headers,
// cookies, and body content against the WAF signature database.
func AnalyzeHeaders(client *http.Client, baseURL string) (wafName, confidence, details string) {
	// Send a clean request first to get baseline headers
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		return "", "", ""
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(bodyBytes)
	bodyLower := strings.ToLower(bodyStr)

	var matchDetails []string
	bestScore := 0
	bestWAF := ""

	for _, sig := range WAFSignatures {
		score := 0

		// Check headers
		for _, hp := range sig.HeaderPatterns {
			headerVal := resp.Header.Get(hp.Header)
			if headerVal == "" {
				continue
			}
			if hp.Value == "" {
				// Header existence is enough
				score += 2
				matchDetails = append(matchDetails, fmt.Sprintf("Header '%s' present: %s", hp.Header, headerVal))
			} else if strings.Contains(strings.ToLower(headerVal), strings.ToLower(hp.Value)) {
				score += 3
				matchDetails = append(matchDetails, fmt.Sprintf("Header '%s' matches '%s': %s", hp.Header, hp.Value, headerVal))
			}
		}

		// Check cookies
		for _, cookie := range resp.Cookies() {
			for _, cp := range sig.CookiePatterns {
				if strings.Contains(strings.ToLower(cookie.Name), strings.ToLower(cp)) {
					score += 3
					matchDetails = append(matchDetails, fmt.Sprintf("Cookie matches '%s': %s", cp, cookie.Name))
				}
			}
		}

		// Check body content
		for _, bp := range sig.BodyPatterns {
			if strings.Contains(bodyLower, strings.ToLower(bp)) {
				score += 2
				matchDetails = append(matchDetails, fmt.Sprintf("Body contains WAF signature: '%s'", bp))
			}
		}

		if score > bestScore {
			bestScore = score
			bestWAF = sig.Name
		}
	}

	if bestScore == 0 {
		return "", "", ""
	}

	// Determine confidence level based on score
	switch {
	case bestScore >= 6:
		confidence = "HIGH"
	case bestScore >= 3:
		confidence = "MEDIUM"
	default:
		confidence = "LOW"
	}

	return bestWAF, confidence, strings.Join(matchDetails, "\n")
}

// AnalyzeBlockPage examines a response that might be a WAF block page.
func AnalyzeBlockPage(resp *http.Response, body string) (wafName string, isBlock bool) {
	if resp.StatusCode != 403 && resp.StatusCode != 406 && resp.StatusCode != 429 && resp.StatusCode != 503 {
		return "", false
	}

	bodyLower := strings.ToLower(body)

	for _, sig := range WAFSignatures {
		// Check if the status code matches
		statusMatch := false
		for _, sc := range sig.StatusCodes {
			if resp.StatusCode == sc {
				statusMatch = true
				break
			}
		}
		if !statusMatch {
			continue
		}

		// Check body patterns for block page signatures
		for _, bp := range sig.BodyPatterns {
			if strings.Contains(bodyLower, strings.ToLower(bp)) {
				return sig.Name, true
			}
		}

		// Check headers on the block response
		for _, hp := range sig.HeaderPatterns {
			headerVal := resp.Header.Get(hp.Header)
			if headerVal != "" {
				if hp.Value == "" || strings.Contains(strings.ToLower(headerVal), strings.ToLower(hp.Value)) {
					return sig.Name, true
				}
			}
		}
	}

	return "", false
}
