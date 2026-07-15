package bypassers

import (
	"net/url"
)

// DoubleURLEncode takes a plaintext payload (e.g., "<script>") and encodes it twice.
// Step 1: "<script>" -> "%3Cscript%3E"
// Step 2: "%3Cscript%3E" -> "%253Cscript%253E"
// 
// This is used to bypass WAFs that only decode input once before inspection,
// allowing the actual backend application to decode it the second time and execute the payload.
func DoubleURLEncode(payload string) string {
	if payload == "" {
		return ""
	}

	// First pass encoding (Standard URL Encode)
	firstPass := url.QueryEscape(payload)

	// Second pass encoding
	secondPass := url.QueryEscape(firstPass)

	return secondPass
}
