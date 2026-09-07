package bflaengine

import (
	"io"
	"net/http"
	"strings"
)

// NewBFLARequest creates an HTTP request with an Authorization header
// normalized to either a passthrough scheme (Bearer/Basic already present
// in token) or a Bearer-wrapped token.
func NewBFLARequest(method, url, token string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DORM-BFLA-Probe/1.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		if strings.HasPrefix(strings.ToLower(token), "bearer ") || strings.HasPrefix(token, "Basic ") {
			req.Header.Set("Authorization", token)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	return req, nil
}

// ContainsSoftError detects cases where the server returns HTTP 200 but the
// response body indicates the operation was actually denied.
func ContainsSoftError(body string) bool {
	lower := strings.ToLower(body)
	for _, se := range SoftErrors {
		if strings.Contains(lower, se) {
			return true
		}
	}
	return false
}

// ContainsSensitiveAdminData checks whether a response body contains at
// least two admin-specific data keywords, reducing false positives.
func ContainsSensitiveAdminData(body string) bool {
	lower := strings.ToLower(body)
	adminKeywords := []string{
		"user_list", "users", "\"role\"", "\"admin\"", "\"permissions\"",
		"\"email\"", "\"password\"", "audit_log", "\"config\"",
		"\"settings\"", "system", "\"token\"", "\"secret\"",
	}
	count := 0
	for _, kw := range adminKeywords {
		if strings.Contains(lower, kw) {
			count++
		}
	}
	return count >= 2 // Require at least 2 admin keywords to reduce false positives
}
