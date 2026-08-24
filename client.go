package main

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"DORM/bypassers"
)

// ==========================================
// CLIENT & MIDDLEWARE LOGIC (AUTH & EVASION)
// ==========================================

var (
	activeClient   *http.Client
	activeClientMu sync.RWMutex
)

// SetActiveClient creates a brand new HTTP client with isolated proxy and auth settings for the current scan.
func SetActiveClient(auth string, proxyEnabled bool, proxyURLStr string) {
	var proxyFunc func(*http.Request) (*url.URL, error) = nil

	if proxyEnabled {
		if proxyURLStr == "" {
			proxyURLStr = "http://127.0.0.1:8080"
		}
		proxyURL, err := url.Parse(proxyURLStr)
		if err == nil {
			proxyFunc = http.ProxyURL(proxyURL)
		}
	}

	customTransport := &http.Transport{
		Proxy: proxyFunc,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Always skip verify for intercepts
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	client := &http.Client{
		Transport: &UARoundTripper{
			Proxied:    customTransport,
			AuthHeader: auth,
		},
		Timeout: 10 * time.Second,
	}

	activeClientMu.Lock()
	activeClient = client
	activeClientMu.Unlock()
}

// --- PROXY MIDDLEWARE (The Brain) ---
type UARoundTripper struct {
	Proxied    http.RoundTripper
	AuthHeader string
}

func (urt *UARoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. User-Agent Rotation (Bukalemun)
	// Always enabled now as part of Stealth module
	req.Header.Set("User-Agent", bypassers.GetRandomUserAgent())

	// 2. Auth Injection (Cookie/Token)
	if urt.AuthHeader != "" {
		// Splits the incoming data formatted as "Cookie: SESSID=..."
		parts := strings.SplitN(urt.AuthHeader, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			req.Header.Set(key, val)
		}
	}

	// 3. WAF Rate Limiting / Jitter Bypass
	bypassers.Sleep()

	return urt.Proxied.RoundTrip(req)
}

// Client Helper (Used by Plugins)
func getClient() *http.Client {
	activeClientMu.RLock()
	defer activeClientMu.RUnlock()
	
	if activeClient == nil {
		// Fallback for background tasks running outside an active scan (if any)
		return &http.Client{Timeout: 10 * time.Second}
	}
	
	return activeClient
}
