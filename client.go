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

// Global Variables (Controlled by main.go/handleScan)

var GlobalAuthHeader string = ""
var GlobalProxyEnabled bool = false
var GlobalProxyURL string = "http://127.0.0.1:8080"

var (
	baseTransport http.RoundTripper
	transportOnce sync.Once
)

// InitTransport updates the global baseTransport, avoiding race conditions and connection pool exhaustion
func InitTransport() {
	var proxyFunc func(*http.Request) (*url.URL, error) = nil

	if GlobalProxyEnabled {
		// Parse proxy
		proxyURL, err := url.Parse(GlobalProxyURL)
		if err != nil || GlobalProxyURL == "" {
			// Fallback to default if somehow broken
			proxyURL, _ = url.Parse("http://127.0.0.1:8080")
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}

	// Create custom transport with Proxy and disabled TLS verify (useful for intercepts)
	customTransport := &http.Transport{
		Proxy: proxyFunc,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Always skip verify for intercepts
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	baseTransport = customTransport
}



// --- PROXY MIDDLEWARE (The Brain) ---
type UARoundTripper struct {
	Proxied http.RoundTripper
}

func (urt *UARoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. User-Agent Rotation (Bukalemun)
	// Always enabled now as part of Stealth module
	req.Header.Set("User-Agent", bypassers.GetRandomUserAgent())

	// 2. Auth Injection (Cookie/Token)
	if GlobalAuthHeader != "" {
		// Splits the incoming data formatted as "Cookie: SESSID=..."
		parts := strings.SplitN(GlobalAuthHeader, ":", 2)
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
	// Fallback in case InitTransport wasn't called yet
	if baseTransport == nil {
		InitTransport()
	}

	return &http.Client{
		Transport: &UARoundTripper{Proxied: baseTransport},
		Timeout:   10 * time.Second,
	}
}
