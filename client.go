package main

import (
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// ==========================================
// CLIENT & MIDDLEWARE LOGIC (AUTH & EVASION)
// ==========================================

// Global Variables (Controlled by main.go/handleScan)
var GlobalRotateUA bool = false
var GlobalAuthHeader string = ""

// User Agent List
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// --- PROXY MIDDLEWARE (The Brain) ---
type UARoundTripper struct {
	Proxied http.RoundTripper
}

func (urt *UARoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. User-Agent Rotation (Bukalemun)
	if GlobalRotateUA {
		req.Header.Set("User-Agent", getRandomUserAgent())
	}

	// 2. Auth Injection (Cookie/Token)
	if GlobalAuthHeader != "" {
		// "Cookie: SESSID=..." şeklinde gelen veriyi böler
		parts := strings.SplitN(GlobalAuthHeader, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			req.Header.Set(key, val)
		}
	}

	return urt.Proxied.RoundTrip(req)
}

// Client Helper (Used by Plugins)
func getClient() *http.Client {
	return &http.Client{
		Transport: &UARoundTripper{Proxied: http.DefaultTransport},
		Timeout:   10 * time.Second,
	}
}
