package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"DORM/bypassers"
	"DORM/models"
)

// ==========================================
// CLIENT & MIDDLEWARE LOGIC (AUTH & EVASION)
// ==========================================

var (
	activeClient    *http.Client
	activeAnonRT    http.RoundTripper // same transport as activeClient, without the auth header
	activeTransport *http.Transport   // kept so Traffic Morph's NEW IDENTITY can drop pooled connections
	activeProxyURL  string            // the route's proxy for non-Go clients (headless Chrome); "" = direct
	activeBgRT      http.RoundTripper // same route, never closed, not counted as scan traffic
	activeClosed    *atomic.Bool      // set when the scan that owns activeClient ends
	activeClientMu  sync.RWMutex

	// fallbackClient serves requests made before any scan built a client
	// (Spider page, SCI, background tasks): direct route, but still the
	// Traffic Morph User-Agent instead of Go-http-client/1.1.
	fallbackOnce   sync.Once
	fallbackClient *http.Client
	fallbackAnonRT http.RoundTripper
)

// newScanTransport builds the transport every scan request goes through.
// Traffic Morph reuses it (TLS fingerprint probe, egress check) so what the
// panel measures is exactly what a target sees.
//
// The dial and TLS handshake have their own timeouts, shorter than the
// clients' 10 s, and a host gets at most as many connections as the idle
// pool keeps for it. Without a dial timeout, a target that stopped
// answering SYNs left each request's dial running after its client gave up
// (until the OS connect timeout), so every retry added another; and with no
// per-host cap, a burst past the idle pool opened connections that were
// closed after one request.
func newScanTransport(proxyFunc func(*http.Request) (*url.URL, error)) *http.Transport {
	return &http.Transport{
		Proxy: proxyFunc,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Always skip verify for intercepts
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: scanConnsPerHost,
		MaxConnsPerHost:     scanConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
	}
}

// scanConnsPerHost is the most connections the scan keeps open to one host.
const scanConnsPerHost = 100

// scanProxyFunc resolves the UI's proxy settings into a Transport.Proxy func.
// SOCKS5 proxies without their own credentials get the current Traffic Morph
// isolation credentials, read per request, so a NEW IDENTITY mid-scan takes
// effect on the next connection (Tor's IsolateSOCKSAuth builds a new circuit
// for new SOCKS credentials).
func scanProxyFunc(proxyEnabled bool, proxyURLStr string) func(*http.Request) (*url.URL, error) {
	if !proxyEnabled {
		return nil
	}
	if proxyURLStr == "" {
		proxyURLStr = defaultProxyURL
	}
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil
	}
	if !isSOCKSProxy(proxyURL) || proxyURL.User != nil {
		return http.ProxyURL(proxyURL)
	}
	return func(*http.Request) (*url.URL, error) {
		u := *proxyURL
		u.User = url.UserPassword("dorm", morphIsolationToken())
		return &u, nil
	}
}

// defaultProxyURL is the built-in analyzer (analyzer.StartAnalyzer("8081")),
// the same default the dashboard's Proxy Settings use.
const defaultProxyURL = "http://127.0.0.1:" + morphAnalyzerPort

// errScanClosed is what a finished scan's client returns instead of sending.
// ScannerPlugin.Run has no context, so the engine abandons a plugin that
// outlives pluginTimeout (and every plugin still running at STOP) and moves
// on; those goroutines used to keep scanning the target after DONE — minutes
// of traffic, visible in Traffic Morph. Refusing their requests makes them
// fall through their loops and exit.
var errScanClosed = errors.New("dorm: scan has ended, request not sent")

// SetActiveClient creates a brand new HTTP client with isolated proxy and auth
// settings for the current scan. The returned endScan closes it: call it when
// the scan finishes or is stopped.
func SetActiveClient(auth string, proxyEnabled bool, proxyURLStr string) (endScan func()) {
	proxyFunc := scanProxyFunc(proxyEnabled, proxyURLStr)
	customTransport := newScanTransport(proxyFunc)
	closed := new(atomic.Bool)

	client := &http.Client{
		Transport: &UARoundTripper{
			Proxied:    customTransport,
			AuthHeader: auth,
			ViaProxy:   proxyFunc != nil,
			Closed:     closed,
		},
		Timeout: 10 * time.Second,
	}
	anon := &UARoundTripper{Proxied: customTransport, ViaProxy: proxyFunc != nil, Closed: closed}
	bg := &UARoundTripper{Proxied: customTransport, ViaProxy: proxyFunc != nil, Background: true}

	proxyURL := ""
	if proxyFunc != nil {
		proxyURL = proxyURLStr
		if proxyURL == "" {
			proxyURL = defaultProxyURL
		}
	}

	activeClientMu.Lock()
	if activeClosed != nil {
		activeClosed.Store(true) // a new scan replaces (and has cancelled) the previous one
	}
	activeClient = client
	activeAnonRT = anon
	activeBgRT = bg
	activeTransport = customTransport
	activeProxyURL = proxyURL
	activeClosed = closed
	activeClientMu.Unlock()

	morphScanStarted(proxyEnabled && proxyFunc != nil, proxyURLStr)

	// The closed client stays the active one until the next scan: plugins
	// that call models.GetClient() per request must get the refusing client,
	// not a working fallback. Out-of-scan callers use the background route.
	return func() {
		if closed.CompareAndSwap(false, true) {
			customTransport.CloseIdleConnections()
		}
	}
}

// --- PROXY MIDDLEWARE (The Brain) ---
type UARoundTripper struct {
	Proxied    http.RoundTripper
	AuthHeader string
	ViaProxy   bool         // for Traffic Morph telemetry only
	Closed     *atomic.Bool // the owning scan has ended: refuse (nil = never)
	Background bool         // not scan traffic: not counted in Traffic Morph
}

func (urt *UARoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if urt.Closed != nil && urt.Closed.Load() {
		return nil, errScanClosed
	}

	// 1. WAF Rate Limiting / Jitter Bypass — first, so the identity below is
	// picked at send time: a NEW IDENTITY during the delay applies to this request.
	bypassers.Sleep()
	if urt.Closed != nil && urt.Closed.Load() { // the scan ended during the delay
		return nil, errScanClosed
	}

	// 2. User-Agent Rotation (Bukalemun)
	// Controlled by the Traffic Morph switch (off at launch: one fixed DORM
	// User-Agent). On, per-request rotation or one sticky persona per identity.
	// A request whose User-Agent is the test payload itself keeps it.
	ua := req.Header.Get("User-Agent")
	if !models.UserAgentKept(req) {
		ua = morphUserAgent()
		req.Header.Set("User-Agent", ua)
	}

	// 3. Auth Injection (Cookie/Token)
	if urt.AuthHeader != "" {
		// Splits the incoming data formatted as "Cookie: SESSID=..."
		parts := strings.SplitN(urt.AuthHeader, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			req.Header.Set(key, val)
		}
	}

	if !urt.Background {
		morphRecordRequest(ua, urt.ViaProxy, req.URL.Hostname())
	}

	return urt.Proxied.RoundTrip(req)
}

func initFallbackClient() {
	fallbackOnce.Do(func() {
		t := newScanTransport(nil)
		fallbackAnonRT = &UARoundTripper{Proxied: t, Background: true}
		fallbackClient = &http.Client{Transport: fallbackAnonRT, Timeout: 10 * time.Second}
	})
}

// Client Helper (Used by Plugins)
func getClient() *http.Client {
	activeClientMu.RLock()
	c := activeClient
	activeClientMu.RUnlock()

	if c == nil {
		// Fallback for background tasks running outside an active scan (if any)
		initFallbackClient()
		return fallbackClient
	}

	return c
}

// scanRoundTripper backs models.GetScanTransport, which calls it on every
// request: the current scan route without the auth header, or the direct
// persona fallback before any scan has run.
func scanRoundTripper() http.RoundTripper {
	activeClientMu.RLock()
	rt := activeAnonRT
	activeClientMu.RUnlock()
	if rt == nil {
		initFallbackClient()
		rt = fallbackAnonRT
	}
	return rt
}

// backgroundRoundTripper backs models.BackgroundRoundTripper: the last scan's
// route without its lifetime, or the direct persona fallback before any scan.
func backgroundRoundTripper() http.RoundTripper {
	activeClientMu.RLock()
	rt := activeBgRT
	activeClientMu.RUnlock()
	if rt == nil {
		initFallbackClient()
		rt = fallbackAnonRT
	}
	return rt
}

func getScanProxyURL() string {
	activeClientMu.RLock()
	defer activeClientMu.RUnlock()
	return activeProxyURL
}
