package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"DORM/bypassers"
)

// ==========================================
// TRAFFIC MORPH — live OpSec / identity panel
// ==========================================
//
// Shows how DORM looks from the target's side: which route the scan client
// leaves through, the TLS ClientHello it sends (JA3/JA4, measured from the
// real scan transport, not a hard-coded value), the User-Agent persona and
// the live request flow. NEW IDENTITY drops pooled connections and, on SOCKS
// routes, switches the isolation credentials so Tor builds a new circuit.
//
// The panel always reports; the morphing itself (User-Agent persona rotation,
// NEW IDENTITY) is behind an on/off switch that starts OFF on every launch.
// Off, every request carries morphPlainUA.

const morphAnalyzerPort = "8081" // analyzer.StartAnalyzer("8081") in main.go

// morphPlainUA is the User-Agent while Traffic Morph is off: one fixed,
// self-identifying value instead of a browser persona.
const morphPlainUA = "Mozilla/5.0 (compatible; DORM-Security-Scanner/1.29)"

var morph = struct {
	mu sync.Mutex

	enabled bool // persona rotation + NEW IDENTITY; off at every launch

	// identity
	generation     int
	isolationToken string
	identitySince  time.Time
	personaMode    string // "rotate" (per request, default) | "sticky" (one UA per identity)
	stickyUA       string

	// route of the most recent scan client (SetActiveClient)
	routeSet          bool
	routeProxyEnabled bool
	routeProxyURL     string
	scanSince         time.Time

	// telemetry since the last scan client was built
	total, proxied uint64
	uaCounts       map[string]uint64
	lastUA         string
	lastAt         time.Time
	hosts          map[string]struct{}
	buckets        [10]morphBucket

	lastEgress *morphEgress
}{
	isolationToken: newMorphToken(),
	identitySince:  time.Now(),
	personaMode:    "rotate",
	uaCounts:       map[string]uint64{},
	hosts:          map[string]struct{}{},
}

type morphBucket struct {
	sec int64
	n   uint64
}

func newMorphToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func morphIsolationToken() string {
	morph.mu.Lock()
	defer morph.mu.Unlock()
	return morph.isolationToken
}

// morphUserAgent picks the User-Agent for one scan request. It is read per
// request, so switching Traffic Morph on or off mid-scan applies to the next one.
func morphUserAgent() string {
	morph.mu.Lock()
	defer morph.mu.Unlock()
	if !morph.enabled {
		return morphPlainUA
	}
	if morph.personaMode == "sticky" {
		if morph.stickyUA == "" {
			morph.stickyUA = bypassers.GetRandomUserAgent()
		}
		return morph.stickyUA
	}
	return bypassers.GetRandomUserAgent()
}

func morphScanStarted(viaProxy bool, proxyURL string) {
	morph.mu.Lock()
	defer morph.mu.Unlock()
	morph.routeSet = true
	morph.routeProxyEnabled = viaProxy
	morph.routeProxyURL = proxyURL
	morph.scanSince = time.Now()
	morph.total, morph.proxied = 0, 0
	morph.uaCounts = map[string]uint64{}
	morph.lastUA = ""
	morph.lastAt = time.Time{}
	morph.hosts = map[string]struct{}{}
	morph.buckets = [10]morphBucket{}
}

func morphRecordRequest(ua string, viaProxy bool, host string) {
	now := time.Now()
	morph.mu.Lock()
	defer morph.mu.Unlock()
	morph.total++
	if viaProxy {
		morph.proxied++
	}
	morph.uaCounts[ua]++
	morph.lastUA = ua
	morph.lastAt = now
	if len(morph.hosts) < 10000 {
		morph.hosts[host] = struct{}{}
	}
	sec := now.Unix()
	b := &morph.buckets[sec%int64(len(morph.buckets))]
	if b.sec != sec {
		b.sec, b.n = sec, 0
	}
	b.n++
}

// requests/second over the last 5 complete seconds. Caller holds morph.mu.
func morphRateLocked(now time.Time) float64 {
	cur := now.Unix()
	var n uint64
	for _, b := range morph.buckets {
		if b.sec < cur && b.sec >= cur-5 {
			n += b.n
		}
	}
	return float64(n) / 5
}

// --- ROUTE CLASSIFICATION ---

type morphRoute struct {
	Mode            string   `json:"mode"` // direct | analyzer | local_proxy | tor | socks | http_proxy | invalid
	Label           string   `json:"label"`
	ProxyURL        string   `json:"proxyUrl,omitempty"`
	Hops            []string `json:"hops"`
	Egress          string   `json:"egress"`
	Warnings        []string `json:"warnings"`
	RotatesIdentity string   `json:"rotatesIdentity"` // what NEW IDENTITY does to the exit IP on this route
}

func isSOCKSProxy(u *url.URL) bool {
	return u.Scheme == "socks5" || u.Scheme == "socks5h"
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func classifyRoute(enabled bool, raw string) morphRoute {
	direct := morphRoute{
		Mode:            "direct",
		Label:           "Direct",
		Hops:            []string{"DORM", "Target"},
		Egress:          "This machine's own public IP",
		Warnings:        []string{},
		RotatesIdentity: "No — a direct connection always leaves from this machine's IP.",
	}
	if !enabled {
		return direct
	}
	if raw == "" {
		raw = defaultProxyURL // same default as scanProxyFunc
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		direct.Mode = "invalid"
		direct.Label = "Invalid proxy → Direct"
		direct.ProxyURL = raw
		direct.Warnings = append(direct.Warnings,
			"The proxy URL could not be parsed (it needs a scheme, e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050). DORM silently falls back to a DIRECT connection.")
		return direct
	}
	r := morphRoute{ProxyURL: u.Redacted(), Warnings: []string{}}
	host, port := u.Hostname(), u.Port()
	local := isLoopbackHost(host)

	switch {
	case u.Scheme != "http" && u.Scheme != "https" && !isSOCKSProxy(u):
		r.Mode, r.Label = "invalid", "Unsupported proxy scheme"
		r.Hops = []string{"DORM", "✕"}
		r.Egress = "None — every request fails"
		r.Warnings = append(r.Warnings, fmt.Sprintf("Go's transport only supports http, https and socks5 proxies; %q makes every scan request fail.", u.Scheme))
		r.RotatesIdentity = "No."
	case isSOCKSProxy(u) && local && (port == "9050" || port == "9150"):
		r.Mode, r.Label = "tor", "Tor (SOCKS5)"
		r.Hops = []string{"DORM", "Tor :" + port, "Tor circuit", "Exit node", "Target"}
		r.Egress = "A Tor exit node"
		if u.User != nil {
			r.RotatesIdentity = "No — the proxy URL carries its own SOCKS credentials, so DORM does not replace them; restart the circuit in Tor (NEWNYM)."
		} else {
			r.RotatesIdentity = "Yes — new SOCKS isolation credentials make Tor (IsolateSOCKSAuth, on by default) build a new circuit, usually with a new exit IP."
		}
		if u.Scheme == "socks5" {
			r.Warnings = append(r.Warnings, "socks5:// resolves target hostnames on this machine, so DNS lookups leave outside Tor. Use socks5h:// to resolve through Tor.")
		}
	case isSOCKSProxy(u):
		r.Mode, r.Label = "socks", "SOCKS5 proxy"
		r.Hops = []string{"DORM", "SOCKS5 " + u.Host, "Target"}
		r.Egress = "The SOCKS proxy's IP"
		if u.User != nil {
			r.RotatesIdentity = "No — the proxy URL carries its own credentials; rotate the session at the provider."
		} else {
			r.RotatesIdentity = "Maybe — new SOCKS session credentials are sent; whether the exit IP changes depends on the provider."
		}
		if u.Scheme == "socks5" {
			r.Warnings = append(r.Warnings, "socks5:// resolves target hostnames on this machine (local DNS leak). Use socks5h:// to resolve at the proxy.")
		}
	case local && port == morphAnalyzerPort:
		r.Mode, r.Label = "analyzer", "DORM Analyzer (local)"
		r.Hops = []string{"DORM", "Analyzer :" + port, "Target"}
		r.Egress = "This machine's own public IP (the analyzer connects directly)"
		r.Warnings = append(r.Warnings,
			"No anonymity: the analyzer is a local inspection hop, the target still sees this machine's IP.",
			"HTTPS is tunnelled through the analyzer (CONNECT) without inspection: only plain-HTTP traffic gets passive analysis.")
		r.RotatesIdentity = "No — the analyzer leaves from this machine's IP."
	case local:
		r.Mode, r.Label = "local_proxy", "Local intercepting proxy"
		r.Hops = []string{"DORM", "Proxy " + u.Host, "Upstream?", "Target"}
		r.Egress = "Whatever this proxy's upstream is (this machine's IP unless it chains further)"
		r.RotatesIdentity = "No — only pooled connections are dropped."
	default:
		r.Mode, r.Label = "http_proxy", "Upstream HTTP proxy"
		r.Hops = []string{"DORM", "Proxy " + u.Host, "Target"}
		r.Egress = "The proxy's IP"
		r.RotatesIdentity = "No — HTTP proxies have no per-session isolation here; rotate at the provider."
		if u.Scheme == "http" {
			r.Warnings = append(r.Warnings, "The hop to the proxy is plain HTTP: plaintext http:// scan requests (and any auth header) are visible on the path to the proxy.")
		}
	}
	return r
}

// --- TLS FINGERPRINT (measured) ---

type morphTLS struct {
	Library        string   `json:"library"`
	JA3            string   `json:"ja3"`
	JA3Hash        string   `json:"ja3Hash"`
	JA4            string   `json:"ja4"`
	ALPN           []string `json:"alpn"`
	HTTPVersion    string   `json:"httpVersion"`
	Versions       []string `json:"versions"`
	CipherCount    int      `json:"cipherCount"`
	ExtensionCount int      `json:"extensionCount"`
	Groups         []string `json:"groups"`
	Error          string   `json:"error,omitempty"`
}

var (
	morphTLSOnce sync.Once
	morphTLSVal  morphTLS
)

func morphFingerprint() morphTLS {
	morphTLSOnce.Do(func() {
		hello, err := captureScanClientHello()
		if err != nil {
			morphTLSVal = morphTLS{Library: "Go crypto/tls", Error: err.Error()}
			return
		}
		morphTLSVal = fingerprintHello(hello)
	})
	return morphTLSVal
}

// captureScanClientHello sends one request through a clone of the scan
// transport to a throwaway loopback TLS listener and records the ClientHello
// it receives. A non-IP hostname is used so SNI is sent just as it is for a
// real target hostname.
func captureScanClientHello() (*tls.ClientHelloInfo, error) {
	cert, err := morphSelfSignedCert()
	if err != nil {
		return nil, err
	}
	helloCh := make(chan *tls.ClientHelloInfo, 1)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			cp := *h
			select {
			case helloCh <- &cp:
			default:
			}
			return nil, errors.New("fingerprint captured")
		},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()

	t := newScanTransport(nil)
	defer t.CloseIdleConnections()
	addr := ln.Addr().String()
	t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://fingerprint.dorm.invalid/", nil)
	if resp, err := t.RoundTrip(req); err == nil {
		_ = resp.Body.Close()
	}

	select {
	case h := <-helloCh:
		return h, nil
	case <-time.After(time.Second):
		return nil, errors.New("no ClientHello captured from the scan transport")
	}
}

func morphSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fingerprint.dorm.invalid"},
		DNSNames:     []string{"fingerprint.dorm.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// GREASE values (RFC 8701) are excluded from JA3/JA4.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func joinU16(vals []uint16, sep string, hexFmt bool) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if hexFmt {
			parts = append(parts, fmt.Sprintf("%04x", v))
		} else {
			parts = append(parts, strconv.Itoa(int(v)))
		}
	}
	return strings.Join(parts, sep)
}

func noGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func fingerprintHello(h *tls.ClientHelloInfo) morphTLS {
	ciphers := noGREASE(h.CipherSuites)
	exts := noGREASE(h.Extensions)
	curves := make([]uint16, 0, len(h.SupportedCurves))
	groupNames := []string{}
	for _, c := range h.SupportedCurves {
		if !isGREASE(uint16(c)) {
			curves = append(curves, uint16(c))
			groupNames = append(groupNames, c.String())
		}
	}
	points := make([]string, 0, len(h.SupportedPoints))
	for _, p := range h.SupportedPoints {
		points = append(points, strconv.Itoa(int(p)))
	}

	// JA3: legacy_version is always 0x0303 (771) in a Go ClientHello — the real
	// versions live in supported_versions, which ClientHelloInfo exposes instead.
	ja3 := strings.Join([]string{
		"771",
		joinU16(ciphers, "-", false),
		joinU16(exts, "-", false),
		joinU16(curves, "-", false),
		strings.Join(points, "-"),
	}, ",")
	ja3Sum := md5.Sum([]byte(ja3))

	// JA4 (FoxIO): t<ver><d|i><ciphers><exts><alpn>_<sorted ciphers>_<sorted exts>_<sigalgs>
	versions := noGREASE(h.SupportedVersions)
	maxVer := uint16(0)
	verNames := []string{}
	for _, v := range versions {
		if v > maxVer {
			maxVer = v
		}
		verNames = append(verNames, tls.VersionName(v))
	}
	verCode := map[uint16]string{tls.VersionTLS13: "13", tls.VersionTLS12: "12", tls.VersionTLS11: "11", tls.VersionTLS10: "10"}[maxVer]
	if verCode == "" {
		verCode = "00"
	}
	sni := "i"
	if h.ServerName != "" {
		sni = "d"
	}
	alpnCode := "00"
	if len(h.SupportedProtos) > 0 && h.SupportedProtos[0] != "" {
		p := h.SupportedProtos[0]
		first, last := p[0], p[len(p)-1]
		if isAlnum(first) && isAlnum(last) {
			alpnCode = string([]byte{first, last})
		} else {
			hx := hex.EncodeToString([]byte(p))
			alpnCode = string([]byte{hx[0], hx[len(hx)-1]})
		}
	}
	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	sortedExts := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 { // SNI and ALPN are counted but not hashed
			sortedExts = append(sortedExts, e)
		}
	}
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	sigs := make([]uint16, 0, len(h.SignatureSchemes))
	for _, s := range h.SignatureSchemes {
		if !isGREASE(uint16(s)) {
			sigs = append(sigs, uint16(s))
		}
	}
	partB := "000000000000"
	if len(sortedCiphers) > 0 {
		partB = sha12(joinU16(sortedCiphers, ",", true))
	}
	cInput := joinU16(sortedExts, ",", true)
	if len(sigs) > 0 {
		cInput += "_" + joinU16(sigs, ",", true)
	}
	partC := "000000000000"
	if len(sortedExts) > 0 {
		partC = sha12(cInput)
	}
	ja4 := fmt.Sprintf("t%s%s%02d%02d%s_%s_%s", verCode, sni, min(len(ciphers), 99), min(len(exts), 99), alpnCode, partB, partC)

	httpVer := "HTTP/1.1 only"
	for _, p := range h.SupportedProtos {
		if p == "h2" {
			httpVer = "HTTP/2 + HTTP/1.1"
		}
	}
	alpn := h.SupportedProtos
	if alpn == nil {
		alpn = []string{}
	}
	return morphTLS{
		Library:        "Go crypto/tls (stdlib)",
		JA3:            ja3,
		JA3Hash:        hex.EncodeToString(ja3Sum[:]),
		JA4:            ja4,
		ALPN:           alpn,
		HTTPVersion:    httpVer,
		Versions:       verNames,
		CipherCount:    len(ciphers),
		ExtensionCount: len(exts),
		Groups:         groupNames,
	}
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// --- PERSONA ---

var (
	reFirefox = regexp.MustCompile(`Firefox/(\d+)`)
	reEdge    = regexp.MustCompile(`Edg/(\d+)`)
	reChrome  = regexp.MustCompile(`Chrome/(\d+)`)
	reSafari  = regexp.MustCompile(`Version/(\d+)[\d.]*.*Safari/`)
)

func personaLabel(ua string) string {
	if ua == "" {
		return ""
	}
	if ua == morphPlainUA {
		return "DORM (no persona)"
	}
	browser := strings.SplitN(ua, " ", 2)[0]
	switch {
	case reFirefox.MatchString(ua):
		browser = "Firefox " + reFirefox.FindStringSubmatch(ua)[1]
	case reEdge.MatchString(ua):
		browser = "Edge " + reEdge.FindStringSubmatch(ua)[1]
	case reChrome.MatchString(ua):
		browser = "Chrome " + reChrome.FindStringSubmatch(ua)[1]
	case reSafari.MatchString(ua):
		browser = "Safari " + reSafari.FindStringSubmatch(ua)[1]
	}
	os := ""
	switch {
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		os = "iOS"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Mac OS X"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}
	if os == "" {
		return browser
	}
	return browser + " / " + os
}

// --- EGRESS CHECK ---

type morphEgress struct {
	IP         string    `json:"ip"`
	IsTor      *bool     `json:"isTor"` // nil when only the plain-HTTP fallback answered
	Country    string    `json:"country"`
	City       string    `json:"city"`
	ISP        string    `json:"isp"`
	ASN        string    `json:"asn"`
	Hosting    bool      `json:"hosting"` // datacenter range — commonly scored as bot traffic
	ProxyFlag  bool      `json:"proxyFlag"`
	LatencyMs  int64     `json:"latencyMs"`
	HTTPSError string    `json:"httpsError,omitempty"`
	Error      string    `json:"error,omitempty"`
	Route      string    `json:"route"`
	RouteMode  string    `json:"routeMode"`
	RouteProxy string    `json:"routeProxyUrl"`
	Generation int       `json:"generation"`
	CheckedAt  time.Time `json:"checkedAt"`
}

func runEgressCheck(proxyEnabled bool, proxyURL string) *morphEgress {
	route := classifyRoute(proxyEnabled, proxyURL)
	morph.mu.Lock()
	gen := morph.generation
	morph.mu.Unlock()
	out := &morphEgress{Route: route.Label, RouteMode: route.Mode, RouteProxy: route.ProxyURL, Generation: gen, CheckedAt: time.Now()}

	t := newScanTransport(scanProxyFunc(proxyEnabled, proxyURL))
	defer t.CloseIdleConnections()
	// Same route, but the certificate is checked: the scan transport skips
	// verification for targets, and on a hostile route (a Tor exit, a proxy)
	// the answer to "which IP do I leave from, am I on Tor?" could otherwise
	// be forged. Verification changes nothing in what is sent.
	t.TLSClientConfig = &tls.Config{}
	client := &http.Client{Transport: t, Timeout: 20 * time.Second}
	get := func(u string, v any) error {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", morphUserAgent())
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(v)
	}

	start := time.Now()
	var tor struct {
		IsTor bool
		IP    string
	}
	if err := get("https://check.torproject.org/api/ip", &tor); err == nil {
		out.IP = tor.IP
		out.IsTor = &tor.IsTor
	} else {
		// HTTPS may be what's broken on this route (e.g. the analyzer rejects
		// CONNECT); a plain-HTTP lookup still shows where plaintext requests exit.
		out.HTTPSError = err.Error()
		var ipify struct {
			IP string `json:"ip"`
		}
		if err2 := get("https://api.ipify.org/?format=json", &ipify); err2 != nil {
			out.Error = err2.Error()
			out.LatencyMs = time.Since(start).Milliseconds()
			return out
		}
		out.IP = ipify.IP
	}
	out.LatencyMs = time.Since(start).Milliseconds()

	if net.ParseIP(out.IP) != nil {
		var geo struct {
			Status  string `json:"status"`
			Country string `json:"country"`
			City    string `json:"city"`
			ISP     string `json:"isp"`
			AS      string `json:"as"`
			Proxy   bool   `json:"proxy"`
			Hosting bool   `json:"hosting"`
		}
		// ip-api.com's free endpoint is plain HTTP only.
		if err := get("http://ip-api.com/json/"+out.IP+"?fields=status,country,city,isp,as,proxy,hosting", &geo); err == nil && geo.Status == "success" {
			out.Country, out.City, out.ISP, out.ASN = geo.Country, geo.City, geo.ISP, geo.AS
			out.Hosting, out.ProxyFlag = geo.Hosting, geo.Proxy
		}
	}
	return out
}

// --- HTTP HANDLERS ---

func morphRouteParams(r *http.Request) (bool, string) {
	return r.URL.Query().Get("proxyEnabled") == "true", r.URL.Query().Get("proxyUrl")
}

func handleIdentity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cfgEnabled, cfgURL := morphRouteParams(r)
	fp := morphFingerprint()
	pool := bypassers.UserAgents()
	now := time.Now()

	morph.mu.Lock()
	type poolEntry struct {
		UA    string `json:"ua"`
		Label string `json:"label"`
		Count uint64 `json:"count"`
	}
	entries := make([]poolEntry, 0, len(pool))
	for _, ua := range pool {
		entries = append(entries, poolEntry{UA: ua, Label: personaLabel(ua), Count: morph.uaCounts[ua]})
	}
	current := morph.lastUA
	if !morph.enabled {
		current = morphPlainUA
	} else if morph.personaMode == "sticky" && morph.stickyUA != "" {
		current = morph.stickyUA
	}
	var active *morphRoute
	if morph.routeSet {
		rt := classifyRoute(morph.routeProxyEnabled, morph.routeProxyURL)
		active = &rt
	}
	var lastAt, scanSince *time.Time
	if !morph.lastAt.IsZero() {
		t := morph.lastAt
		lastAt = &t
	}
	if !morph.scanSince.IsZero() {
		t := morph.scanSince
		scanSince = &t
	}
	resp := map[string]any{
		"version":       "v1.29.0",
		"enabled":       morph.enabled,
		"generation":    morph.generation,
		"identitySince": morph.identitySince,
		"isolationTag":  morph.isolationToken[:6],
		"configured":    classifyRoute(cfgEnabled, cfgURL),
		"active":        active,
		"live":          !morph.lastAt.IsZero() && now.Sub(morph.lastAt) < 5*time.Second,
		"persona": map[string]any{
			"mode":         morph.personaMode,
			"current":      current,
			"currentLabel": personaLabel(current),
			"pool":         entries,
		},
		"tls": fp,
		"traffic": map[string]any{
			"total":     morph.total,
			"proxied":   morph.proxied,
			"direct":    morph.total - morph.proxied,
			"reqPerSec": morphRateLocked(now),
			"lastAt":    lastAt,
			"scanSince": scanSince,
			"hosts":     len(morph.hosts),
			"delayMs":   bypassers.GlobalDelayConfig.BaseDelayMs,
			"jitterMs":  bypassers.GlobalDelayConfig.JitterMs,
		},
		"egress": morph.lastEgress,
	}
	mode := morph.personaMode
	enabled := morph.enabled
	morph.mu.Unlock()

	resp["consistency"] = morphConsistency(fp, entries2labels(pool), mode, len(pool), enabled)
	_ = json.NewEncoder(w).Encode(resp)
}

func entries2labels(pool []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, ua := range pool {
		l := strings.SplitN(personaLabel(ua), " ", 2)[0]
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

func morphConsistency(fp morphTLS, browsers []string, mode string, poolSize int, enabled bool) map[string]any {
	if !enabled {
		return map[string]any{"verdict": "OFF", "reasons": []string{
			"Traffic Morph is off: every request says it is DORM (User-Agent \"" + morphPlainUA + "\"), so there is no browser persona to check against the TLS fingerprint.",
		}}
	}
	reasons := []string{}
	if fp.Error == "" {
		reasons = append(reasons, fmt.Sprintf(
			"The User-Agent claims a browser (%s), but every TLS ClientHello is Go crypto/tls (JA4 %s). WAFs that pair JA3/JA4 with the User-Agent can tell this is not a browser.",
			strings.Join(browsers, ", "), fp.JA4))
		hasH2 := false
		for _, p := range fp.ALPN {
			if p == "h2" {
				hasH2 = true
			}
		}
		if !hasH2 {
			reasons = append(reasons, "No \"h2\" in ALPN: every current browser offers HTTP/2, the scan client speaks HTTP/1.1 only.")
		}
	}
	if mode == "rotate" && poolSize > 1 {
		reasons = append(reasons, "The User-Agent changes on every request while the source IP, TLS fingerprint and keep-alive connection stay the same — one client wearing several browsers at once. STICKY persona keeps one User-Agent per identity.")
	}
	verdict := "CONSISTENT"
	if len(reasons) > 0 {
		verdict = "MISMATCH"
	}
	return map[string]any{"verdict": verdict, "reasons": reasons}
}

func handleIdentityRotate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
		return
	}
	cfgEnabled, cfgURL := morphRouteParams(r)

	morph.mu.Lock()
	if !morph.enabled {
		morph.mu.Unlock()
		http.Error(w, `{"error":"Traffic Morph is off"}`, http.StatusConflict)
		return
	}
	morph.generation++
	morph.isolationToken = newMorphToken()
	morph.identitySince = time.Now()
	prevUA := morph.stickyUA
	morph.stickyUA = ""
	if morph.personaMode == "sticky" {
		pool := bypassers.UserAgents()
		for i := 0; i < 8 && (morph.stickyUA == "" || (morph.stickyUA == prevUA && len(pool) > 1)); i++ {
			morph.stickyUA = bypassers.GetRandomUserAgent()
		}
	}
	newUA := morph.stickyUA
	mode := morph.personaMode
	gen := morph.generation
	morph.lastEgress = nil // the old egress result no longer describes this identity
	route := classifyRoute(cfgEnabled, cfgURL)
	if morph.routeSet {
		route = classifyRoute(morph.routeProxyEnabled, morph.routeProxyURL)
	}
	morph.mu.Unlock()

	activeClientMu.RLock()
	t := activeTransport
	activeClientMu.RUnlock()

	actions := []map[string]string{}
	add := func(status, what, detail string) {
		actions = append(actions, map[string]string{"status": status, "what": what, "detail": detail})
	}
	if t != nil {
		t.CloseIdleConnections()
		add("done", "Connections", "Pooled keep-alive connections dropped — the next request opens a fresh TCP + TLS session from a new source port.")
	} else {
		add("done", "Connections", "No scan client yet — the next scan starts with fresh connections.")
	}
	ipStatus := "kept"
	if strings.HasPrefix(route.RotatesIdentity, "Yes") {
		ipStatus = "done"
	} else if strings.HasPrefix(route.RotatesIdentity, "Maybe") {
		ipStatus = "partial"
	}
	add(ipStatus, "Exit IP ("+route.Label+")", route.RotatesIdentity)
	if mode == "sticky" {
		add("done", "Persona", "New sticky User-Agent: "+personaLabel(newUA)+".")
	} else {
		add("kept", "Persona", "Per-request rotation — every request already draws a random User-Agent.")
	}
	add("done", "Session traces", "No TLS session tickets to clear (the scan transport has no session cache) and no cookie jar (the scan client is stateless). A user-supplied auth header is kept.")
	add("kept", "TLS fingerprint", "Unchanged — Go crypto/tls sends a fixed ClientHello. JA3/JA4 spoofing needs a uTLS-based transport.")

	_ = json.NewEncoder(w).Encode(map[string]any{"generation": gen, "actions": actions})
}

func handleIdentityPersona(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
		return
	}
	mode := r.URL.Query().Get("mode")
	if mode != "rotate" && mode != "sticky" {
		http.Error(w, `{"error":"mode must be rotate or sticky"}`, http.StatusBadRequest)
		return
	}
	morph.mu.Lock()
	morph.personaMode = mode
	if mode == "sticky" && morph.stickyUA == "" {
		morph.stickyUA = bypassers.GetRandomUserAgent()
	}
	morph.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"mode": mode})
}

// handleIdentityEnabled switches Traffic Morph on or off. Off, the scan
// client sends morphPlainUA and NEW IDENTITY is refused; the identity,
// persona mode and sticky persona are kept, so switching back on resumes them.
func handleIdentityEnabled(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
		return
	}
	on, err := strconv.ParseBool(r.URL.Query().Get("on"))
	if err != nil {
		http.Error(w, `{"error":"on must be true or false"}`, http.StatusBadRequest)
		return
	}
	morph.mu.Lock()
	morph.enabled = on
	morph.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": on})
}

func handleIdentityEgress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
		return
	}
	res := runEgressCheck(morphRouteParams(r))
	morph.mu.Lock()
	if res.Generation == morph.generation { // a NEW IDENTITY during the check makes it stale
		morph.lastEgress = res
	}
	morph.mu.Unlock()
	_ = json.NewEncoder(w).Encode(res)
}
