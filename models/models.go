package models

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// SharedData is a global concurrent map for sharing data between plugins
var SharedData sync.Map

// SharedData key prefixes — always append the target hostname.
const (
	KeyPrefixSiteMap    = "sitemap_"    // *sitemapper.SiteMap
	KeyPrefixEndpoints  = "endpoints_"  // []models.Endpoint
	KeyPrefixForbidden  = "forbidden_"  // []string (403/401 paths + robots disallows)
	KeyPrefixJSFiles    = "jsfiles_"    // []string (JS file URLs)
	KeyPrefixTechProfile = "techprofile_" // *models.TechProfile
)

type ScanTarget struct {
	IP   string
	Port int
}

type Endpoint struct {
	URL    string
	Method string
	Params []string
}

type Vulnerability struct {
	Target      ScanTarget
	Name        string
	Severity    string
	CVSS        float64
	Description string
	Solution    string
	Reference   string
	Status      string
}

type ScannerPlugin interface {
	Name() string
	Run(target ScanTarget) *Vulnerability
}

// Function pointer to avoid circular dependencies when plugins need the HTTP client.
// Initialized with a safe fallback (matching client.go's own getClient()
// fallback) so a plugin invoked before main() rewires this — a future test,
// tool subcommand, or refactor that changes init order — degrades to a
// default client instead of nil-panicking and crashing the whole process.
var GetClient func() *http.Client = func() *http.Client { return &http.Client{} }

// ScanRoundTripper is wired by main to the current scan route WITHOUT the
// scan's auth header: the configured proxy (incl. Traffic Morph's Tor
// isolation credentials), the User-Agent persona and the WAF delay.
var ScanRoundTripper func() http.RoundTripper = func() http.RoundTripper { return http.DefaultTransport }

// scanTransport defers to ScanRoundTripper on every request, so a client
// built during package init (before main wires the hook) or before a scan
// started still follows the current scan's route.
type scanTransport struct{}

func (scanTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if IsBackground(req.Context()) {
		return BackgroundRoundTripper().RoundTrip(req)
	}
	return ScanRoundTripper().RoundTrip(req)
}

// BackgroundRoundTripper is wired by main to the last scan's route (or the
// direct persona fallback) WITHOUT the scan's lifetime: it keeps working after
// the scan ends and is not counted as scan traffic. It serves requests that
// belong to a page the user opened, not to a scan (the SCI page).
var BackgroundRoundTripper func() http.RoundTripper = func() http.RoundTripper { return http.DefaultTransport }

type backgroundKey struct{}

// WithBackground marks requests made with ctx as background (see
// BackgroundRoundTripper). Requests of a finished scan are refused; these are not.
func WithBackground(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundKey{}, true)
}

// IsBackground reports whether WithBackground marked ctx.
func IsBackground(ctx context.Context) bool {
	bg, _ := ctx.Value(backgroundKey{}).(bool)
	return bg
}

// GetScanTransport returns the scan route as a RoundTripper. Components that
// need their own http.Client (own timeout, redirect policy, anonymous
// requests) wrap this instead of building a bare http.Transport, which would
// leave directly from this machine with a Go-http-client User-Agent.
func GetScanTransport() http.RoundTripper { return scanTransport{} }

// GetScanProxyURL returns the scan route's proxy for clients that are not Go
// (headless Chrome's --proxy-server), or "" for a direct route.
var GetScanProxyURL func() string = func() string { return "" }

// GetScanUserAgent returns the current Traffic Morph User-Agent persona for
// clients outside the Go transport (headless Chrome).
var GetScanUserAgent func() string = func() string { return "" }

type keepUAKey struct{}

// KeepUserAgent marks a request whose User-Agent header is itself a test
// payload (e.g. SQLi via User-Agent), so the scan transport sends it as is
// instead of replacing it with the persona.
func KeepUserAgent(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), keepUAKey{}, true))
}

// UserAgentKept reports whether KeepUserAgent marked req.
func UserAgentKept(req *http.Request) bool {
	keep, _ := req.Context().Value(keepUAKey{}).(bool)
	return keep
}


type TechNode struct {
    Product string
    Version string
}

type TechProfile struct {
    Techs []TechNode
    WAF   string
    CMS   string
}

type LocalCVE struct {
    ID            string  `json:"id"`
    Product       string  `json:"product"`
    Version       string  `json:"version"`
    CVSS          float64 `json:"cvss"`
    VendorProject string  `json:"vendorProject"`
    Description   string  `json:"description"`
    Severity      string  `json:"severity"`
}

// The four function pointers below carry the same nil-panic risk as
// GetClient above if ever called before main() wires them — each is given a
// safe no-result default for the same reason.
var DeepScanTarget func(targetURL string) *TechProfile = func(string) *TechProfile { return &TechProfile{} }
var DeepScanTargetContext func(ctx context.Context, targetURL string) *TechProfile = func(context.Context, string) *TechProfile { return &TechProfile{} }
var SearchLocalCVEs func(product, version string) []LocalCVE = func(string, string) []LocalCVE { return nil }
var GetCVEByID func(id string) *LocalCVE = func(string) *LocalCVE { return nil }
var SearchExploitDB func(query string) []string = func(string) []string { return nil }

// ==========================================
// SHARED HELPERS FOR ENGINE SUB-PACKAGES
// ==========================================

// IsWebPort returns true if the port is a common web port.
func IsWebPort(port int) bool {
	return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 3000 || port == 5000 || port == 9090 ||
		port == 8000 || port == 8001 || port == 8081 || port == 8888 || port == 9000
}

// GetURL constructs a full URL from a ScanTarget and optional path.
func GetURL(target ScanTarget, path string) string {
	proto := "http"
	if target.Port == 443 || target.Port == 8443 {
		proto = "https"
	}
	if !strings.HasPrefix(path, "/") && path != "" {
		path = "/" + path
	}
	return fmt.Sprintf("%s://%s:%d%s", proto, target.IP, target.Port, path)
}

// ReadBody reads the response body up to maxBytes and closes it.
func ReadBody(resp *http.Response, maxBytes int64) string {
	if resp == nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return string(b)
}

// GetSharedString reads a string value from SharedData.
func GetSharedString(key string) string {
	v, ok := SharedData.Load(key)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// SignHS256 manually computes an HMAC-SHA256-signed JWT (header.payload.sig),
// avoiding an external dependency like jwt-go for plugins that need to forge
// tokens.
func SignHS256(header, payload string, secret []byte) string {
	unsignedToken := header + "." + payload
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(unsignedToken))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return unsignedToken + "." + signature
}

// ParseAndValidateJWT splits a raw JWT into its three base64url segments and
// sanity-checks that the header segment decodes and looks like a JWT header.
func ParseAndValidateJWT(raw string) (header string, payload string, signature string, valid bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		headerBytes, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return "", "", "", false
		}
	}

	if !strings.Contains(string(headerBytes), `"alg"`) {
		return "", "", "", false
	}

	return parts[0], parts[1], parts[2], true
}

// FindJWT searches an Authorization header, Set-Cookie header, and response
// body for the first syntactically valid JWT.
func FindJWT(content string, headers http.Header) string {
	re := regexp.MustCompile(`ey[A-Za-z0-9-_]+\.ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*`)

	candidates := []string{}

	auth := headers.Get("Authorization")
	if len(auth) > 7 && strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		candidates = append(candidates, strings.TrimSpace(auth[7:]))
	}

	cookieHeader := headers.Get("Set-Cookie")
	matches := re.FindAllString(cookieHeader, -1)
	candidates = append(candidates, matches...)

	bodyMatches := re.FindAllString(content, -1)
	candidates = append(candidates, bodyMatches...)

	for _, c := range candidates {
		_, _, _, valid := ParseAndValidateJWT(c)
		if valid {
			return c
		}
	}

	return ""
}
