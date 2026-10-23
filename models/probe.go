package models

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

// NoRedirectClient returns a private copy of the scan client that does not
// follow redirects. For "is this endpoint reachable / does this method work"
// checks a 3xx means "not this endpoint": following it turns PUT/DELETE into a
// GET (Go rewrites the method on 301/302/303) and lands on whatever page the
// redirect ends at, usually a 200 home page. The shared client is untouched.
func NoRedirectClient() *http.Client {
	base := GetClient()
	return &http.Client{
		Transport:     base.Transport,
		Jar:           base.Jar,
		Timeout:       base.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// RandomToken returns a short random hex string for probe paths and markers.
func RandomToken() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Baseline is how a server answers a path that cannot exist.
type Baseline struct {
	Status int
	Size   int
	OK     bool // the probe got an answer at all
}

// ProbeSibling sends method to a random sibling of rawURL (same directory,
// last segment replaced) and records the answer. A 2xx there means the
// server answers any path under that prefix (SPA fallback, soft 404, a
// catch-all route that accepts any method), so a 2xx on the "real" path
// proves nothing by itself.
func ProbeSibling(client *http.Client, rawURL, method, contentType, body string) Baseline {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Baseline{}
	}
	p := strings.TrimSuffix(u.Path, "/")
	dir := p[:strings.LastIndex(p, "/")+1]
	if dir == "" {
		dir = "/"
	}
	u.Path = dir + "dorm-nx-" + RandomToken()
	u.RawQuery = ""

	var req *http.Request
	if body != "" {
		req, err = http.NewRequest(method, u.String(), strings.NewReader(body))
	} else {
		req, err = http.NewRequest(method, u.String(), nil)
	}
	if err != nil {
		return Baseline{}
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Baseline{}
	}
	b := ReadBody(resp, 65536)
	return Baseline{Status: resp.StatusCode, Size: len(b), OK: true}
}

// AcceptsAnything reports whether the baseline shows a server that answers a
// non-existent path with success.
func (b Baseline) AcceptsAnything() bool {
	return b.OK && b.Status >= 200 && b.Status < 300
}

// SameAs reports whether a response looks like the baseline's catch-all
// answer: same status and a body size within 10% (or 64 bytes).
func (b Baseline) SameAs(status, size int) bool {
	if !b.OK || status != b.Status {
		return false
	}
	diff := size - b.Size
	if diff < 0 {
		diff = -diff
	}
	return diff <= 64 || float64(diff) <= 0.10*float64(b.Size)
}

// LooksJSON reports whether a response is JSON by Content-Type or shape.
// Admin-data keyword checks are only meaningful on API data, not on an HTML
// page, where words like "users" or "system" appear everywhere.
func LooksJSON(resp *http.Response, body string) bool {
	if resp != nil && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "json") {
		return true
	}
	t := strings.TrimSpace(body)
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}
