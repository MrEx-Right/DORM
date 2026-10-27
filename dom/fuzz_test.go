package dom

// Fuzz targets for the DOM crawler's URL handling. Hrefs, routes and XHR
// URLs all come from the target's pages, and the proxy URL from the scan
// form; none of them may panic the crawler or widen its scope. Nightly CI
// runs each target for a short budget.

import (
	"net/url"
	"strings"
	"testing"
)

func newFuzzCrawler() *DOMCrawler {
	base, _ := url.Parse("http://target.test/app/")
	return &DOMCrawler{baseURL: base}
}

func FuzzResolveFrom(f *testing.F) {
	f.Add("http://target.test/app/page", "../x?y=1#z")
	f.Add("http://target.test/", "javascript:void(0)")
	f.Add("", "//evil.test/a")
	f.Add("http://[::1]:80/", " /a b ")
	f.Add("%zz", "%zz")

	f.Fuzz(func(t *testing.T, pageURL, href string) {
		c := newFuzzCrawler()
		abs := c.resolveFrom(pageURL, href)
		if abs == "" {
			return
		}
		// net/url can resolve to a URL it cannot parse back ("//::" ->
		// "http://::"); the crawler must then drop it, never treat it as
		// in scope.
		if _, err := url.Parse(abs); err != nil {
			if c.inScope(abs) || c.isCapturableRequest(abs) {
				t.Errorf("unparseable %q (from %q, %q) treated as in scope", abs, pageURL, href)
			}
			return
		}
		_ = c.inScope(abs)
		_ = c.isCapturableRequest(abs)
		// Normalizing it for the visited set must be stable.
		n := normalizeURL(abs)
		if n2 := normalizeURL(n); n2 != n {
			t.Errorf("normalizeURL not idempotent: %q -> %q -> %q", abs, n, n2)
		}
	})
}

func FuzzChromeProxyServer(f *testing.F) {
	f.Add("http://127.0.0.1:8080")
	f.Add("socks5h://user:pass@tor.local:9050")
	f.Add("ftp://x")
	f.Add("http://user:secret@proxy:3128")
	f.Add("::")

	f.Fuzz(func(t *testing.T, raw string) {
		server, socksHost := chromeProxyServer(raw)
		if raw == "" {
			if server != "" || socksHost != "" {
				t.Errorf("empty proxy must mean direct, got %q %q", server, socksHost)
			}
			return
		}
		if server == "" {
			t.Fatalf("non-empty proxy %q mapped to a direct connection", raw)
		}
		ok := false
		for _, s := range []string{"http://", "https://", "socks4://", "socks5://"} {
			if strings.HasPrefix(server, s) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("proxy %q -> server %q has an unsupported scheme", raw, server)
		}
		// Chrome's --proxy-server is visible in the process list: the proxy's
		// credentials must never be copied into it.
		if strings.Contains(server, "@") {
			t.Errorf("proxy %q -> server %q carries userinfo", raw, server)
		}
	})
}
