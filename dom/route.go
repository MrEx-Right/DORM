package dom

import (
	"net/url"
	"strings"

	"DORM/models"

	"github.com/chromedp/chromedp"
)

// RouteOptions returns the Chrome flags that put a headless browser on the
// scan route: the Traffic Morph User-Agent persona and, when the scan uses a
// proxy, --proxy-server. Without them Chrome connects directly from this
// machine and announces itself (HeadlessChrome / DORM-DOMCrawler).
//
// Chrome cannot take proxy credentials on the command line, so userinfo is
// dropped: an authenticating HTTP proxy then answers 407 (the crawl fails
// instead of leaking direct), and on Tor Chrome uses Tor's default circuit
// rather than the NEW IDENTITY isolation circuit.
func RouteOptions() []chromedp.ExecAllocatorOption {
	var opts []chromedp.ExecAllocatorOption
	if ua := models.GetScanUserAgent(); ua != "" {
		opts = append(opts, chromedp.UserAgent(ua))
	}
	if server, socksHost := chromeProxyServer(models.GetScanProxyURL()); server != "" {
		opts = append(opts, chromedp.ProxyServer(server))
		// Chrome skips the proxy for loopback hosts by default; Go's
		// transport does not. "<-loopback>" removes that implicit bypass so
		// both take the same route.
		opts = append(opts, chromedp.Flag("proxy-bypass-list", "<-loopback>"))
		if socksHost != "" {
			// SOCKS: hostnames go to the proxy unresolved; this stops any
			// stray local DNS lookup (the same rule Tor recommends for Chrome).
			opts = append(opts, chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND , EXCLUDE "+socksHost))
		}
	}
	return opts
}

// unusableProxy is handed to Chrome when the scan route names a proxy it
// cannot use: Go fails every request on such a route, so Chrome must fail
// too rather than quietly connect direct.
const unusableProxy = "http://127.0.0.1:1"

// chromeProxyServer converts a Go proxy URL into Chrome's --proxy-server
// form ("" = direct). socksHost is the proxy's host for SOCKS routes.
func chromeProxyServer(raw string) (server, socksHost string) {
	if raw == "" {
		return "", ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return unusableProxy, ""
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "socks4":
	case "socks5", "socks5h":
		scheme = "socks5" // Chrome always resolves through a SOCKS5 proxy
		socksHost = u.Hostname()
	default:
		return unusableProxy, ""
	}
	return scheme + "://" + u.Host, socksHost
}
