package sitemapper

// Fuzz targets for the parsers that read target-controlled content: HTML
// pages, inline/external JS and robots.txt. A scan target is free to serve
// hostile input, so none of these may panic, and the crawl-scope invariants
// must hold for any input. Nightly CI runs each target for a short budget.

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func FuzzParseHTML(f *testing.F) {
	f.Add(`<html><head><title>t</title></head><body><a href="/a?x=1">a</a></body></html>`, "/")
	f.Add(`<form action="login.php" method="post"><input name="user"><input type="password" name="pass" required></form>`, "/dir/page")
	f.Add(`<script src="/static/app.js"></script><script>fetch('/api/users'); router.get('/admin/x', h)</script>`, "/")
	f.Add(`<div data-href="//evil.test/x" data-url="javascript:alert(1)"></div><a href="http://other.test/">x</a>`, "/")
	f.Add(`<meta name="generator" content="WordPress 6.4"><a href="%zz">bad</a><form><input name="q"></form>`, "%zz")
	// A third-party link with a query string and a form posting off-site:
	// neither may become an endpoint the injection plugins fuzz.
	f.Add(`<a href="https://video.example/watch?v=abc">v</a><form action="https://pay.example/checkout"><input name="amount"></form>`, "/")

	base, _ := url.Parse("http://target.test/")
	f.Fuzz(func(t *testing.T, body, pagePath string) {
		// The crawler only ever parses pages it fetched from the target.
		pageURL := base.String()
		if ref, err := url.Parse(pagePath); err == nil {
			pageURL = base.ResolveReference(ref).String()
		}
		c := NewCrawler(base, Config{}, nil, &SiteMap{})
		if !c.inScope(pageURL) {
			return
		}
		page := &Page{}
		res := c.parseHTML(body, pageURL, page)
		if res == nil {
			t.Fatal("parseHTML returned nil")
		}
		// Links the crawler queues must never leave the target's scope.
		for _, l := range page.Links {
			if !c.inScope(l) {
				t.Errorf("out-of-scope page link %q", l)
			}
		}
		for _, js := range page.JSFiles {
			if !c.sameHost(js) {
				t.Errorf("out-of-scope JS file %q", js)
			}
		}
		// Endpoints feed every injection plugin; one on another host means
		// DORM sends attack payloads to a site that is not the target.
		for _, ep := range res.endpoints {
			if !c.inScope(ep.URL) {
				t.Errorf("out-of-scope %s endpoint %q (source %s)", ep.Method, ep.URL, ep.Source)
			}
		}
	})
}

func FuzzExtractPathsFromJS(f *testing.F) {
	f.Add(`fetch('/api/v1/users'); axios.post("/api/login", d)`)
	f.Add(`app.use('/admin', r); const routes = [{path: '/dashboard'}]; let u = {url: '/x/y.json'}`)
	f.Add(`"/static/app.css" '/images/a.png' "//cdn" '/ok/path'`)

	f.Fuzz(func(t *testing.T, js string) {
		seen := map[string]bool{}
		for _, p := range ExtractPathsFromJS(js) {
			if !strings.HasPrefix(p, "/") {
				t.Errorf("path %q does not start with /", p)
			}
			if isBlacklisted(p) {
				t.Errorf("blacklisted path %q returned", p)
			}
			if seen[p] {
				t.Errorf("duplicate path %q", p)
			}
			seen[p] = true
		}
	})
}

// staticBody serves the same 200 response to every request, so a parser
// that fetches over HTTP can be fuzzed without a network.
type staticBody string

func (b staticBody) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(string(b))),
		Request:    r,
	}, nil
}

func FuzzRobotsTxt(f *testing.F) {
	f.Add("User-agent: *\nDisallow: /admin\nAllow: /admin/public\nSitemap: http://target.test/sitemap.xml\n")
	f.Add("User-agent: googlebot\nDisallow: /x\n\nUser-agent: DORM\nDisallow: /y\n# comment\n")
	f.Add("Disallow:\n:::\nSITEMAP :  /s.xml\r\nuser-agent:*\r\ndisallow: /a b\r\n")

	base, _ := url.Parse("http://target.test/")
	f.Fuzz(func(t *testing.T, robots string) {
		res := FetchRobotsTxt(&http.Client{Transport: staticBody(robots)}, base)
		for _, list := range [][]string{res.Disallows, res.Allows, res.Sitemaps} {
			for _, v := range list {
				if v == "" || v != strings.TrimSpace(v) {
					t.Errorf("untrimmed or empty directive value %q", v)
				}
			}
		}
	})
}
