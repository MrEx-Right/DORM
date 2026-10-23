package wafengine

// Regression tests for "WAF Detected: AWS CloudFront" (2026-10-22 scan,
// dynatrace.com): CDN headers were reported as an active WAF.

import (
	"DORM/models"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func serveOn(t *testing.T, addr string, h http.HandlerFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	s := httptest.NewUnstartedServer(h)
	_ = s.Listener.Close()
	s.Listener = ln
	s.Start()
	t.Cleanup(s.Close)
}

// useDirectClient points the plugin at the mocks and makes the legacy
// DeepScan fallback answer legacyWAF, whatever the mock looks like.
func useDirectClient(t *testing.T, legacyWAF string) {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second}
	oldClient, oldDeep := models.GetClient, models.DeepScanTarget
	models.GetClient = func() *http.Client { return c }
	models.DeepScanTarget = func(string) *models.TechProfile { return &models.TechProfile{WAF: legacyWAF} }
	t.Cleanup(func() { models.GetClient, models.DeepScanTarget = oldClient, oldDeep })
}

func cdnSite(extra map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for k, v := range extra {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html><body>Same marketing page for every request, long enough to look real.</body></html>")
	}
}

var cloudFrontHeaders = map[string]string{
	"Via":          "1.1 abc123.cloudfront.net (CloudFront)",
	"X-Cache":      "Hit from cloudfront",
	"X-Amz-Cf-Pop": "FRA56-P1",
	"X-Amz-Cf-Id":  "x0Yq-example==",
}

func TestWAF_CloudFrontCDNIsNotAWAF(t *testing.T) {
	useDirectClient(t, "AWS CloudFront") // the old DeepScan answer for "Via: cloudfront"
	serveOn(t, "127.0.0.51:8000", cdnSite(cloudFrontHeaders))
	if v := (&WAFDetectorPlugin{}).Run(models.ScanTarget{IP: "127.0.0.51", Port: 8000}); v != nil {
		t.Fatalf("CloudFront CDN headers are not a WAF: %s", v.Name)
	}
}

func TestWAF_FastlyCDNIsNotAWAF(t *testing.T) {
	useDirectClient(t, "")
	serveOn(t, "127.0.0.52:8000", cdnSite(map[string]string{"X-Served-By": "cache-fra-123", "X-Fastly-Request-ID": "abc"}))
	if v := (&WAFDetectorPlugin{}).Run(models.ScanTarget{IP: "127.0.0.52", Port: 8000}); v != nil {
		t.Fatalf("Fastly CDN headers are not a WAF: %s", v.Name)
	}
}

func TestWAF_AWSWAFBehindCloudFrontIsDetected(t *testing.T) {
	useDirectClient(t, "")
	h := map[string]string{"X-Amzn-Waf-Action": "captcha"}
	for k, v := range cloudFrontHeaders {
		h[k] = v
	}
	serveOn(t, "127.0.0.53:8000", cdnSite(h))
	v := (&WAFDetectorPlugin{}).Run(models.ScanTarget{IP: "127.0.0.53", Port: 8000})
	if v == nil || v.Name != "WAF Detected: AWS WAF" {
		t.Fatalf("want AWS WAF, got %+v", v)
	}
}

func TestWAF_CloudflareStillDetected(t *testing.T) {
	useDirectClient(t, "")
	serveOn(t, "127.0.0.54:8000", cdnSite(map[string]string{"Server": "cloudflare", "CF-RAY": "8a1b2c3d4e5f-FRA"}))
	v := (&WAFDetectorPlugin{}).Run(models.ScanTarget{IP: "127.0.0.54", Port: 8000})
	if v == nil || v.Name != "WAF Detected: Cloudflare" {
		t.Fatalf("want Cloudflare, got %+v", v)
	}
}
