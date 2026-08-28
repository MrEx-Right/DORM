package models

import (
	"fmt"
	"io"
	"net/http"
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

// Function pointer to avoid circular dependencies when plugins need the HTTP client
var GetClient func() *http.Client


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

var DeepScanTarget func(targetURL string) *TechProfile
var SearchLocalCVEs func(product, version string) []LocalCVE
var GetCVEByID func(id string) *LocalCVE
var SearchExploitDB func(query string) []string

// ==========================================
// SHARED HELPERS FOR ENGINE SUB-PACKAGES
// ==========================================

// IsWebPort returns true if the port is a common web port.
func IsWebPort(port int) bool {
	return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 3000 || port == 5000 || port == 9090
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
