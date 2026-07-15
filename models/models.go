package models

import (
	"net/http"
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
var SearchExploitDB func(query string) []string
