package sitemapper

import "time"

// Page represents a single crawled page with rich metadata.
type Page struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	ContentType  string            `json:"content_type"`
	Title        string            `json:"title"`
	Depth        int               `json:"depth"`
	Links        []string          `json:"links"`
	JSFiles      []string          `json:"js_files"`
	Headers      map[string]string `json:"headers"`
	Tech         []string          `json:"tech"`
	DiscoveredAt time.Time         `json:"discovered_at"`
}

// FormInput represents a single HTML form field.
type FormInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`     // "text", "password", "hidden", "file", "email", etc.
	Required bool   `json:"required"`
}

// Form represents a discovered HTML <form> element.
type Form struct {
	PageURL string      `json:"page_url"`
	Action  string      `json:"action"`
	Method  string      `json:"method"` // "GET" or "POST"
	Inputs  []FormInput `json:"inputs"`
}

// Endpoint represents a discovered HTTP endpoint with its parameters.
type Endpoint struct {
	URL    string   `json:"url"`
	Method string   `json:"method"` // "GET", "POST", "PUT", "DELETE", etc.
	Params []string `json:"params"`
	Source string   `json:"source"` // "html_link"|"html_form"|"js_extract"|"robots"|"sitemap_xml"|"analyzer"
}

// JSFile represents a discovered JavaScript file and the paths extracted from it.
type JSFile struct {
	URL   string   `json:"url"`
	Paths []string `json:"paths"`
}

// MapStats holds aggregate statistics about the site map.
type MapStats struct {
	TotalPages     int            `json:"total_pages"`
	TotalForms     int            `json:"total_forms"`
	TotalEndpoints int            `json:"total_endpoints"`
	TotalJSFiles   int            `json:"total_js_files"`
	MaxDepth       int            `json:"max_depth"`
	Technologies   map[string]int `json:"technologies"`
}

// SiteMap is the complete discovered structure of a target host.
// It is the central data structure that feeds all DORM plugins and the DAST analyzer.
type SiteMap struct {
	Host           string     `json:"host"`
	BaseURL        string     `json:"base_url"`
	ScanID         string     `json:"scan_id"`
	Pages          []Page     `json:"pages"`
	Endpoints      []Endpoint `json:"endpoints"`
	Forms          []Form     `json:"forms"`
	JSFiles        []JSFile   `json:"js_files"`
	RobotDisallows []string   `json:"robot_disallows"` // paths from robots.txt Disallow directives
	SitemapURLs    []string   `json:"sitemap_urls"`    // URLs found in sitemap.xml
	Stats          MapStats   `json:"stats"`
	CreatedAt      time.Time  `json:"created_at"`
}
