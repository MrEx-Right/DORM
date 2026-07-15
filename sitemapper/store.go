package sitemapper

import (
	"DORM/models"
	"strings"
)

// OnSiteMapReady is a callback invoked after a SiteMap is fully built and stored in SharedData.
// The main package sets this to persist the SiteMap to SQLite — avoiding circular imports.
var OnSiteMapReady func(host, scanID string, sm *SiteMap)

// RegisterAnalyzerEndpoint adds a new endpoint discovered by the DAST proxy (analyzer) to
// an existing in-memory SiteMap. Safe to call from any goroutine.
func RegisterAnalyzerEndpoint(host, rawURL, method string, params []string) {
	key := "sitemap_" + host
	existing, ok := models.SharedData.Load(key)
	if !ok {
		return
	}
	sm, ok := existing.(*SiteMap)
	if !ok {
		return
	}

	ep := Endpoint{
		URL:    rawURL,
		Method: method,
		Params: params,
		Source: "analyzer",
	}

	// Deduplicate before appending
	for _, e := range sm.Endpoints {
		if e.URL == ep.URL && e.Method == ep.Method {
			return
		}
	}

	sm.Endpoints = append(sm.Endpoints, ep)
	sm.Stats.TotalEndpoints = len(sm.Endpoints)

	// Re-store the updated map
	models.SharedData.Store(key, sm)

	// Also keep the models.Endpoint slice in sync
	modelEps := toModelEndpoints(sm.Endpoints)
	models.SharedData.Store("endpoints_"+host, modelEps)
}

// StoreSiteMap persists a completed SiteMap to SharedData under multiple keys
// so all downstream DORM plugins can access it. It also triggers the DB callback.
func StoreSiteMap(sm *SiteMap) {
	host := sm.Host

	// 1. Full SiteMap — accessible by UI and any code that knows about sitemapper
	models.SharedData.Store("sitemap_"+host, sm)

	// 2. endpoints_<host> — used by SQLi, XSS, LFI, SSTI, XXE, CRLF, IDOR, NoSQL, etc.
	models.SharedData.Store("endpoints_"+host, toModelEndpoints(sm.Endpoints))

	// 3. forbidden_<host> — used by bypass403, adminbypass, dirbuster
	existing, ok := models.SharedData.Load("forbidden_" + host)
	var forbidden []string
	if ok {
		forbidden, _ = existing.([]string)
	}
	// Merge robots.txt disallows with existing forbidden paths (no duplicates)
	seen := make(map[string]bool)
	for _, p := range forbidden {
		seen[p] = true
	}
	for _, p := range sm.RobotDisallows {
		if !seen[p] {
			seen[p] = true
			forbidden = append(forbidden, p)
		}
	}
	models.SharedData.Store("forbidden_"+host, forbidden)

	// 4. jsfiles_<host> — list of JS file URLs for any plugin that wants to analyze JS
	var jsURLs []string
	for _, jf := range sm.JSFiles {
		jsURLs = append(jsURLs, jf.URL)
	}
	models.SharedData.Store("jsfiles_"+host, jsURLs)

	// 5. techprofile_<host> — aggregated tech fingerprint compatible with models.TechProfile
	profile := buildTechProfile(sm)
	models.SharedData.Store("techprofile_"+host, profile)

	// 6. Trigger DB persistence (main package sets this callback in main.go)
	if OnSiteMapReady != nil {
		OnSiteMapReady(host, sm.ScanID, sm)
	}
}

// GetSiteMap retrieves a SiteMap from SharedData. Returns nil if not found.
func GetSiteMap(host string) *SiteMap {
	v, ok := models.SharedData.Load("sitemap_" + host)
	if !ok {
		return nil
	}
	sm, _ := v.(*SiteMap)
	return sm
}

// toModelEndpoints converts sitemapper.Endpoint slice to models.Endpoint slice
// for backward compatibility with all existing DORM plugins.
func toModelEndpoints(eps []Endpoint) []models.Endpoint {
	out := make([]models.Endpoint, 0, len(eps))
	for _, e := range eps {
		out = append(out, models.Endpoint{
			URL:    e.URL,
			Method: e.Method,
			Params: e.Params,
		})
	}
	return out
}

// buildTechProfile aggregates page-level tech tags into a models.TechProfile.
func buildTechProfile(sm *SiteMap) *models.TechProfile {
	seen := make(map[string]bool)
	profile := &models.TechProfile{}

	for _, page := range sm.Pages {
		for _, tech := range page.Tech {
			if seen[tech] {
				continue
			}
			seen[tech] = true

			techLower := strings.ToLower(tech)
			if strings.Contains(techLower, "cloudflare") {
				profile.WAF = "Cloudflare"
			} else {
				profile.Techs = append(profile.Techs, models.TechNode{Product: tech})
			}
		}
	}

	return profile
}
