package main

import (
	"DORM/models"
	"DORM/plugins"
	"DORM/sitemapper"
	"context"
	"fmt"
)

// ==========================
// DORM INTEGRATION (PLUGIN)
// ==========================

type SpiderPlugin struct{}

func (p *SpiderPlugin) Name() string { return "Web Spider (Crawler)" }

// Run is now an orchestrator: it calls the sitemapper engine to build a full site map,
// which is persisted to SharedData for all downstream injection plugins to consume.
// If sitemapper already ran (pre-scan in handleScan), it just reads the cached result.
func (p *SpiderPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !plugins.IsWebPort(target.Port) {
		return nil
	}

	startURL := plugins.GetURL(target, "/")
	host := target.IP

	// Check if sitemapper already ran for this host (pre-scan step in handleScan)
	if existing := sitemapper.GetSiteMap(host); existing != nil {
		return buildSpiderVuln(target, existing)
	}

	// Fallback: run sitemapper directly (e.g. standalone plugin invocation)
	fmt.Printf("[Spider] Running sitemapper for %s\n", startURL)
	sm, err := sitemapper.QuickWithContext(context.Background(), startURL, "")
	if err != nil || sm == nil {
		return nil
	}

	return buildSpiderVuln(target, sm)
}

// buildSpiderVuln formats a SiteMap as an INFO vulnerability record for the scan report.
func buildSpiderVuln(target models.ScanTarget, sm *sitemapper.SiteMap) *models.Vulnerability {
	if sm.Stats.TotalPages == 0 {
		return nil
	}

	desc := fmt.Sprintf(
		"Sitemapper discovered the following surface for %s:\n"+
			"  • Pages crawled:   %d\n"+
			"  • Endpoints found: %d\n"+
			"  • Forms found:     %d\n"+
			"  • JS files parsed: %d\n"+
			"  • Max crawl depth: %d\n",
		sm.Host,
		sm.Stats.TotalPages,
		sm.Stats.TotalEndpoints,
		sm.Stats.TotalForms,
		sm.Stats.TotalJSFiles,
		sm.Stats.MaxDepth,
	)

	if len(sm.RobotDisallows) > 0 {
		desc += fmt.Sprintf("  • Robots.txt disallows: %d paths\n", len(sm.RobotDisallows))
	}

	// Show first 10 discovered pages
	limit := 10
	if len(sm.Pages) < limit {
		limit = len(sm.Pages)
	}
	if limit > 0 {
		desc += "\nSample pages:\n"
		for i := 0; i < limit; i++ {
			p := sm.Pages[i]
			desc += fmt.Sprintf("  [%d] %s\n", p.StatusCode, p.URL)
		}
		if len(sm.Pages) > limit {
			desc += fmt.Sprintf("  ...and %d more pages.\n", len(sm.Pages)-limit)
		}
	}

	return &models.Vulnerability{
		Target:      target,
		Name:        "Site Map (Sitemapper v1.19)",
		Severity:    "INFO",
		CVSS:        0.0,
		Description: desc,
		Solution:    "Review discovered pages and ensure sensitive paths are properly protected.",
		Reference:   "DORM Sitemapper",
	}
}
