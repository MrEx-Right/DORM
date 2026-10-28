package main

import (
	"DORM/analyzer"
	"DORM/cve"
	"DORM/models"
	"DORM/plugins/promptinjectionengine"
	"DORM/sitemapper"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	models.GetClient = getClient
	models.ScanRoundTripper = scanRoundTripper
	models.GetScanProxyURL = getScanProxyURL
	models.GetScanUserAgent = morphUserAgent
	models.DeepScanTarget = DeepScanTarget
	models.DeepScanTargetContext = DeepScanTargetContext
	models.BackgroundRoundTripper = backgroundRoundTripper
	models.SearchLocalCVEs = func(product, version string) []models.LocalCVE {
		return cve.Search(product, version)
	}
	models.GetCVEByID = cve.GetCVEByID
	models.SearchExploitDB = SearchExploitDB
	// 1. Initialize the Database
	InitDB("dorm_engine.db")

	// Clean up any scans left "Running" by a previous process instance
	// (crash, manual close, restart) — otherwise they sit in history forever
	// with no end time.
	if err := DB.SweepStaleRunningScans(); err != nil {
		fmt.Printf("[!] Failed to sweep stale running scans: %v\n", err)
	}

	// Wire sitemapper DB callback (avoids circular import)
	sitemapper.OnSiteMapReady = func(host, scanID string, sm *sitemapper.SiteMap) {
		if err := DB.SaveSiteMap(host, scanID, sm); err != nil {
			fmt.Printf("[Sitemapper] DB save error for %s: %v\n", host, err)
		}
	}

	// 2. Sync full CVEProject database (~280K CVEs) — blocking at startup
	cve.SyncFullDatabase()

	// 2b. Keep the CISA KEV catalog warm in the background so the CVE Center
	// always renders from a fresh cache instead of stalling on the first
	// request after the cache goes stale.
	cve.StartKEVSync()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		http.ServeFile(w, r, "web/dashboard.html")
	})

	// Serves every split JS file under web/js/ (core.js, helpers.js, ... init.js)
	// at /js/<name>.js. Piece-by-piece splits that add new files to web/js/ later
	// need no main.go change — this route picks them up automatically.
	http.Handle("/js/", noCacheHeaders(http.StripPrefix("/js/", http.FileServer(http.Dir("web/js")))))

	http.HandleFunc("/scan", handleScan)
	http.HandleFunc("/stop", handleStop)
	http.HandleFunc("/plugins", handlePluginList)

	// History API Routes
	http.HandleFunc("/api/history", handleHistory)
	http.HandleFunc("/api/history/delete", handleDelete)
	http.HandleFunc("/api/history/delete_all", handleDeleteAll)

	// CVE DB API Routes
	http.HandleFunc("/api/cvedb", handleCVEDatabase)
	http.HandleFunc("/api/cvedb/search", handleCVESearch)
	http.HandleFunc("/api/cvedb/detail", handleCVEDetail)
	http.HandleFunc("/api/kev", handleKEV)

	// Supply Chain Interface API
	http.HandleFunc("/api/sci", handleSCI)

	// Sitemapper API Routes
	http.HandleFunc("/api/sitemap", handleSiteMap)
	http.HandleFunc("/api/sitemap/list", handleSiteMapList)

	// Scan Template API Routes (personal, UI-built vulnerability templates)
	http.HandleFunc("/api/templates", handleTemplates)             // GET list, POST create
	http.HandleFunc("/api/templates/get", handleTemplateGet)       // GET ?id=
	http.HandleFunc("/api/templates/update", handleTemplateUpdate) // POST
	http.HandleFunc("/api/templates/delete", handleTemplateDelete) // POST ?id=
	http.HandleFunc("/api/templates/options", handleTemplateOptions)

	// Traffic Morph — live OpSec / identity panel
	http.HandleFunc("/api/identity", handleIdentity)                // GET ?proxyEnabled=&proxyUrl=
	http.HandleFunc("/api/identity/rotate", handleIdentityRotate)   // POST — NEW IDENTITY
	http.HandleFunc("/api/identity/persona", handleIdentityPersona) // POST ?mode=rotate|sticky
	http.HandleFunc("/api/identity/enabled", handleIdentityEnabled) // POST ?on=true|false (off at launch)
	http.HandleFunc("/api/identity/egress", handleIdentityEgress)   // POST — on-demand egress IP check

	// DOM-Crawler real-time event stream (SSE)
	http.HandleFunc("/dom-events", handleDOMEvents)

	port := ":8080"
	url := "http://localhost" + port

	banner := `
██████╗  ██████╗ ██████╗ ███╗   ███╗
██╔══██╗██╔═══██╗██╔══██╗████╗ ████║
██║  ██║██║   ██║██████╔╝██╔████╔██║
██║  ██║██║   ██║██╔══██╗██║╚██╔╝██║
██████╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║
╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝ v1.29.3

       [ Security Engine • Active ]
`
	fmt.Println("\033[38;5;214m" + banner + "\033[0m")
	fmt.Println("\033[1;30m====================================================\033[0m")
	fmt.Printf("\033[1;32m[*] Server Active: \033[1;36m%s\033[0m\n", url)
	fmt.Printf("\033[1;32m[*] Analyzer Proxy Active on Port: \033[1;36m8081\033[0m\n")
	fmt.Println("\033[1;30m====================================================\033[0m")

	go func() {
		time.Sleep(1 * time.Second)
		openBrowser(url)
	}()

	// 3. Start Native Analyzer Proxy in background
	go func() {
		if err := analyzer.StartAnalyzer("8081"); err != nil {
			fmt.Println("Analyzer Error:", err)
		}
	}()

	// 4. Sync the AI/LLM prompt-injection payload corpus in background —
	// fire-and-forget, never blocks server startup or a scan on GitHub.
	go func() {
		promptinjectionengine.StartBackgroundSync()
	}()

	if err := http.ListenAndServe(port, localOnly(http.DefaultServeMux)); err != nil {
		fmt.Println("ERROR:", err)
	}
}

// noCacheHeaders wraps a handler so every response carries the same
// Cache-Control policy the routes above set explicitly — http.FileServer
// does not set cache headers on its own.
func noCacheHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		h.ServeHTTP(w, r)
	})
}

// localOnly guards every dashboard and API route on :8080. DORM's API takes
// plain GETs (the dashboard starts scans with EventSource, which can send
// nothing else) and used to answer every origin with
// Access-Control-Allow-Origin: *, so any web page open in the user's
// browser, or a scanned site's page opened by the DOM crawler's headless
// Chrome, could start a scan of any target from the user's machine, stop
// the running one, or read the whole scan history.
//
// A request is served only when:
//   - its Host is a loopback name (localhost, 127.0.0.0/8, ::1), so a
//     hostile domain re-pointed at 127.0.0.1 (DNS rebinding) is refused;
//   - an Origin header, if sent, is the dashboard's own origin;
//   - without Origin, Sec-Fetch-Site (sent by current browsers on every
//     request, including <img> and no-cors fetches that carry no Origin) is
//     same-origin or none (typed into the address bar).
//
// Tools that send neither header (curl, the scan-regression lab) still work.
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = strings.Trim(r.Host, "[]")
		}
		if !isLoopbackHost(strings.ToLower(host)) {
			http.Error(w, "DORM: refused, the dashboard only answers on localhost / 127.0.0.1", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			if origin != "http://"+r.Host {
				http.Error(w, "DORM: refused, request from another site ("+origin+")", http.StatusForbidden)
				return
			}
		} else if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "DORM: refused, request from another site (Sec-Fetch-Site: "+site+")", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
