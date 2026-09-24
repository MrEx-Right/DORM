package main

import (
	"DORM/analyzer"
	"DORM/cve"
	"DORM/models"
	"DORM/plugins/promptinjectionengine"
	"DORM/sitemapper"
	"fmt"
	"net/http"
	"time"
)

func main() {
	models.GetClient = getClient
	models.DeepScanTarget = DeepScanTarget
	models.SearchLocalCVEs = func(product, version string) []models.LocalCVE {
		return cve.Search(product, version)
	}
	models.GetCVEByID = cve.GetCVEByID
	models.SearchExploitDB = SearchExploitDB
	// 1. Initialize the Database
	InitDB("dorm_engine.db")

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
╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝ v1.27.0

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

	if err := http.ListenAndServe(port, nil); err != nil {
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
