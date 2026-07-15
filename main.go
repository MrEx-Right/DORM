package main

import (
	"DORM/analyzer"
	"DORM/cve"
	"DORM/models"
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		http.ServeFile(w, r, "web/dashboard.html")
	})

	http.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		http.ServeFile(w, r, "web/app.js")
	})

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

	// Sitemapper API Routes
	http.HandleFunc("/api/sitemap", handleSiteMap)
	http.HandleFunc("/api/sitemap/list", handleSiteMapList)

	port := ":8080"
	url := "http://localhost" + port

	banner := `
██████╗  ██████╗ ██████╗ ███╗   ███╗
██╔══██╗██╔═══██╗██╔══██╗████╗ ████║
██║  ██║██║   ██║██████╔╝██╔████╔██║
██║  ██║██║   ██║██╔══██╗██║╚██╔╝██║
██████╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║
╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝ v1.19.0

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

	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Println("ERROR:", err)
	}
}
