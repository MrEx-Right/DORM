package main

import (
	"DORM/models"
	"fmt"
	"net/http"
	"time"
)

func main() {
	models.GetClient = getClient
	models.DeepScanTarget = DeepScanTarget
	models.SearchLocalCVEs = SearchLocalCVEs
	models.SearchExploitDB = SearchExploitDB
	// 1. Initialize the Database
	InitDB("dorm_engine.db")
	SyncCVEDatabase()

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

	// 2. Register History API Routes
	http.HandleFunc("/api/history", handleHistory)
	http.HandleFunc("/api/history/delete", handleDelete)

	port := ":8080"
	url := "http://localhost" + port

	fmt.Println("===========================================")
	fmt.Println("          DORM SCANNER v1.7.0 		 	    ")
	fmt.Println("===========================================")
	fmt.Printf("[*] Server Active: %s\n", url)

	go func() {
		time.Sleep(1 * time.Second)
		openBrowser(url)
	}()

	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Println("ERROR:", err)
	}
}
