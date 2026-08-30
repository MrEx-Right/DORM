package main

import (
	"DORM/cve"
	"DORM/dom"
	"DORM/models"
	"DORM/plugins"
	"DORM/sci"
	"DORM/sitemapper"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)


// ==========================================
// 3. HANDLERS (WEB OPS)
// ==========================================

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	}
	if err != nil {
		fmt.Printf("Failed to open browser: %s\n", url)
	}
}

// Endpoint sending plugin list to UI
func handlePluginList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(plugins.GetPluginInventory())
}

// handleDOMEvents streams real-time DOM-Crawler events to the UI via SSE.
// The UI subscribes to GET /dom-events and receives a stream of JSON events
// describing every navigate, click, XHR intercept and SPA route discovery.
func handleDOMEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Register this connection as a subscriber on the DOM event bus
	subID := fmt.Sprintf("sse-%p", r)
	events := dom.GetBus().Subscribe(subID)
	defer dom.GetBus().Unsubscribe(subID)

	// Send a heartbeat comment every 15s to keep the connection alive
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", ev.ToJSON())
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// STOP ENDPOINT
func handleStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if activeScanCancel != nil {
		fmt.Println("[!] USER ABORTED THE SCAN!")
		activeScanCancel() // Hit the brakes!
		activeScanCancel = nil
		_, _ = w.Write([]byte("Scan stopped"))
	} else {
		_, _ = w.Write([]byte("No active scan"))
	}
}

// List CVE Database (first 500 records + stats)
func handleCVEDatabase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	type CVEResponse struct {
		Stats       map[string]interface{} `json:"stats"`
		CVEs        []models.LocalCVE      `json:"cves"`
		ThreatRadar []models.LocalCVE      `json:"threat_radar"`
	}

	_ = json.NewEncoder(w).Encode(CVEResponse{
		Stats:       cve.GetStats(),
		CVEs:        cve.GetFirst(500),
		ThreatRadar: cve.GetThreatRadar(),
	})
}

// CVE Search
func handleCVESearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	query := r.URL.Query().Get("q")
	if query == "" {
		_ = json.NewEncoder(w).Encode([]models.LocalCVE{})
		return
	}

	results := cve.Search(query, "")
	_ = json.NewEncoder(w).Encode(results)
}

// handleScan is a thin SSE wrapper around runScanCore (scanrunner.go) for
// classic, ad-hoc (non-Vector) scans. It owns the single global cancel func
// that always applied to this endpoint, and persists the result to the
// classic dorm_engine.db exactly as before the extraction.
func handleScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// --- CONTEXT SETUP (FOR CANCELLATION) ---
	if activeScanCancel != nil {
		activeScanCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	activeScanCancel = cancel
	// ----------------------------------------

	// 🛠️ CRITICAL FIX 1: Keep SSE alive instantly!
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	w.WriteHeader(http.StatusOK)
	flusher.Flush() // Tell the browser "I'm here, don't drop the connection!"

	targetsParam := r.URL.Query().Get("targets") // Look for the new multi-target param
	if targetsParam == "" {
		targetsParam = r.URL.Query().Get("target") // Fallback: If old app.js is running, grab this!
	}
	if targetsParam == "" {
		return
	}

	wafDelayMs := 0
	if delayStr := r.URL.Query().Get("wafDelay"); delayStr != "" {
		if d, err := strconv.Atoi(delayStr); err == nil {
			wafDelayMs = d
		}
	}
	wafJitterMs := 0
	if jitterStr := r.URL.Query().Get("wafJitter"); jitterStr != "" {
		if j, err := strconv.Atoi(jitterStr); err == nil {
			wafJitterMs = j
		}
	}

	cfg := models.ScanRunConfig{
		Targets:      strings.Split(targetsParam, ","),
		PluginFilter: r.URL.Query().Get("plugins"),
		AuthHeader:   r.URL.Query().Get("auth"),
		ProxyEnabled: r.URL.Query().Get("proxyEnabled") == "true",
		ProxyURL:     r.URL.Query().Get("proxyUrl"),
		WAFDelayMs:   wafDelayMs,
		WAFJitterMs:  wafJitterMs,
		CVERadar:     r.URL.Query().Get("cveRadar") == "true",
	}

	emit := func(payload string) {
		_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
		flusher.Flush()
	}

	scanID := uuid.New().String()
	var target string
	outcome := runScanCore(ctx, scanID, cfg, emit, func(t string) {
		target = t
		record := ScanRecord{
			ID:              scanID,
			Target:          target,
			StartTime:       time.Now(),
			Status:          "Running",
			SeverityStats:   make(map[string]int),
			Vulnerabilities: []*models.Vulnerability{},
		}
		_ = DB.SaveScan(record)
	})

	if target == "" {
		return // no targets were sanitizable — runScanCore never persisted a "Running" row
	}
	_ = DB.UpdateScan(scanID, ScanRecord{
		ID:              scanID,
		Target:          target,
		StartTime:       outcome.StartTime,
		EndTime:         outcome.EndTime,
		Status:          outcome.Status,
		Vulnerabilities: outcome.Vulnerabilities,
		TotalVulns:      outcome.TotalVulns,
		SeverityStats:   outcome.SeverityStats,
	})
}

// handleSiteMap returns the site map for a given host.
// First checks in-memory SharedData (live scan), then falls back to SQLite.
func handleSiteMap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	host := r.URL.Query().Get("target")
	scanID := r.URL.Query().Get("scan_id")
	if host == "" {
		http.Error(w, "Missing 'target' parameter", http.StatusBadRequest)
		return
	}
	if scanID == "" {
		http.Error(w, "Missing 'scan_id' parameter", http.StatusBadRequest)
		return
	}

	// Normalize: strip scheme if provided
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimRight(host, "/")

	// 1. Try in-memory (running or recently completed scan)
	if sm := sitemapper.GetSiteMap(host); sm != nil && sm.ScanID == scanID {
		_ = json.NewEncoder(w).Encode(sm)
		return
	}

	// 2. Fall back to database
	sm, err := DB.GetSiteMap(host, scanID)
	if err != nil {
		http.Error(w, `{"error":"No sitemap found for this target. Run a scan first."}`, http.StatusNotFound)
		return
	}

	_ = json.NewEncoder(w).Encode(sm)
}

// handleSiteMapList returns the list of hosts that have a stored SiteMap for a specific scanID.
func handleSiteMapList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		_ = json.NewEncoder(w).Encode([]string{})
		return
	}

	hosts, err := DB.ListSiteMapHosts(scanID)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}

	if hosts == nil {
		hosts = []string{}
	}
	_ = json.NewEncoder(w).Encode(hosts)
}

// --- HISTORY API HANDLERS ---

func handleHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	records, err := DB.GetAll()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(records)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	if err := DB.DeleteScan(scanID); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	// Also delete any associated sitemaps
	_ = DB.DeleteSiteMapsByScanID(scanID)

	_, _ = fmt.Fprintf(w, `{"status":"success"}`)
}

func handleDeleteAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := DB.DeleteAllScans(); err != nil {
		http.Error(w, `{"error":"Failed to clear history"}`, http.StatusInternalServerError)
		return
	}

	// Clear all sitemaps as well
	_ = DB.DeleteAllSiteMaps()

	_, _ = fmt.Fprintf(w, `{"status":"success"}`)
}

func handleKEV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	buckets, err := cve.GetRecentKEVs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(buckets)
}

// handleSCI runs the Supply Chain Interface analysis for a given target URL.
// GET /api/sci?target=https://example.com
func handleSCI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, `{"error":"Missing 'target' parameter"}`, http.StatusBadRequest)
		return
	}

	// Normalize: add scheme if missing
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	result := sci.AnalyzeTarget(target)
	_ = json.NewEncoder(w).Encode(result)
}
