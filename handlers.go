package main

import (
	"DORM/analyzer"
	"DORM/bypassers"
	"DORM/cve"
	"DORM/dom"
	"DORM/models"
	"DORM/plugins"
	"DORM/sitemapper"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
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
	json.NewEncoder(w).Encode(plugins.GetPluginInventory())
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
			fmt.Fprintf(w, "data: %s\n\n", ev.ToJSON())
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
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
		w.Write([]byte("Scan stopped"))
	} else {
		w.Write([]byte("No active scan"))
	}
}

// List CVE Database (first 500 records + stats)
func handleCVEDatabase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	type CVEResponse struct {
		Stats map[string]interface{} `json:"stats"`
		CVEs  []models.LocalCVE      `json:"cves"`
	}

	json.NewEncoder(w).Encode(CVEResponse{
		Stats: cve.GetStats(),
		CVEs:  cve.GetFirst(500),
	})
}

// CVE Search
func handleCVESearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	query := r.URL.Query().Get("q")
	if query == "" {
		json.NewEncoder(w).Encode([]models.LocalCVE{})
		return
	}

	results := cve.Search(query, "")
	json.NewEncoder(w).Encode(results)
}

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
	selectedPluginsStr := r.URL.Query().Get("plugins")

	// --- UPDATE CLIENT SETTINGS (Located in client.go) ---
	GlobalAuthHeader = r.URL.Query().Get("auth")

	// Proxy Setup
	GlobalProxyEnabled = r.URL.Query().Get("proxyEnabled") == "true"
	if proxyUrl := r.URL.Query().Get("proxyUrl"); proxyUrl != "" {
		GlobalProxyURL = proxyUrl
	}
	InitTransport() // Initialize proxy transport and connection pool safely

	// --- WAF BYPASS SETTINGS ---
	bypassers.GlobalDelayConfig.BaseDelayMs = 0
	bypassers.GlobalDelayConfig.JitterMs = 0
	if delayStr := r.URL.Query().Get("wafDelay"); delayStr != "" {
		if d, err := strconv.Atoi(delayStr); err == nil {
			bypassers.GlobalDelayConfig.BaseDelayMs = d
		}
	}
	if jitterStr := r.URL.Query().Get("wafJitter"); jitterStr != "" {
		if j, err := strconv.Atoi(jitterStr); err == nil {
			bypassers.GlobalDelayConfig.JitterMs = j
		}
	}
	// ----------------------------------------------------

	if targetsParam == "" {
		return
	}

	cveRadarEnabled := r.URL.Query().Get("cveRadar") == "true"

	// ==========================================
	// 🛠️ MULTI-TARGET PARSING & SANITIZATION
	// ==========================================
	rawTargets := strings.Split(targetsParam, ",")
	var sanitizedTargets []string

	for _, t := range rawTargets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		if strings.Contains(t, "://") {
			if u, err := url.Parse(t); err == nil {
				t = u.Hostname()
			}
		} else {
			parts := strings.Split(t, "/")
			if len(parts) > 0 {
				t = parts[0]
			}
		}

		t = strings.TrimPrefix(t, "http://")
		t = strings.TrimPrefix(t, "https://")
		t = strings.TrimRight(t, "/")

		if t != "" {
			sanitizedTargets = append(sanitizedTargets, t)
		}
	}

	if len(sanitizedTargets) == 0 {
		return
	}

	fmt.Printf("[DEBUG] Sanitized Targets: %v\n", sanitizedTargets)

	// --- STORAGE INTEGRATION START (1/2) ---
	// Create a single record for this batch scan
	recordTitle := strings.Join(sanitizedTargets, ", ")
	if len(recordTitle) > 50 {
		recordTitle = recordTitle[:47] + "..."
	}
	record := NewScanRecord(recordTitle)
	DB.SaveScan(record)

	// Stream the generated ScanID back to the frontend immediately so live updates work!
	fmt.Fprintf(w, "data: {\"Status\": \"STARTED\", \"ScanID\": \"%s\"}\n\n", record.ID)
	flusher.Flush()

	var foundVulns []*models.Vulnerability
	var muVulns sync.Mutex
	// --- STORAGE INTEGRATION END ---

	// STEP 1: PRE-SCAN — Run Sitemapper + DOM-Crawler in parallel.
	//
	// Race-Free Design:
	//   goroutine A → sitemapper.Run()  → writes to its own *SiteMap
	//   goroutine B → dom.Crawl()       → writes to its own *DOMResult
	//   After BOTH finish (or timeout): domResult.MergeInto(sm) is called once,
	//   then StoreSiteMap writes to SharedData — zero concurrent writes.
	//
	// A shared prescanTimeout caps the combined pre-scan phase.
	// If either crawler finishes early, the WaitGroup just proceeds.
	const prescanTimeout = 120 * time.Second
	prescanCtx, prescanCancel := context.WithTimeout(ctx, prescanTimeout)
	defer prescanCancel()

	fmt.Printf("[*] PRE-SCAN: Sitemapper + DOM-Crawler starting for %d target(s)...\n", len(sanitizedTargets))

	var prescanWg sync.WaitGroup
	for _, host := range sanitizedTargets {
		proto := "http"
		targetURL := fmt.Sprintf("%s://%s", proto, host)

		prescanWg.Add(1)
		go func(tURL, tHost string) {
			defer prescanWg.Done()

			// ── Sub-goroutine A: Sitemapper (HTTP crawl) ──────────────────
			type smResult struct {
				sm  *sitemapper.SiteMap
				err error
			}
			smCh := make(chan smResult, 1)
			go func() {
				sm, err := sitemapper.QuickWithContext(prescanCtx, tURL, record.ID)
				smCh <- smResult{sm, err}
			}()

			// ── Sub-goroutine B: DOM-Crawler (browser crawl) ───────────────
			type domResult struct {
				result *dom.DOMResult
				err    error
			}
			domCh := make(chan domResult, 1)
			go func() {
				result, err := dom.Crawl(prescanCtx, tURL, dom.FastDOMConfig())
				domCh <- domResult{result, err}
			}()

			// ── Wait for BOTH to complete (prescanCtx deadline is the cap) ─
			var finalSM *sitemapper.SiteMap
			var finalDOM *dom.DOMResult

			for pending := 2; pending > 0; pending-- {
				select {
				case r := <-smCh:
					if r.err != nil {
						fmt.Printf("[Sitemapper] Error for %s: %v\n", tHost, r.err)
					} else {
						finalSM = r.sm
						fmt.Printf("[Sitemapper] Done for %s — pages=%d endpoints=%d\n",
							tHost, len(r.sm.Pages), len(r.sm.Endpoints))
					}
				case r := <-domCh:
					if r.err != nil {
						fmt.Printf("[DOM-Crawler] Error for %s: %v\n", tHost, r.err)
					} else {
						finalDOM = r.result
						fmt.Printf("[DOM-Crawler] Done for %s — pages=%d xhr=%d routes=%d\n",
							tHost, len(r.result.Pages), len(r.result.XHREndpoints), len(r.result.JSRoutes))
					}
				case <-prescanCtx.Done():
					fmt.Printf("[PRE-SCAN] Timeout reached for %s — using partial results\n", tHost)
					pending = 0 // exit wait loop
				}
			}

			// ── Merge: DOM result → SiteMap (single-threaded, no race) ─────
			if finalDOM != nil && finalSM != nil {
				finalDOM.MergeInto(finalSM)
				// Re-store the enriched SiteMap so downstream plugins see XHR/SPA data
				sitemapper.StoreSiteMap(finalSM)
				fmt.Printf("[PRE-SCAN] Merge complete for %s — total endpoints=%d\n",
					tHost, len(finalSM.Endpoints))
			} else if finalSM != nil {
				// DOM crawler failed/timed out — sitemapper result still valid
				sitemapper.StoreSiteMap(finalSM)
			}
		}(targetURL, host)
	}

	// ==========================================
	// STEP 1.5: SMART PORT DISCOVERY (CONCURRENT WITH PRE-SCAN)
	// ==========================================
	// We run port discovery immediately while sitemapper & dom-crawler are still running!
	fmt.Printf("[*] Discovered %d target(s) for port scanning...\n", len(sanitizedTargets))

	commonPorts := []int{
		80, 443, 8080, 8443, 8000, 8001, 8081, 8888, 3000, 5000, 9000, 9090,
		22, 23, 3389, 5900, 5901, 20, 21,
		3306, 5432, 1433, 1434, 1521, 27017, 6379, 9200,
		2375, 2376, 6443, 11211, 5672, 15672, 8500,
		25, 465, 587, 110, 995, 143, 993, 389, 636, 53, 161, 445,
	}

	type TargetPort struct {
		Host string
		Port int
	}
	var activeTargets []TargetPort
	var mu sync.Mutex
	var portWg sync.WaitGroup

	for _, host := range sanitizedTargets {
		for _, port := range commonPorts {
			select {
			case <-ctx.Done():
				fmt.Fprintf(w, "data: {\"Status\": \"DONE\"}\n\n")
				flusher.Flush()
				return
			default:
			}

			portWg.Add(1)
			go func(h string, p int) {
				defer portWg.Done()
				address := net.JoinHostPort(h, fmt.Sprintf("%d", p))
				conn, err := net.DialTimeout("tcp", address, 1*time.Second)
				if err == nil {
					conn.Close()
					mu.Lock()
					activeTargets = append(activeTargets, TargetPort{Host: h, Port: p})
					mu.Unlock()
				}
			}(host, port)
		}
	}
	portWg.Wait()
	fmt.Printf("[*] PORT DISCOVERY complete.\n")

	// ==========================================
	// WAIT FOR PRE-SCAN WITH HEARTBEATS
	// ==========================================
	// We must wait for Sitemapper and DOM Crawler to finish, but we CANNOT block
	// the thread silently, or the browser/nginx will timeout the SSE connection!
	prescanDone := make(chan struct{})
	go func() {
		prescanWg.Wait()
		close(prescanDone)
	}()

WaitLoop:
	for {
		select {
		case <-prescanDone:
			break WaitLoop
		case <-ctx.Done():
			fmt.Fprintf(w, "data: {\"Status\": \"DONE\"}\n\n")
			flusher.Flush()
			return
		case <-time.After(3 * time.Second):
			// Keep SSE connection alive while DOM crawler does its heavy lifting
			fmt.Fprintf(w, "data: {\"Status\": \"CRAWLING_DOM\"}\n\n")
			flusher.Flush()
		}
	}
	
	fmt.Printf("[*] PRE-SCAN complete — engine starting\n")


	// STEP 2: PREPARE AND RUN ENGINE
	engine := NewEngine(10) // Concurrency 10
	engine.Ctx = ctx        // PASS CONTEXT TO ENGINE

	// PLUGINS REGISTRATION
	engine.AddPlugin(&plugins.DOMScannerPlugin{}) //DOM Scanner
	engine.AddPlugin(&plugins.UnnecessaryPortsPlugin{})
	engine.AddPlugin(&plugins.FingerprintPlugin{}) //Fingerprinting
	engine.AddPlugin(&plugins.TLSCheckPlugin{})    //TLS Check
	engine.AddPlugin(&plugins.BruteForcePlugin{})  //Brute Force
	engine.AddPlugin(&SpiderPlugin{})              //Spider
	engine.AddPlugin(&plugins.EDBPlugin{})         //Exploit DB

	if cveRadarEnabled {
		engine.AddPlugin(&plugins.PassiveCVEPlugin{}) // Passive CVE (Only if selected)
	}

	engine.AddPlugin(&plugins.BannerGrabPlugin{})
	engine.AddPlugin(&plugins.HTTPHeaderPlugin{})
	engine.AddPlugin(&plugins.SSLCheckPlugin{})
	engine.AddPlugin(&plugins.DirBusterPlugin{})
	engine.AddPlugin(&plugins.CORSCheckPlugin{})
	engine.AddPlugin(&plugins.WPUserEnumPlugin{})
	engine.AddPlugin(&plugins.PHPInfoPlugin{})
	engine.AddPlugin(&plugins.WAFDetectorPlugin{})
	engine.AddPlugin(&plugins.OpenRedirectPlugin{})

	engine.AddPlugin(&plugins.SQLInjectionPlugin{})
	engine.AddPlugin(&plugins.XSSPlugin{})
	engine.AddPlugin(&plugins.LFIPlugin{})
	engine.AddPlugin(&plugins.SpringBootPlugin{})
	engine.AddPlugin(&plugins.GitConfigPlugin{})
	engine.AddPlugin(&plugins.BackupFilePlugin{})
	engine.AddPlugin(&plugins.ApacheStatusPlugin{})
	engine.AddPlugin(&plugins.DSStorePlugin{})
	engine.AddPlugin(&plugins.TraceMethodPlugin{})
	engine.AddPlugin(&plugins.EnvFilePlugin{})

	engine.AddPlugin(&plugins.CMSTestPlugin{})
	engine.AddPlugin(&plugins.AdminPanelPlugin{})
	engine.AddPlugin(&plugins.LaravelDebugPlugin{})
	engine.AddPlugin(&plugins.DockerAPIPlugin{})
	engine.AddPlugin(&plugins.CookieSecPlugin{})
	engine.AddPlugin(&plugins.SecurityTxtPlugin{})
	engine.AddPlugin(&plugins.WebDAVPlugin{})
	engine.AddPlugin(&plugins.EmailExtractPlugin{})
	engine.AddPlugin(&plugins.S3BucketPlugin{})

	engine.AddPlugin(&plugins.ClickjackingPlugin{})
	engine.AddPlugin(&plugins.GraphQLPlugin{})
	engine.AddPlugin(&plugins.SwaggerPlugin{})
	engine.AddPlugin(&plugins.HostHeaderPlugin{})
	engine.AddPlugin(&plugins.PrometheusPlugin{})
	engine.AddPlugin(&plugins.SSTIPlugin{})
	engine.AddPlugin(&plugins.HSTSPlugin{})
	engine.AddPlugin(&plugins.TomcatManagerPlugin{})
	engine.AddPlugin(&plugins.SensitiveConfigPlugin{})
	engine.AddPlugin(&plugins.PythonServerPlugin{})

	engine.AddPlugin(&plugins.BlindRCEPlugin{})
	engine.AddPlugin(&plugins.XXEPlugin{})
	engine.AddPlugin(&plugins.AdminBypassPlugin{})
	engine.AddPlugin(&plugins.CRLFPlugin{})
	engine.AddPlugin(&plugins.DangerousMethodsPlugin{})
	engine.AddPlugin(&plugins.JavaDeserializationPlugin{})
	engine.AddPlugin(&plugins.PrototypePollutionPlugin{})
	engine.AddPlugin(&plugins.TraversalPlugin{})
	engine.AddPlugin(&plugins.ConfigJsonPlugin{})
	engine.AddPlugin(&plugins.IDORPlugin{})

	engine.AddPlugin(&plugins.KubeletPlugin{})
	engine.AddPlugin(&plugins.DockerRegistryPlugin{})
	engine.AddPlugin(&plugins.JenkinsPlugin{})
	engine.AddPlugin(&plugins.RedisPlugin{})
	engine.AddPlugin(&plugins.MongoPlugin{})
	engine.AddPlugin(&plugins.ElasticPlugin{})
	engine.AddPlugin(&plugins.MemcachedPlugin{})

	engine.AddPlugin(&plugins.FTPAnonPlugin{})
	engine.AddPlugin(&plugins.SMTPRelayPlugin{})
	engine.AddPlugin(&plugins.APIKeyPlugin{})
	engine.AddPlugin(&plugins.TakeoverPlugin{})
	engine.AddPlugin(&plugins.ViewStatePlugin{})
	engine.AddPlugin(&plugins.LaravelEnvPlugin{})
	engine.AddPlugin(&plugins.ColdFusionPlugin{})
	engine.AddPlugin(&plugins.GitLabPlugin{})
	engine.AddPlugin(&plugins.NginxTraversalPlugin{})

	engine.AddPlugin(&plugins.SSRFMetadataPlugin{})
	engine.AddPlugin(&plugins.JWTWeaknessPlugin{})
	engine.AddPlugin(&plugins.StrutsPlugin{})
	engine.AddPlugin(&plugins.NoSQLPlugin{})
	engine.AddPlugin(&plugins.TerraformPlugin{})
	engine.AddPlugin(&plugins.WebSocketPlugin{})
	engine.AddPlugin(&plugins.ShadowAPIPlugin{})

	engine.AddPlugin(&plugins.RequestSmugglingPlugin{})
	engine.AddPlugin(&plugins.RaceConditionPlugin{})
	engine.AddPlugin(&plugins.WebCachePoisoningPlugin{})
	engine.AddPlugin(&plugins.FileUploadPlugin{})
	engine.AddPlugin(&plugins.WPEnumPlugin{})
	engine.AddPlugin(&plugins.TLSCipherPlugin{})

	engine.AddPlugin(&plugins.Bypass403Plugin{})
	engine.AddPlugin(&plugins.BFLABOLAPlugin{}) // BFLA/BOLA — HTTP Method Tampering + Role Escalation
	engine.AddPlugin(&plugins.IPSpoofPlugin{})  // IP Spoof — Rate-Limit & WAF Bypass
	engine.AddPlugin(&plugins.PromptInjectionPlugin{})

	// ── Framework-Specific Security Misconfiguration Plugins ──
	engine.AddPlugin(&plugins.DjangoPlugin{})
	engine.AddPlugin(&plugins.RailsPlugin{})
	engine.AddPlugin(&plugins.AspNetCorePlugin{})
	engine.AddPlugin(&plugins.ExpressJSPlugin{})
	engine.AddPlugin(&plugins.NextJSPlugin{})
	engine.AddPlugin(&plugins.NestJSPlugin{})
	engine.AddPlugin(&plugins.FastAPIPlugin{})
	engine.AddPlugin(&plugins.SymfonyPlugin{})
	engine.AddPlugin(&plugins.CodeIgniterPlugin{})

	// Apply User Filters
	engine.SetFilter(selectedPluginsStr)

	if len(activeTargets) == 0 {
		// Send explicit error to frontend so it doesn't just silently stop
		fmt.Fprintf(w, "data: {\"Status\": \"ERROR\", \"Message\": \"No reachable ports found for the provided target(s). Check your input or network.\"}\n\n")
		fmt.Fprintf(w, "data: {\"Status\": \"DONE\"}\n\n")
		flusher.Flush()
		record.Status = "Failed"
		record.EndTime = time.Now()
		DB.UpdateScan(record.ID, record)
		return
	}

	// ADD ALL DISCOVERED TARGET/PORT COMBINATIONS TO ENGINE
	for _, tp := range activeTargets {
		engine.AddTarget(tp.Host, tp.Port)
	}

	// Capture and Stream Findings
	engine.OnFind = func(v *models.Vulnerability) {
		// 1. Send to Frontend via SSE
		data, _ := json.Marshal(v)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()

		// 2. Capture for Database Storage
		muVulns.Lock()
		foundVulns = append(foundVulns, v)
		muVulns.Unlock()
	}

	// Link Analyzer's passive findings to the main engine output
	analyzer.OnVulnFound = engine.OnFind

	engine.Start()

	// --- STORAGE INTEGRATION START (2/2) ---
	record.EndTime = time.Now()
	record.Status = "Completed"
	record.Vulnerabilities = foundVulns
	record.TotalVulns = len(foundVulns)

	stats := make(map[string]int)
	for _, v := range foundVulns {
		stats[v.Severity]++
	}
	record.SeverityStats = stats

	DB.UpdateScan(record.ID, record)
	// --- STORAGE INTEGRATION END ---

	fmt.Fprintf(w, "data: {\"Status\": \"DONE\"}\n\n")
	flusher.Flush()
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
		json.NewEncoder(w).Encode(sm)
		return
	}

	// 2. Fall back to database
	sm, err := DB.GetSiteMap(host, scanID)
	if err != nil {
		http.Error(w, `{"error":"No sitemap found for this target. Run a scan first."}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(sm)
}

// handleSiteMapList returns the list of hosts that have a stored SiteMap for a specific scanID.
func handleSiteMapList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		json.NewEncoder(w).Encode([]string{})
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
	json.NewEncoder(w).Encode(hosts)
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

	json.NewEncoder(w).Encode(records)
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
	DB.DeleteSiteMapsByScanID(scanID)

	fmt.Fprintf(w, `{"status":"success"}`)
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
	DB.DeleteAllSiteMaps()

	fmt.Fprintf(w, `{"status":"success"}`)
}
