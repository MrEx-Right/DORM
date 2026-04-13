package main

import (
	"DORM/models"
	"DORM/plugins"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
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
	if r.URL.Query().Get("rotateUA") == "true" {
		GlobalRotateUA = true
	} else {
		GlobalRotateUA = false
	}
	GlobalAuthHeader = r.URL.Query().Get("auth")
	// ----------------------------------------------------

	if targetsParam == "" {
		return
	}

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

	var foundVulns []*models.Vulnerability
	var muVulns sync.Mutex
	// --- STORAGE INTEGRATION END ---

	// STEP 1: SMART PORT DISCOVERY (FAST PRE-SCAN)
	fmt.Printf("[*] Discovered %d target(s) for scanning...\n", len(sanitizedTargets))

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
	var wg sync.WaitGroup

	// Scan all ports for ALL provided targets
	for _, host := range sanitizedTargets {
		for _, port := range commonPorts {
			select {
			case <-ctx.Done():
				fmt.Fprintf(w, "data: {\"Status\": \"DONE\"}\n\n")
				flusher.Flush()
				return
			default:
			}

			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()
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
	wg.Wait()

	// STEP 2: PREPARE AND RUN ENGINE
	engine := NewEngine(10) // Concurrency 10
	engine.Ctx = ctx        // PASS CONTEXT TO ENGINE

	// PLUGINS REGISTRATION
	engine.AddPlugin(&plugins.DOMScannerPlugin{})  //DOM Scanner
	engine.AddPlugin(&plugins.FingerprintPlugin{}) //Fingerprinting
	engine.AddPlugin(&plugins.TLSCheckPlugin{})    //TLS Check
	engine.AddPlugin(&plugins.BruteForcePlugin{})  //Brute Force
	engine.AddPlugin(&SpiderPlugin{})              //Spider
	engine.AddPlugin(&plugins.EDBPlugin{})         //Exploit DB
	engine.AddPlugin(&plugins.PassiveCVEPlugin{})  //Passive CVE

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
	engine.AddPlugin(&plugins.ShellshockPlugin{})
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

	engine.AddPlugin(&plugins.Log4jPlugin{})
	engine.AddPlugin(&plugins.KubeletPlugin{})
	engine.AddPlugin(&plugins.DockerRegistryPlugin{})
	engine.AddPlugin(&plugins.SpringCloudPlugin{})
	engine.AddPlugin(&plugins.F5BigIPPlugin{})
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
	engine.AddPlugin(&plugins.DrupalPlugin{})
	engine.AddPlugin(&plugins.GitLabPlugin{})
	engine.AddPlugin(&plugins.NginxTraversalPlugin{})

	engine.AddPlugin(&plugins.SSRFMetadataPlugin{})
	engine.AddPlugin(&plugins.JWTWeaknessPlugin{})
	engine.AddPlugin(&plugins.StrutsPlugin{})
	engine.AddPlugin(&plugins.CitrixPlugin{})
	engine.AddPlugin(&plugins.NoSQLPlugin{})
	engine.AddPlugin(&plugins.ConfluencePlugin{})
	engine.AddPlugin(&plugins.TerraformPlugin{})
	engine.AddPlugin(&plugins.WebSocketPlugin{})
	engine.AddPlugin(&plugins.TeamCityPlugin{})
	engine.AddPlugin(&plugins.ShadowAPIPlugin{})

	engine.AddPlugin(&plugins.RequestSmugglingPlugin{})
	engine.AddPlugin(&plugins.RaceConditionPlugin{})
	engine.AddPlugin(&plugins.WebCachePoisoningPlugin{})
	engine.AddPlugin(&plugins.FileUploadPlugin{})
	engine.AddPlugin(&plugins.WPEnumPlugin{})
	engine.AddPlugin(&plugins.TLSCipherPlugin{})

	// Apply User Filters
	engine.SetFilter(selectedPluginsStr)

	if len(activeTargets) == 0 {
		fmt.Fprintf(w, "data: {\"Status\": \"DONE\"}\n\n")
		flusher.Flush()
		record.Status = "Completed"
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

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	err := DB.DeleteScan(id)
	if err != nil {
		http.Error(w, "Failed to delete: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Scan deleted successfully"))
}
