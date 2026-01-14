package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ==========================================
// 1. STRUCTURAL DEFINITIONS
// ==========================================

type ScanTarget struct {
	IP   string
	Port int
}

type Vulnerability struct {
	Target      ScanTarget
	Name        string
	Severity    string
	CVSS        float64
	Description string
	Solution    string
	Reference   string
	Status      string
}

type ScannerPlugin interface {
	Name() string
	Run(target ScanTarget) *Vulnerability
}

type Engine struct {
	Targets        []ScanTarget
	Plugins        []ScannerPlugin
	Concurrency    int
	Results        []Vulnerability
	mu             sync.Mutex
	OnFind         func(v *Vulnerability)
	AllowedPlugins map[string]bool
}

// ==========================================
// 2. ENGINE LOGIC
// ==========================================

func NewEngine(concurrency int) *Engine {
	return &Engine{
		Concurrency:    concurrency,
		Plugins:        []ScannerPlugin{},
		Results:        []Vulnerability{},
		AllowedPlugins: make(map[string]bool),
	}
}

func (e *Engine) AddPlugin(p ScannerPlugin) {
	e.Plugins = append(e.Plugins, p)
}

func (e *Engine) AddTarget(ip string, port int) {
	e.Targets = append(e.Targets, ScanTarget{IP: ip, Port: port})
}

// FILTER FUNCTION (For Plugin Selection)
func (e *Engine) SetFilter(pluginNames string) {
	if pluginNames == "" || pluginNames == "ALL" {
		return
	}
	names := strings.Split(pluginNames, ",")
	for _, n := range names {
		e.AllowedPlugins[n] = true
	}
}

func (e *Engine) Start() {
	var wg sync.WaitGroup
	type Job struct {
		Target ScanTarget
		Plugin ScannerPlugin
	}
	jobs := make(chan Job, 1000)

	for w := 1; w <= e.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				// FILTER CHECK
				// If filter is active and this plugin is not selected -> SKIP
				if len(e.AllowedPlugins) > 0 {
					if !e.AllowedPlugins[job.Plugin.Name()] {
						continue
					}
				}

				// --- [RATE LIMIT KORUMASI] ---
				// Her bir worker işlem yapmadan önce 300ms bekler.
				// Bu sayede sunucuyu boğmadan (DoS yapmadan) tarama yapar.
				time.Sleep(300 * time.Millisecond)
				// -----------------------------

				vuln := job.Plugin.Run(job.Target)
				if vuln != nil {
					e.mu.Lock()
					e.Results = append(e.Results, *vuln)
					e.mu.Unlock()
					if e.OnFind != nil {
						e.OnFind(vuln)
					}
				}
			}
		}()
	}

	for _, target := range e.Targets {
		for _, plugin := range e.Plugins {
			jobs <- Job{Target: target, Plugin: plugin}
		}
	}
	close(jobs)
	wg.Wait()
}

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
	json.NewEncoder(w).Encode(GetPluginInventory())
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	targetHost := r.URL.Query().Get("target")
	selectedPluginsStr := r.URL.Query().Get("plugins")

	rotateParam := r.URL.Query().Get("rotateUA")

	if rotateParam == "true" {
		GlobalRotateUA = true
	} else {
		GlobalRotateUA = false
	}
	// ----------------------------------

	// 3. VALIDATION
	if targetHost == "" {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	// --- STORAGE INTEGRATION START (1/2) ---
	// Initialize a new scan record and save it as "Running"
	record := NewScanRecord(targetHost)
	DB.SaveScan(record)

	// We need a slice to capture vulnerabilities as they are found,
	// because SSE streams them one by one, but Storage needs the full list.
	var foundVulns []*Vulnerability
	var muVulns sync.Mutex
	// --- STORAGE INTEGRATION END ---

	// STEP 1: SMART PORT DISCOVERY (FAST PRE-SCAN)
	fmt.Printf("[*] %s is being scanned...\n", targetHost)

	commonPorts := []int{
		// --- WEB & PROXY ---
		80, 443, 8080, 8443, 8000, 8001, 8081, 8888, 3000, 5000, 9000, 9090,
		// --- REMOTE ACCESS & MGMT ---
		22, 23, 3389, 5900, 5901, 20, 21,
		// --- DATABASES ---
		3306, 5432, 1433, 1434, 1521, 27017, 6379, 9200,
		// --- DEV OPS & CLOUD & API ---
		2375, 2376, 6443, 11211, 5672, 15672, 8500,
		// --- SERVICES & OTHERS ---
		25, 465, 587, 110, 995, 143, 993, 389, 636, 53, 161, 445,
	}

	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := net.JoinHostPort(targetHost, fmt.Sprintf("%d", p))
			// Fast check: 1 second timeout
			conn, err := net.DialTimeout("tcp", address, 1*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	// STEP 2: PREPARE AND RUN ENGINE
	// [HIZ AYARI]: Concurrency'yi 50'den 10'a düşürdük. Daha az paralel istek = Daha az yük.
	engine := NewEngine(10)

	// PLUGINS REGISTRATION
	engine.AddPlugin(&DOMScannerPlugin{}) // DOM Based Scanner

	engine.AddPlugin(&FingerprintPlugin{}) // Service
	engine.AddPlugin(&TLSCheckPlugin{})    // Encryption
	engine.AddPlugin(&BruteForcePlugin{})  // Brute Force
	engine.AddPlugin(&SpiderPlugin{})      // Spider
	engine.AddPlugin(&EDBPlugin{})         // Exploit-DB
	engine.AddPlugin(&FuzzerPlugin{})      // Fuzzer

	engine.AddPlugin(&BannerGrabPlugin{})
	engine.AddPlugin(&HTTPHeaderPlugin{})
	engine.AddPlugin(&SSLCheckPlugin{})
	engine.AddPlugin(&DirBusterPlugin{})
	engine.AddPlugin(&CORSCheckPlugin{})
	engine.AddPlugin(&WPUserEnumPlugin{})
	engine.AddPlugin(&PHPInfoPlugin{})
	engine.AddPlugin(&WAFDetectorPlugin{})
	engine.AddPlugin(&OpenRedirectPlugin{})

	engine.AddPlugin(&SQLInjectionPlugin{})
	engine.AddPlugin(&XSSPlugin{})
	engine.AddPlugin(&LFIPlugin{})
	engine.AddPlugin(&SpringBootPlugin{})
	engine.AddPlugin(&GitConfigPlugin{})
	engine.AddPlugin(&BackupFilePlugin{})
	engine.AddPlugin(&ApacheStatusPlugin{})
	engine.AddPlugin(&DSStorePlugin{})
	engine.AddPlugin(&TraceMethodPlugin{})
	engine.AddPlugin(&EnvFilePlugin{})

	engine.AddPlugin(&CMSTestPlugin{})
	engine.AddPlugin(&AdminPanelPlugin{})
	engine.AddPlugin(&ShellshockPlugin{})
	engine.AddPlugin(&LaravelDebugPlugin{})
	engine.AddPlugin(&DockerAPIPlugin{})
	engine.AddPlugin(&CookieSecPlugin{})
	engine.AddPlugin(&SecurityTxtPlugin{})
	engine.AddPlugin(&WebDAVPlugin{})
	engine.AddPlugin(&EmailExtractPlugin{})
	engine.AddPlugin(&S3BucketPlugin{})

	engine.AddPlugin(&ClickjackingPlugin{})
	engine.AddPlugin(&GraphQLPlugin{})
	engine.AddPlugin(&SwaggerPlugin{})
	engine.AddPlugin(&HostHeaderPlugin{})
	engine.AddPlugin(&PrometheusPlugin{})
	engine.AddPlugin(&SSTIPlugin{})
	engine.AddPlugin(&HSTSPlugin{})
	engine.AddPlugin(&TomcatManagerPlugin{})
	engine.AddPlugin(&SensitiveConfigPlugin{})
	engine.AddPlugin(&PythonServerPlugin{})

	engine.AddPlugin(&BlindRCEPlugin{})
	engine.AddPlugin(&XXEPlugin{})
	engine.AddPlugin(&AdminBypassPlugin{})
	engine.AddPlugin(&CRLFPlugin{})
	engine.AddPlugin(&DangerousMethodsPlugin{})
	engine.AddPlugin(&JavaDeserializationPlugin{})
	engine.AddPlugin(&PrototypePollutionPlugin{})
	engine.AddPlugin(&TraversalPlugin{})
	engine.AddPlugin(&ConfigJsonPlugin{})
	engine.AddPlugin(&IDORPlugin{})

	engine.AddPlugin(&Log4jPlugin{})
	engine.AddPlugin(&KubeletPlugin{})
	engine.AddPlugin(&DockerRegistryPlugin{})
	engine.AddPlugin(&SpringCloudPlugin{})
	engine.AddPlugin(&F5BigIPPlugin{})
	engine.AddPlugin(&JenkinsPlugin{})
	engine.AddPlugin(&RedisPlugin{})
	engine.AddPlugin(&MongoPlugin{})
	engine.AddPlugin(&ElasticPlugin{})
	engine.AddPlugin(&MemcachedPlugin{})

	engine.AddPlugin(&FTPAnonPlugin{})
	engine.AddPlugin(&SMTPRelayPlugin{})
	engine.AddPlugin(&APIKeyPlugin{})
	engine.AddPlugin(&TakeoverPlugin{})
	engine.AddPlugin(&ViewStatePlugin{})
	engine.AddPlugin(&LaravelEnvPlugin{})
	engine.AddPlugin(&ColdFusionPlugin{})
	engine.AddPlugin(&DrupalPlugin{})
	engine.AddPlugin(&GitLabPlugin{})
	engine.AddPlugin(&NginxTraversalPlugin{})

	engine.AddPlugin(&SSRFMetadataPlugin{})
	engine.AddPlugin(&JWTWeaknessPlugin{})
	engine.AddPlugin(&StrutsPlugin{})
	engine.AddPlugin(&CitrixPlugin{})
	engine.AddPlugin(&NoSQLPlugin{})
	engine.AddPlugin(&ConfluencePlugin{})
	engine.AddPlugin(&TerraformPlugin{})
	engine.AddPlugin(&WebSocketPlugin{})
	engine.AddPlugin(&TeamCityPlugin{})
	engine.AddPlugin(&ShadowAPIPlugin{})

	// Apply User Filters
	engine.SetFilter(selectedPluginsStr)

	if len(openPorts) == 0 {
		fmt.Fprintf(w, "data: {\"Status\": \"DONE\"}\n\n")
		flusher.Flush()
		// Even if no ports found, update record to completed
		record.Status = "Completed"
		record.EndTime = time.Now()
		DB.UpdateScan(record.ID, record)
		return
	}

	for _, p := range openPorts {
		engine.AddTarget(targetHost, p)
	}

	// Capture and Stream Findings
	engine.OnFind = func(v *Vulnerability) {
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
	// Update the record with results and finalize status
	record.EndTime = time.Now()
	record.Status = "Completed"
	record.Vulnerabilities = foundVulns
	record.TotalVulns = len(foundVulns)

	// Calculate severity statistics
	stats := make(map[string]int)
	for _, v := range foundVulns {
		stats[v.Severity]++
	}
	record.SeverityStats = stats

	// Save final state to DB
	DB.UpdateScan(record.ID, record)
	// --- STORAGE INTEGRATION END ---

	fmt.Fprintf(w, "data: {\"Status\": \"DONE\"}\n\n")
	flusher.Flush()
}

// New struct for CPP Integration (If needed)
type CPPScanResult struct {
	Target struct {
		IP   string `json:"IP"`
		Port int    `json:"Port"`
	} `json:"Target"`
	Name        string  `json:"Name"`
	Severity    string  `json:"Severity"`
	CVSS        float64 `json:"CVSS"`
	Description string  `json:"Description"`
	Banner      string  `json:"Banner"`
}

// --- HISTORY API HANDLERS ---

// handleHistory returns the full list of past scans as JSON.
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

// handleDelete removes a specific scan record by ID.
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

func main() {
	// 1. Initialize the Database (Auto-creates scans.json)
	InitDB("scans.json")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "dashboard.html")
	})
	http.HandleFunc("/scan", handleScan)
	http.HandleFunc("/plugins", handlePluginList)

	// 2. Register History API Routes
	http.HandleFunc("/api/history", handleHistory)       // GET: List all scans
	http.HandleFunc("/api/history/delete", handleDelete) // POST: Delete a scan by ID

	port := ":8080"
	url := "http://localhost" + port

	fmt.Println("===========================================")
	fmt.Println("   	DORM SCANNER v1.2.0                 ")
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

// ==========================================
// 4. CHAMELEON MODE (USER-AGENT ROTATION)
// ==========================================

// Global Flag to control rotation (Simple implementation)
var GlobalRotateUA bool = false

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

func getRandomUserAgent() string {
	// Simple random selection
	return userAgents[time.Now().UnixNano()%int64(len(userAgents))]
}

// --- PROXY MIDDLEWARE ---
type UARoundTripper struct {
	Proxied http.RoundTripper
}

func (urt *UARoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// ONLY rotate if the checkbox was checked (Global Flag is true)
	if GlobalRotateUA {
		req.Header.Set("User-Agent", getRandomUserAgent())
	}
	return urt.Proxied.RoundTrip(req)
}

// Client Helper
func getClient() *http.Client {
	return &http.Client{

		Transport: &UARoundTripper{Proxied: http.DefaultTransport},
		Timeout:   10 * time.Second,
	}
}
