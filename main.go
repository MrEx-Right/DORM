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
				if len(e.AllowedPlugins) > 0 {
					if !e.AllowedPlugins[job.Plugin.Name()] {
						continue
					}
				}

				// --- [RATE LIMIT PROTECTION] ---
				// 300ms Backend Delay to prevent DoS
				time.Sleep(300 * time.Millisecond)
				// -------------------------------

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

	// --- UPDATE CLIENT SETTINGS (Located in client.go) ---

	// 1. Chameleon Mode
	rotateParam := r.URL.Query().Get("rotateUA")
	if rotateParam == "true" {
		GlobalRotateUA = true
	} else {
		GlobalRotateUA = false
	}

	// 2. Auth Header (Cookie/Token)
	authParam := r.URL.Query().Get("auth")
	GlobalAuthHeader = authParam
	// ----------------------------------------------------

	// 3. VALIDATION
	if targetHost == "" {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	// --- STORAGE INTEGRATION START (1/2) ---
	record := NewScanRecord(targetHost)
	DB.SaveScan(record)

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
	engine := NewEngine(10) // Concurrency 10

	// PLUGINS REGISTRATION
	engine.AddPlugin(&DOMScannerPlugin{})  //DOM Scanner
	engine.AddPlugin(&FingerprintPlugin{}) //Fingerprinting
	engine.AddPlugin(&TLSCheckPlugin{})    //TLS Check
	engine.AddPlugin(&BruteForcePlugin{})  //Brute Force
	engine.AddPlugin(&SpiderPlugin{})      //Spider
	engine.AddPlugin(&EDBPlugin{})         //Exploit DB
	engine.AddPlugin(&FuzzerPlugin{})      //Fuzzer

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

func main() {
	// 1. Initialize the Database
	InitDB("scans.json")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "dashboard.html")
	})
	http.HandleFunc("/scan", handleScan)
	http.HandleFunc("/plugins", handlePluginList)

	// 2. Register History API Routes
	http.HandleFunc("/api/history", handleHistory)
	http.HandleFunc("/api/history/delete", handleDelete)

	port := ":8080"
	url := "http://localhost" + port

	fmt.Println("===========================================")
	fmt.Println("       DORM SCANNER v1.3.0                 ")
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
