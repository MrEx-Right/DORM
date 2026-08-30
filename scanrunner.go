package main

import (
	"DORM/analyzer"
	"DORM/bypassers"
	"DORM/dom"
	"DORM/models"
	"DORM/plugins"
	"DORM/plugins/idorengine"
	"DORM/plugins/nosqliengine"
	"DORM/plugins/sqliengine"
	"DORM/plugins/wafengine"
	"DORM/plugins/xssengine"
	"DORM/sitemapper"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// scanExecMu serializes the network-issuing phase of a scan (active client
// setup, WAF delay config, and engine.Start()) across concurrent runs.
//
// DORM's plugin surface (83 files) reads the process-global models.GetClient()
// and models.SharedData rather than taking a per-run client/context — making
// every concurrent run fully parallel-safe would mean touching that entire
// surface. Instead, this mutex lets any number of DORM Vectors be configured,
// scheduled, queued and cancelled fully independently and concurrently (real
// goroutines drive each Vector's lifecycle, see vectors/vectors.go), while
// only ever letting ONE run's engine actually be issuing HTTP requests
// against the shared globals at a time. That is enough to fix the
// pre-existing bug where starting a second scan silently cancelled the first
// (single global activeScanCancel), without a large, risky rewrite of every
// plugin.
var scanExecMu sync.Mutex

// runScanCore executes one complete scan pass — target sanitization, the
// sitemapper/DOM-crawler pre-scan, port discovery, and the plugin engine —
// reporting progress through emit (one JSON payload per SSE-style event,
// without the "data: " envelope). It has no knowledge of persistence or of
// DORM Vectors: it just runs a scan and returns the outcome. Wired into
// models.RunScan at startup (main.go) so the vectors package — which cannot
// import package main — can trigger real scans without ever seeing engine.go
// or client.go.
func runScanCore(ctx context.Context, scanID string, cfg models.ScanRunConfig, emit func(payload string), onStart func(target string)) models.ScanOutcome {
	// ==========================================
	// 🛠️ MULTI-TARGET PARSING & SANITIZATION
	// ==========================================
	var sanitizedTargets []string
	for _, t := range cfg.Targets {
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
		return models.ScanOutcome{Status: "Failed", StartTime: time.Now(), EndTime: time.Now(), SeverityStats: map[string]int{}}
	}

	fmt.Printf("[DEBUG] Sanitized Targets: %v\n", sanitizedTargets)

	title := strings.Join(sanitizedTargets, ", ")
	if len(title) > 50 {
		title = title[:47] + "..."
	}
	startTime := time.Now()
	if onStart != nil {
		onStart(title)
	}
	emit(fmt.Sprintf(`{"Status": "STARTED", "ScanID": "%s"}`, scanID))

	var foundVulns []*models.Vulnerability
	var muVulns sync.Mutex

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
				sm, err := sitemapper.QuickWithContext(prescanCtx, tURL, scanID)
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
				emit(`{"Status": "DONE"}`)
				return models.ScanOutcome{Status: "Stopped", StartTime: startTime, EndTime: time.Now(), SeverityStats: map[string]int{}}
			default:
			}

			portWg.Add(1)
			go func(h string, p int) {
				defer portWg.Done()
				address := net.JoinHostPort(h, fmt.Sprintf("%d", p))
				conn, err := net.DialTimeout("tcp", address, 1*time.Second)
				if err == nil {
					_ = conn.Close()
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
			emit(`{"Status": "DONE"}`)
			return models.ScanOutcome{Status: "Stopped", StartTime: startTime, EndTime: time.Now(), SeverityStats: map[string]int{}}
		case <-time.After(3 * time.Second):
			// Keep SSE connection alive while DOM crawler does its heavy lifting
			emit(`{"Status": "CRAWLING_DOM"}`)
		}
	}

	fmt.Printf("[*] PRE-SCAN complete — engine starting\n")

	// STEP 2: PREPARE AND RUN ENGINE
	engine := NewEngine(10) // Concurrency 10
	engine.Ctx = ctx         // PASS CONTEXT TO ENGINE

	// ── Engine-Powered Plugins (Prioritized) ──
	engine.AddPlugin(&wafengine.WAFDetectorPlugin{})   // WAF Detection — Runs FIRST
	engine.AddPlugin(&xssengine.XSSPlugin{})           // XSS Engine
	engine.AddPlugin(&sqliengine.SQLInjectionPlugin{}) // SQLi Engine
	engine.AddPlugin(&nosqliengine.NoSQLPlugin{})      // NoSQLi Engine
	engine.AddPlugin(&idorengine.IDORPlugin{})         // IDOR Engine

	engine.AddPlugin(&plugins.FingerprintPlugin{}) //Fingerprinting
	engine.AddPlugin(&plugins.TLSCheckPlugin{})    //TLS Check
	engine.AddPlugin(&plugins.BruteForcePlugin{})  //Brute Force
	engine.AddPlugin(&SpiderPlugin{})              //Spider
	engine.AddPlugin(&plugins.EDBPlugin{})         //Exploit DB

	// Passive CVE Check
	if cfg.CVERadar {
		engine.AddPlugin(&plugins.PassiveCVEPlugin{}) // Passive CVE (Only if selected)
	}

	// Active Core Scanners
	engine.AddPlugin(&plugins.BannerGrabPlugin{})
	engine.AddPlugin(&plugins.HTTPHeaderPlugin{})
	engine.AddPlugin(&plugins.SSLCheckPlugin{})
	engine.AddPlugin(&plugins.DirBusterPlugin{})
	engine.AddPlugin(&plugins.CORSCheckPlugin{})
	engine.AddPlugin(&plugins.WPUserEnumPlugin{})
	engine.AddPlugin(&plugins.PHPInfoPlugin{})
	engine.AddPlugin(&plugins.OpenRedirectPlugin{})

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
	engine.AddPlugin(&plugins.TerraformPlugin{})
	engine.AddPlugin(&plugins.WebSocketPlugin{})
	engine.AddPlugin(&plugins.ShadowAPIPlugin{})

	engine.AddPlugin(&plugins.RequestSmugglingPlugin{})
	engine.AddPlugin(&plugins.RaceConditionPlugin{})
	engine.AddPlugin(&plugins.WebCachePoisoningPlugin{})
	engine.AddPlugin(&plugins.FileUploadPlugin{})
	engine.AddPlugin(&plugins.WPEnumPlugin{})
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
	engine.SetFilter(cfg.PluginFilter)

	if len(activeTargets) == 0 {
		// Send explicit error to frontend so it doesn't just silently stop
		emit(`{"Status": "ERROR", "Message": "No reachable ports found for the provided target(s). Check your input or network."}`)
		emit(`{"Status": "DONE"}`)
		return models.ScanOutcome{Status: "Failed", StartTime: startTime, EndTime: time.Now(), SeverityStats: map[string]int{}}
	}

	// ADD ALL DISCOVERED TARGET/PORT COMBINATIONS TO ENGINE
	for _, tp := range activeTargets {
		engine.AddTarget(tp.Host, tp.Port)
	}

	// Capture and Stream Findings
	engine.OnFind = func(v *models.Vulnerability) {
		// 1. Send to Frontend via SSE
		data, _ := json.Marshal(v)
		emit(string(data))

		// 2. Capture for the outcome
		muVulns.Lock()
		foundVulns = append(foundVulns, v)
		muVulns.Unlock()
	}

	// --- SERIALIZED NETWORK-ISSUING PHASE ---
	// Everything here touches process-global state shared by all ~90 plugins
	// (active HTTP client, WAF delay/jitter, the analyzer's passive-finding
	// callback). Locking around it is what lets multiple Vectors run
	// independently without corrupting each other's auth/proxy/plugin output —
	// but it also means a run can sit blocked here for the ENTIRE duration of
	// another run's engine phase. Emit QUEUED/SCANNING so the UI can tell
	// "waiting for the engine to free up" apart from "actively scanning, zero
	// findings so far yet" instead of showing a bare "Running" the whole time.
	emit(`{"Status": "QUEUED"}`)
	scanExecMu.Lock()
	emit(`{"Status": "SCANNING"}`)
	SetActiveClient(cfg.AuthHeader, cfg.ProxyEnabled, cfg.ProxyURL)
	bypassers.GlobalDelayConfig.BaseDelayMs = cfg.WAFDelayMs
	bypassers.GlobalDelayConfig.JitterMs = cfg.WAFJitterMs
	analyzer.OnVulnFound = engine.OnFind // Link Analyzer's passive findings to the main engine output
	engine.Start()
	scanExecMu.Unlock()
	// -----------------------------------------

	stats := make(map[string]int)
	for _, v := range foundVulns {
		stats[v.Severity]++
	}

	emit(`{"Status": "DONE"}`)

	return models.ScanOutcome{
		Status:          "Completed",
		StartTime:       startTime,
		EndTime:         time.Now(),
		Vulnerabilities: foundVulns,
		TotalVulns:      len(foundVulns),
		SeverityStats:   stats,
	}
}
