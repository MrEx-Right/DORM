package main

import (
	"DORM/models"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var activeScanCancel context.CancelFunc

type Engine struct {
	Targets        []models.ScanTarget
	Plugins        []models.ScannerPlugin
	Concurrency    int
	Results        []models.Vulnerability
	mu             sync.Mutex
	OnFind         func(v *models.Vulnerability)
	AllowedPlugins map[string]bool
	Ctx            context.Context
}

func NewEngine(concurrency int) *Engine {
	return &Engine{
		Concurrency:    concurrency,
		Plugins:        []models.ScannerPlugin{},
		Results:        []models.Vulnerability{},
		AllowedPlugins: make(map[string]bool),
	}
}

func (e *Engine) AddPlugin(p models.ScannerPlugin) {
	e.Plugins = append(e.Plugins, p)
}

func (e *Engine) AddTarget(ip string, port int) {
	e.Targets = append(e.Targets, models.ScanTarget{IP: ip, Port: port})
}

func (e *Engine) SetFilter(pluginNames string) {
	if pluginNames == "" || pluginNames == "ALL" {
		return
	}
	names := strings.Split(pluginNames, ",")
	for _, n := range names {
		e.AllowedPlugins[n] = true
	}
}

// pluginTimeout bounds how long a single plugin's Run() call is allowed to
// occupy a worker slot. Plugins take no context and cannot be interrupted
// mid-flight — a stuck or pathologically slow one (e.g. a large-wordlist
// brute-forcer against an unresponsive host) would otherwise hang an entire
// scan indefinitely, with Stop() unable to do anything about it since
// cancellation is only ever checked between jobs, never inside one.
const pluginTimeout = 45 * time.Second

// runPluginBounded runs a plugin in its own goroutine and returns as soon as
// it finishes, ctx is cancelled, or pluginTimeout elapses — whichever comes
// first. A plugin that times out keeps running in the background (Go has no
// way to force-kill a goroutine) but the worker moves on immediately instead
// of waiting on it forever; its eventual result, if any, is discarded into
// the buffered channel and the goroutine exits cleanly.
func runPluginBounded(ctx context.Context, p models.ScannerPlugin, target models.ScanTarget, timeout time.Duration) *models.Vulnerability {
	resultCh := make(chan *models.Vulnerability, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[Engine] Plugin %s panicked for %s:%d — %v\n", p.Name(), target.IP, target.Port, r)
				resultCh <- nil
			}
		}()
		resultCh <- p.Run(target)
	}()

	select {
	case v := <-resultCh:
		return v
	case <-ctx.Done():
		return nil
	case <-time.After(timeout):
		fmt.Printf("[Engine] Plugin %s timed out after %s for %s:%d — skipping\n", p.Name(), timeout, target.IP, target.Port)
		return nil
	}
}

func (e *Engine) Start() {
	var wg sync.WaitGroup
	type Job struct {
		Target models.ScanTarget
		Plugin models.ScannerPlugin
	}
	jobs := make(chan Job, 1000)

	for w := 1; w <= e.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-e.Ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}

					select {
					case <-e.Ctx.Done():
						return
					default:
					}

					if len(e.AllowedPlugins) > 0 {
						if !e.AllowedPlugins[job.Plugin.Name()] {
							continue
						}
					}

					time.Sleep(300 * time.Millisecond)

					vuln := runPluginBounded(e.Ctx, job.Plugin, job.Target, pluginTimeout)
					if vuln != nil {
						e.mu.Lock()
						e.Results = append(e.Results, *vuln)
						e.mu.Unlock()
						if e.OnFind != nil {
							e.OnFind(vuln)
						}
					}
				}
			}
		}()
	}

	go func() {
		for _, target := range e.Targets {
			for _, plugin := range e.Plugins {
				select {
				case <-e.Ctx.Done(): 
					goto FINISH
				case jobs <- Job{Target: target, Plugin: plugin}:
				}
			}
		}
	FINISH:
		close(jobs)
	}()

	wg.Wait()
}

// ==========================================
// DORM DEEP FINGERPRINTING ENGINE
// ==========================================

var scanCache sync.Map

func DeepScanTarget(targetURL string) *models.TechProfile {

	if cached, ok := scanCache.Load(targetURL); ok {
		return cached.(*models.TechProfile)
	}

	profile := &models.TechProfile{}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		return profile
	}
	req.Header.Set("User-Agent", "DORM-Enterprise-Scanner/1.5.0")

	resp, err := client.Do(req)
	if err != nil {
		return profile
	}
	defer func() { _ = resp.Body.Close() }()

	re := regexp.MustCompile(`(?i)([a-zA-Z0-9\-\.]+)(?:/|\s+v?)([0-9]+(?:\.[0-9]+)+)`)
	headersToScan := []string{"Server", "X-Powered-By", "X-Generator"}

	for _, h := range headersToScan {
		val := resp.Header.Get(h)
		if val == "" {
			continue
		}

		matches := re.FindAllStringSubmatch(val, -1)
		for _, m := range matches {
			if len(m) >= 3 {
				prodName := strings.ToLower(m[1])
				if prodName == "microsoft-iis" {
					prodName = "iis"
				}
				profile.Techs = append(profile.Techs, models.TechNode{
					Product: prodName,
					Version: m[2],
				})
			}
		}

		if h == "X-Generator" && len(matches) == 0 {
			profile.Techs = append(profile.Techs, models.TechNode{
				Product: strings.ToLower(strings.Split(val, " ")[0]),
				Version: "",
			})
		}
	}

	for _, cookie := range resp.Cookies() {
		cookieName := strings.ToUpper(cookie.Name)
		if strings.Contains(cookieName, "JSESSIONID") {
			profile.Techs = append(profile.Techs, models.TechNode{Product: "java", Version: ""})
		} else if strings.Contains(cookieName, "PHPSESSID") {
			profile.Techs = append(profile.Techs, models.TechNode{Product: "php", Version: ""})
		} else if strings.Contains(cookieName, "ASPSESSIONID") || strings.Contains(cookieName, "ASP.NET_SESSIONID") {
			profile.Techs = append(profile.Techs, models.TechNode{Product: "asp.net", Version: ""})
		}
	}

	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	viaHeader := strings.ToLower(resp.Header.Get("Via"))

	if strings.Contains(serverHeader, "cloudflare") || resp.Header.Get("CF-RAY") != "" {
		profile.WAF = "Cloudflare"
	} else if strings.Contains(serverHeader, "f5") {
		profile.WAF = "F5 BIG-IP"
	} else if strings.Contains(serverHeader, "akamai") {
		profile.WAF = "Akamai"
	} else if strings.Contains(viaHeader, "cloudfront") {
		profile.WAF = "AWS CloudFront"
	}

	scanCache.Store(targetURL, profile)

	return profile
}
