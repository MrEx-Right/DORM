package main

import (
	"DORM/models"
	"context"
	"crypto/tls"
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
	defer resp.Body.Close()

	re := regexp.MustCompile(`(?i)([a-zA-Z0-9\-]+)(?:/|\s+v?)([0-9]+(?:\.[0-9]+)*)`)
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
