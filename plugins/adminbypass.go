package plugins

import (
	"DORM/models"
	"fmt"
	"net/http"
)

// 43. ADMIN IP BYPASS (Header Spoofing & Verified) - v2
type AdminBypassPlugin struct{}

func (p *AdminBypassPlugin) Name() string { return "Admin Panel Bypass (IP Spoof - Verified)" }

func (p *AdminBypassPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	targetPath := "/admin"
	fullURL := getURL(target, targetPath)

	reqBase, _ := http.NewRequest("GET", fullURL, nil)
	respBase, err := client.Do(reqBase)
	if err != nil {
		return nil
	}
	baseStatus := respBase.StatusCode
	respBase.Body.Close()

	if baseStatus != 403 && baseStatus != 401 {
		return nil
	}

	headers := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"Client-IP",
		"X-Originating-IP",
		"X-Remote-IP",
		"X-Remote-Addr",
		"X-Client-IP",
		"X-Host",
		"X-Forwarded-Host",
	}

	spoofIPs := []string{
		"127.0.0.1",
		"localhost",
		"0.0.0.0",
		"192.168.1.1",
		"10.0.0.1",
		"::1",
	}

	for _, header := range headers {
		for _, ip := range spoofIPs {
			reqSpoof, _ := http.NewRequest("GET", fullURL, nil)
			reqSpoof.Header.Set(header, ip)

			respSpoof, err := client.Do(reqSpoof)
			if err == nil {
				spoofStatus := respSpoof.StatusCode
				respSpoof.Body.Close()

				if spoofStatus == 200 {
					return &models.Vulnerability{
						Target:   target,
						Name:     "Admin IP Restriction Bypass",
						Severity: "CRITICAL",
						CVSS:     9.8,
						Description: fmt.Sprintf(
							"Access restriction bypassed!\nBaseline Status: %d\nBypass Status: %d\nEffective Header: %s: %s",
							baseStatus, spoofStatus, header, ip),
						Solution:  "Do not rely solely on client-side headers (e.g., X-Forwarded-For) for access control/authentication.",
						Reference: "CWE-290: Authentication Bypass by Spoofing",
					}
				}
			}
		}
	}

	return nil
}
