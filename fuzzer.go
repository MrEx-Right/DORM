package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ==========================
// FUZZER ENGINE
// ==========================

// "Toxic" data list used by the Fuzzer.
// Carefully selected to destabilize the server.
var fuzzPayloads = []string{
	"'",                             // SQL Syntax error trigger
	"\"",                            // String escape error
	"../",                           // Path Traversal attempt
	"%00",                           // Null Byte (Crashes C-based languages)
	"A" + strings.Repeat("A", 1000), // Buffer Overflow
	"{{7*7}}",                       // SSTI (Template Injection)
	"${jndi:ldap://x}",              // Log4Shell trigger
	"<script>alert(1)</script>",     // Simple XSS check
	"| ls",                          // Command Injection
	"waitfor delay '0:0:5'",         // SQL Time-based Injection (MSSQL)
	"SLEEP(5)",                      // SQL Time-based Injection (MySQL)
}

type Fuzzer struct {
	TargetURL string
	Client    *http.Client
}

func NewFuzzer(targetURL string) *Fuzzer {
	return &Fuzzer{
		TargetURL: targetURL,
		Client: &http.Client{
			Timeout: 10 * time.Second, // Be tolerant for fuzzing
			// Do not follow redirects to see the error clearly
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ANOMALY DETECTION REPORT
type FuzzResult struct {
	Param   string
	Payload string
	Reason  string // Why are we suspicious? (500 Error / Latency)
}

func (f *Fuzzer) Attack() []FuzzResult {
	var anomalies []FuzzResult

	// 1. Parse the URL
	u, err := url.Parse(f.TargetURL)
	if err != nil {
		return nil
	}

	params := u.Query()
	if len(params) == 0 {
		return nil // No parameters (e.g., id=1) means nothing to fuzz
	}

	// 2. Baseline Measurement: How does the system behave normally?
	start := time.Now()
	baseResp, err := f.Client.Get(f.TargetURL)
	if err != nil {
		return nil
	}
	baseResp.Body.Close()
	baseDuration := time.Since(start)

	// 3. MUTATION LOOP (One by one for each parameter)
	for paramKey, values := range params {
		originalValue := values[0] // Get first value

		for _, payload := range fuzzPayloads {
			// Poison the parameter
			newParams := u.Query() // Get clean copy

			// Fuzz logic: Inject payload
			newParams.Set(paramKey, payload) // e.g. id='

			u.RawQuery = newParams.Encode()
			attackURL := u.String()

			// 4. Attack and Measure
			reqStart := time.Now()
			resp, err := f.Client.Get(attackURL)
			if err != nil {
				continue
			}

			reqDuration := time.Since(reqStart)

			// Prevent leaks
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			// 5. ANOMALY ANALYSIS

			// A) STATUS CODE ANOMALY: If server returns 500, code crashed.
			if resp.StatusCode >= 500 {
				anomalies = append(anomalies, FuzzResult{
					Param:   paramKey,
					Payload: payload,
					Reason:  fmt.Sprintf("Server Error Returned (Code: %d)", resp.StatusCode),
				})
			}

			// B) TIME ANOMALY: If it took much longer than normal (Time-based SQLi or DoS)
			// If it takes 5x longer than base duration and at least 3 seconds
			if reqDuration > 3*time.Second && reqDuration > baseDuration*5 {
				anomalies = append(anomalies, FuzzResult{
					Param:   paramKey,
					Payload: payload,
					Reason:  fmt.Sprintf("Timeout (DoS/SQLi Suspected) - Duration: %v", reqDuration),
				})
			}

			// Restore parameter for next round
			newParams.Set(paramKey, originalValue)
		}
	}

	return anomalies
}

// ==========================
// DORM INTEGRATION (PLUGIN WRAPPER)
// ==========================

type FuzzerPlugin struct{}

func (p *FuzzerPlugin) Name() string { return "DORM Fuzzer (Smart Mutation)" }

func (p *FuzzerPlugin) Run(target ScanTarget) *Vulnerability {
	// Fuzzer works only on Web ports
	if !isWebPort(target.Port) {
		return nil
	}

	// Works only on URLs with parameters (?id=1 etc.)
	// Note: main.go currently sends root (/).
	// For Fuzzer to be effective, it needs to be fed by the Spider.
	// Ideally, we loop through all Spider results here.

	// Construct Target URL
	targetURL := getURL(target, "/")

	fuzzer := NewFuzzer(targetURL)
	anomalies := fuzzer.Attack()

	if len(anomalies) > 0 {
		desc := fmt.Sprintf("Fuzzer detected %d anomalies (unexpected responses) on the target.\nThis indicates potential 0-Day vulnerabilities.\n\n", len(anomalies))

		for _, a := range anomalies {
			desc += fmt.Sprintf("- Param: [%s] | Payload: [%s] -> %s\n", a.Param, a.Payload, a.Reason)
		}

		return &Vulnerability{
			Target:      target,
			Name:        "Unknown Vulnerability (Fuzzing Anomaly)",
			Severity:    "HIGH", // Fuzzing errors are usually critical
			CVSS:        8.0,
			Description: desc,
			Solution:    "Hide error messages and implement strict input validation.",
			Reference:   "OWASP Fuzzing",
		}
	}

	return nil
}
