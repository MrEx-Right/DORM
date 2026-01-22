package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ==========================
// FUZZER ENGINE V2.0
// ==========================

type Fuzzer struct {
	TargetURL string
	Client    *http.Client
	Payloads  []string
}

// NewFuzzer initializes the fuzzing engine with payloads loaded from a file.
func NewFuzzer(targetURL string) *Fuzzer {
	// 1. Load Payloads from File
	payloads := loadPayloads("payloads/fuzzing.txt")

	// Fallback if file is missing (Safety Net)
	if len(payloads) == 0 {
		fmt.Println("[!] Warning: payloads/fuzzing.txt not found! Using default list.")
		payloads = []string{"'", "\"", "../", "%00", "{{47*47}}"}
	}

	return &Fuzzer{
		TargetURL: targetURL,
		// Using getClient() from client.go to inherit Auth Headers and User-Agent settings.
		Client:   getClient(),
		Payloads: payloads,
	}
}

// Helper function to read payloads line by line
func loadPayloads(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if text != "" && !strings.HasPrefix(text, "#") {
			lines = append(lines, text)
		}
	}
	return lines
}

// Data structure for reporting found anomalies
type FuzzResult struct {
	Param   string
	Payload string
	Reason  string
	Diff    string // Details (e.g., "Size changed by 50%")
}

// Attack executes the fuzzing logic with smart mutation and analysis
func (f *Fuzzer) Attack() []FuzzResult {
	var anomalies []FuzzResult

	u, err := url.Parse(f.TargetURL)
	if err != nil {
		return nil
	}

	params := u.Query()
	if len(params) == 0 {
		return nil
	}

	// 🎯 CRITICAL FIX: Save the clean query string to reset later
	cleanRawQuery := u.RawQuery

	// 2. BASELINE MEASUREMENT
	start := time.Now()
	baseResp, err := f.Client.Get(f.TargetURL)
	if err != nil {
		return nil
	}

	baseBody, _ := io.ReadAll(baseResp.Body)
	baseResp.Body.Close()

	baseDuration := time.Since(start)
	baseSize := len(baseBody)

	// WAF EVASION: Smart Jitter
	smartSleep := func() {
		min := 300
		max := 1500
		sleepTime := rand.Intn(max-min) + min
		time.Sleep(time.Duration(sleepTime) * time.Millisecond)
	}

	// 3. MUTATION LOOP
	for paramKey := range params {

		for _, payload := range f.Payloads {
			smartSleep()

			// Poison the parameter
			// We modify 'u' directly. Since we overwrite 'paramKey',
			// it doesn't matter if it holds the previous payload for THIS param.
			qs := u.Query()
			qs.Set(paramKey, payload)
			u.RawQuery = qs.Encode()
			attackURL := u.String()

			// Execute Attack
			reqStart := time.Now()
			resp, err := f.Client.Get(attackURL)
			if err != nil {
				continue
			}

			reqDuration := time.Since(reqStart)
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			currentSize := len(bodyBytes)
			bodyStr := string(bodyBytes)

			// 4. DEEP ANOMALY ANALYSIS

			// A) STATUS CODE CRASH
			if resp.StatusCode >= 500 {
				anomalies = append(anomalies, FuzzResult{
					Param: paramKey, Payload: payload,
					Reason: fmt.Sprintf("Server Crash (Code: %d)", resp.StatusCode),
				})
				continue
			}

			// B) TIME-BASED DETECTION
			if reqDuration > 3*time.Second && reqDuration > baseDuration*4 {
				anomalies = append(anomalies, FuzzResult{
					Param: paramKey, Payload: payload,
					Reason: "Time-Based Anomaly (Potential DoS/SQLi)",
					Diff:   fmt.Sprintf("Base: %v vs Attack: %v", baseDuration, reqDuration),
				})
			}

			// C) SIZE ANOMALY
			sizeDiff := math.Abs(float64(currentSize - baseSize))
			if sizeDiff > float64(baseSize)*0.4 {
				anomalies = append(anomalies, FuzzResult{
					Param: paramKey, Payload: payload,
					Reason: "Response Size Anomaly (Structure Break)",
					Diff:   fmt.Sprintf("Base: %d bytes vs Attack: %d bytes", baseSize, currentSize),
				})
			}

			// D) REFLECTION CHECK
			if strings.Contains(bodyStr, payload) && !strings.Contains(string(baseBody), payload) {
				anomalies = append(anomalies, FuzzResult{
					Param: paramKey, Payload: payload,
					Reason: "Input Reflection (Potential XSS/SSTI)",
				})
			}
		}

		// 🧹 RESET: Restore URL to clean state for the next parameter
		u.RawQuery = cleanRawQuery
	}

	return anomalies
}

// ==========================
// PLUGIN WRAPPER
// ==========================

type FuzzerPlugin struct{}

func (p *FuzzerPlugin) Name() string { return "DORM Fuzzer (Sledgehammer v1.3.2)" }

func (p *FuzzerPlugin) Run(target ScanTarget) *Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// Note: Fuzzer currently scans the root directory.
	// In the future, this should be integrated with the Spider results.
	targetURL := getURL(target, "/")

	fuzzer := NewFuzzer(targetURL)
	anomalies := fuzzer.Attack()

	if len(anomalies) > 0 {
		desc := fmt.Sprintf("Fuzzer detected %d critical anomalies.\nPayloads loaded from: payloads/fuzzing.txt\n\n", len(anomalies))

		for _, a := range anomalies {
			extra := ""
			if a.Diff != "" {
				extra = fmt.Sprintf(" (%s)", a.Diff)
			}
			desc += fmt.Sprintf("🔴 Param: %s | Payload: %s\n   -> %s%s\n", a.Param, a.Payload, a.Reason, extra)
		}

		return &Vulnerability{
			Target:      target,
			Name:        "Fuzzing Anomalies Detected",
			Severity:    "HIGH",
			CVSS:        8.5,
			Description: desc,
			Solution:    "Review the anomalies manually. Implement strict input validation and WAF rules.",
			Reference:   "OWASP Automated Threats",
		}
	}

	return nil
}
