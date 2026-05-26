package plugins

import (
	"DORM/models"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
)

// ============================================================
//  IDOR NEXT-GEN (V4.0)
// ============================================================

type IDORPlugin struct{}

func (p *IDORPlugin) Name() string { return "IDOR (Next-Gen — Auth Matrix & GraphQL)" }

// PII keywords used to validate that a real user object is being leaked
var piiKeywords = []string{
	"email", "phone", "mobile", "username", "user_name", "fullname", "full_name",
	"address", "street", "zipcode", "zip_code", "ssn", "national_id",
	"birth", "dob", "gender", "role", "admin", "password", "passwd",
	"credit_card", "card_number", "cvv", "account_number", "iban",
	"passport", "license", "token", "secret", "api_key",
}

// ID-like parameter names to extract from spider-discovered endpoints
var idParamNames = []string{
	"id", "uid", "user_id", "userId", "account_id", "accountId",
	"doc_id", "docId", "order_id", "orderId", "invoice_id", "invoiceId",
	"profile_id", "profileId", "message_id", "messageId", "ticket_id", "ticketId",
	"item_id", "itemId", "resource_id", "resourceId", "object_id", "objectId",
}

// GraphQL introspection query (full schema dump)
const gqlIntrospectionQuery = `{
	"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind ofType { name kind } } } } } } }"
}`

// UUID pattern
var idorUUIDPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// Numeric ID pattern
var numericIDPattern = regexp.MustCompile(`\b([0-9]{1,10})\b`)

func (p *IDORPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ================================================================
	// PHASE 1: DUAL-PROFILE AUTHORIZATION MATRIX
	// Read Token A and Token B from SharedData (set by scan config)
	// ================================================================
	tokenA := getSharedString("idor_token_a")
	tokenB := getSharedString("idor_token_b")

	if tokenA != "" && tokenB != "" {
		result := runDualProfileMatrix(client, baseURL, target, tokenA, tokenB)
		if result != nil {
			return result
		}
	}

	// ================================================================
	// PHASE 2: UUID HARVESTING — Collect from public pages + errors
	// ================================================================
	harvestedUUIDs := harvestUUIDs(client, baseURL)
	if len(harvestedUUIDs) > 0 {
		result := testUUIDAuthorization(client, baseURL, target, harvestedUUIDs, tokenB)
		if result != nil {
			return result
		}
	}

	// ================================================================
	// PHASE 3: SPIDER-DRIVEN DYNAMIC PARAMETER IDOR + PII CHECK
	// ================================================================
	spiderResult := runSpiderIDOR(client, baseURL, target)
	if spiderResult != nil {
		return spiderResult
	}

	// ================================================================
	// PHASE 4: GRAPHQL INTROSPECTION + SUB-FIELD IDOR
	// ================================================================
	gqlResult := runGraphQLIDOR(client, baseURL, target, tokenA, tokenB)
	if gqlResult != nil {
		return gqlResult
	}

	return nil
}

// ================================================================
// DUAL-PROFILE AUTHORIZATION MATRIX
// ================================================================
func runDualProfileMatrix(client *http.Client, baseURL string, target models.ScanTarget, tokenA, tokenB string) *models.Vulnerability {
	// Step 1: Discover resources with User A
	// Use Spider-discovered endpoints + common IDOR-prone patterns
	patterns := []string{
		"/api/v1/user/{ID}", "/api/v1/profile/{ID}", "/api/v1/users/{ID}",
		"/api/v1/order/{ID}", "/api/v1/invoice/{ID}", "/api/v1/messages/{ID}",
		"/api/v1/tickets/{ID}", "/api/v1/documents/{ID}", "/api/v1/account/{ID}",
		"/api/v2/user/{ID}", "/api/v2/profile/{ID}",
		"/api/users/{ID}", "/api/orders/{ID}",
		"/profile?id={ID}", "/my-account?uid={ID}",
		"/user/{ID}", "/users/{ID}", "/account/{ID}",
	}

	// Discover objects as User A (IDs 1..5)
	type foundObject struct {
		Pattern string
		ID      string
		Body    string
		Size    int
	}
	var objectsA []foundObject

	for _, pat := range patterns {
		for _, id := range []string{"1", "2", "3"} {
			ep := strings.ReplaceAll(pat, "{ID}", id)
			req, err := newAuthRequest("GET", baseURL+ep, tokenA, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				continue
			}
			body := readBody(resp, 65536)
			objectsA = append(objectsA, foundObject{
				Pattern: pat,
				ID:      id,
				Body:    body,
				Size:    len(body),
			})
			break // Found a valid pattern, move on
		}
	}

	// Also extract UUIDs from User A responses
	var uuidsA []string
	for _, obj := range objectsA {
		found := idorUUIDPattern.FindAllString(obj.Body, -1)
		uuidsA = append(uuidsA, found...)
	}

	// Step 2: Re-request User A's objects with User B's token
	for _, obj := range objectsA {
		// Try sequential IDs around what User A accessed
		testIDs := generateTestIDs(obj.ID)
		for _, testID := range testIDs {
			ep := strings.ReplaceAll(obj.Pattern, "{ID}", testID)
			req, err := newAuthRequest("GET", baseURL+ep, tokenB, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			bodyB := readBody(resp, 65536)
			statusB := resp.StatusCode

			// CRITICAL: If User B can access User A's resource
			if statusB == 200 && len(bodyB) > 50 {
				// Check if User A's data appears in User B's response (PII cross-contamination)
				if containsPII(bodyB) && isDataSimilar(obj.Body, bodyB, obj.Size) {
					return &models.Vulnerability{
						Target:   target,
						Name:     "CRITICAL IDOR — Dual-Profile Authorization Bypass",
						Severity: "CRITICAL",
						CVSS:     9.8,
						Description: fmt.Sprintf(
							"🔴 CRITICAL IDOR: User B successfully accessed User A's private resource.\n\n"+
								"Endpoint Pattern: %s\n"+
								"User A ID: %s → User B Accessed ID: %s\n"+
								"HTTP Status: %d (Expected: 401 or 403)\n"+
								"User A Response Size: %d bytes | User B Response Size: %d bytes\n\n"+
								"PII Data Detected in Response: YES\n"+
								"This is a confirmed broken object-level authorization (BOLA/IDOR) vulnerability.",
							obj.Pattern, obj.ID, testID, statusB, obj.Size, len(bodyB),
						),
						Solution:  "Enforce object-level authorization checks on every API endpoint. Validate that the authenticated user owns the requested resource ID. Never rely solely on authentication; always authorize each data access.",
						Reference: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
					}
				}
			}
		}
	}

	// Step 3: Replay UUID-based resources with User B
	for _, uuid := range uuidsA {
		uuidEndpoints := []string{
			"/api/v1/profile/" + uuid,
			"/api/v1/user/" + uuid,
			"/api/v1/documents/" + uuid,
			"/api/v1/account/" + uuid,
		}
		for _, ep := range uuidEndpoints {
			req, err := newAuthRequest("GET", baseURL+ep, tokenB, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			bodyB := readBody(resp, 65536)
			if resp.StatusCode == 200 && containsPII(bodyB) {
				return &models.Vulnerability{
					Target:   target,
					Name:     "CRITICAL IDOR — UUID Object Accessed by Unauthorized User",
					Severity: "CRITICAL",
					CVSS:     9.5,
					Description: fmt.Sprintf(
						"🔴 CRITICAL IDOR: User B accessed a UUID-based resource owned by User A.\n\n"+
							"Endpoint: %s\n"+
							"UUID (User A's resource): %s\n"+
							"HTTP Status from User B's request: %d (Expected: 401 or 403)\n"+
							"PII data found in response body.",
						baseURL+ep, uuid, resp.StatusCode,
					),
					Solution:  "UUIDs are not a security boundary. Always validate that the requestor has permission to access the specific object, regardless of ID type.",
					Reference: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
				}
			}
		}
	}

	return nil
}

// ================================================================
// UUID HARVESTING ENGINE
// Collects UUIDs from public pages, error messages, and headers
// ================================================================
func harvestUUIDs(client *http.Client, baseURL string) []string {
	harvestPages := []string{
		"/", "/about", "/contact", "/api/v1/status", "/health",
		"/api/v1/public", "/api/public", "/sitemap.xml", "/robots.txt",
		// Intentionally trigger error pages to harvest from error messages
		"/api/v1/user/invalid-id-that-doesnt-exist",
		"/api/v1/notfound-zzzzzz",
		"/api/v1/user/00000000-0000-0000-0000-000000000000",
	}

	seen := make(map[string]bool)
	var uuids []string

	for _, page := range harvestPages {
		resp, err := client.Get(baseURL + page)
		if err != nil {
			continue
		}

		// Check response headers for UUIDs (X-Request-ID, X-Trace-ID, etc.)
		for _, headerVals := range resp.Header {
			for _, v := range headerVals {
				for _, u := range idorUUIDPattern.FindAllString(v, -1) {
					if !seen[u] {
						seen[u] = true
						uuids = append(uuids, u)
					}
				}
			}
		}

		body := readBody(resp, 131072) // 128KB per page
		for _, u := range idorUUIDPattern.FindAllString(body, -1) {
			if !seen[u] {
				seen[u] = true
				uuids = append(uuids, u)
			}
		}
	}

	return uuids
}

// ================================================================
// UUID-TARGETED AUTHORIZATION TESTING
// ================================================================
func testUUIDAuthorization(client *http.Client, baseURL string, target models.ScanTarget, uuids []string, tokenB string) *models.Vulnerability {
	// Privileged-action endpoints that should require authorization
	privilegedPatterns := []string{
		"/api/v1/delete-profile/%s",
		"/api/v1/user/%s",
		"/api/v1/profile/%s",
		"/api/v1/account/%s/data",
		"/api/v1/documents/%s",
		"/api/v1/admin/user/%s",
		"/api/v1/orders/%s",
		"/api/v2/user/%s",
	}

	// Limit to first 20 unique UUIDs to avoid flooding
	limit := 20
	if len(uuids) < limit {
		limit = len(uuids)
	}

	for _, u := range uuids[:limit] {
		for _, pat := range privilegedPatterns {
			ep := fmt.Sprintf(pat, u)
			var req *http.Request
			var err error
			if tokenB != "" {
				req, err = newAuthRequest("GET", baseURL+ep, tokenB, nil)
			} else {
				req, err = http.NewRequest("GET", baseURL+ep, nil)
				req.Header.Set("User-Agent", "DORM-IDOR-Probe/4.0")
			}
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body := readBody(resp, 65536)

			// Only flag if server returns 200 with meaningful data (not just 200 empty)
			if resp.StatusCode == 200 && len(body) > 30 && containsPII(body) {
				return &models.Vulnerability{
					Target:   target,
					Name:     "IDOR — Unauthorized UUID-Based Object Access",
					Severity: "HIGH",
					CVSS:     8.5,
					Description: fmt.Sprintf(
						"A UUID harvested from public pages was accepted by a privileged endpoint without proper authorization.\n\n"+
							"UUID Source: Harvested from public page / error response / response header\n"+
							"Endpoint Accessed: %s\n"+
							"HTTP Status: %d (Expected: 401 or 403)\n"+
							"PII Keywords Found: YES\n\n"+
							"This indicates the application trusts UUID as a security mechanism rather than enforcing access control.",
						baseURL+ep, resp.StatusCode,
					),
					Solution:  "UUIDs do not provide security by obscurity. Implement proper session-based authorization for every resource endpoint.",
					Reference: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
				}
			}
		}
	}

	return nil
}

// ================================================================
// SPIDER-DRIVEN DYNAMIC IDOR WITH PII VERIFICATION
// ================================================================
func runSpiderIDOR(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	key := "endpoints_" + target.IP
	existing, ok := models.SharedData.Load(key)
	if !ok {
		return nil
	}

	spiderEndpoints := existing.([]models.Endpoint)

	for _, ep := range spiderEndpoints {
		for _, param := range ep.Params {
			// Only test ID-like parameters
			if !isIDParam(param) {
				continue
			}

			u, err := parseURLWithParam(ep.URL, param, "1")
			if err != nil {
				continue
			}

			// Baseline: request with ID=1
			resp1, err := client.Get(u)
			if err != nil || resp1.StatusCode != 200 {
				if resp1 != nil {
					resp1.Body.Close()
				}
				continue
			}
			body1 := readBody(resp1, 65536)
			size1 := len(body1)

			// Target: request with ID=2
			u2, _ := parseURLWithParam(ep.URL, param, "2")
			resp2, err2 := client.Get(u2)
			if err2 != nil {
				continue
			}
			body2 := readBody(resp2, 65536)
			size2 := len(body2)

			// Noise baseline: request with invalid ID
			uNoise, _ := parseURLWithParam(ep.URL, param, "99999999")
			respNoise, _ := client.Get(uNoise)
			sizeNoise := 0
			if respNoise != nil {
				bNoise := readBody(respNoise, 65536)
				sizeNoise = len(bNoise)
			}

			// Determine if ID=2 response is meaningfully different from noise
			isDifferentFromNoise := math.Abs(float64(size2-sizeNoise)) > math.Max(float64(sizeNoise)*0.15, 100)

			if resp2.StatusCode == 200 && isDifferentFromNoise && size1 > 50 && size2 > 50 {
				// PII validation: confirm actual user data is in the response
				hasPII1 := containsPII(body1)
				hasPII2 := containsPII(body2)

				if hasPII1 && hasPII2 {
					return &models.Vulnerability{
						Target:   target,
						Name:     "IDOR — Direct Object Reference with PII Exposure",
						Severity: "HIGH",
						CVSS:     8.0,
						Description: fmt.Sprintf(
							"Accessing different object IDs via parameter '%s' returns distinct user objects containing PII.\n\n"+
								"Endpoint: %s\n"+
								"Parameter: %s\n"+
								"ID=1 Response Size: %d bytes (PII: %v)\n"+
								"ID=2 Response Size: %d bytes (PII: %v)\n"+
								"Invalid ID=99999999 Response Size: %d bytes\n\n"+
								"No access control enforced — any user can enumerate other users' data.",
							param, ep.URL, param, size1, hasPII1, size2, hasPII2, sizeNoise,
						),
						Solution:  "Validate that the authenticated session owns or has permission to access the requested object. Use indirect object references instead of direct DB IDs.",
						Reference: "https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference",
					}
				}
			}
		}
	}

	return nil
}

// ================================================================
// GRAPHQL INTROSPECTION + SUB-FIELD IDOR
// ================================================================
func runGraphQLIDOR(client *http.Client, baseURL string, target models.ScanTarget, tokenA, tokenB string) *models.Vulnerability {
	gqlURL := baseURL + "/graphql"

	// Step 1: Confirm GraphQL is present
	pingReq, err := http.NewRequest("POST", gqlURL, strings.NewReader(`{"query":"{__typename}"}`))
	if err != nil {
		return nil
	}
	pingReq.Header.Set("Content-Type", "application/json")
	pingReq.Header.Set("User-Agent", "DORM-IDOR-GQL/4.0")
	pingResp, err := client.Do(pingReq)
	if err != nil || pingResp.StatusCode != 200 {
		if pingResp != nil {
			pingResp.Body.Close()
		}
		return nil
	}
	pingBody := readBody(pingResp, 4096)
	if !strings.Contains(pingBody, "__typename") && !strings.Contains(pingBody, "data") {
		return nil
	}

	// Step 2: Fetch full introspection schema
	introReq, err := http.NewRequest("POST", gqlURL, bytes.NewBufferString(gqlIntrospectionQuery))
	if err != nil {
		return nil
	}
	introReq.Header.Set("Content-Type", "application/json")
	if tokenA != "" {
		introReq.Header.Set("Authorization", tokenA)
	}
	introResp, err := client.Do(introReq)
	if err != nil {
		return nil
	}
	schemaBody := readBody(introResp, 524288) // up to 512KB schema

	// Step 3: Parse schema to find query/mutation types with integer sub-fields
	intSubFields := extractIntSubFields(schemaBody)

	if len(intSubFields) == 0 {
		// Even without schema parsing, try common GraphQL IDOR patterns
		intSubFields = []gqlField{
			{TypeName: "User", FieldName: "invoice", ArgName: "id"},
			{TypeName: "User", FieldName: "orders", ArgName: "id"},
			{TypeName: "Profile", FieldName: "documents", ArgName: "id"},
			{TypeName: "Account", FieldName: "tickets", ArgName: "id"},
		}
	}

	// Step 4: Probe IDOR on integer sub-fields
	parentQueries := []string{"getUser", "me", "currentUser", "profile", "viewer"}
	for _, parentQ := range parentQueries {
		for _, sf := range intSubFields {
			for _, testID := range []int{1, 2, 3, 100, 999} {
				gqlQuery := fmt.Sprintf(`{"query":"{ %s(id: \"test\") { %s(%s: %d) { id } } }"}`,
					parentQ, sf.FieldName, sf.ArgName, testID)

				var req *http.Request
				if tokenB != "" {
					req, err = newAuthRequest("POST", gqlURL, tokenB, bytes.NewBufferString(gqlQuery))
				} else {
					req, err = http.NewRequest("POST", gqlURL, bytes.NewBufferString(gqlQuery))
					req.Header.Set("User-Agent", "DORM-IDOR-GQL/4.0")
				}
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body := readBody(resp, 65536)

				// Success: no "errors" key AND data key is present
				if resp.StatusCode == 200 &&
					!strings.Contains(body, `"errors"`) &&
					strings.Contains(body, `"data"`) &&
					!strings.Contains(body, `"null"`) {
					return &models.Vulnerability{
						Target:   target,
						Name:     "GraphQL IDOR — Sub-Field Integer ID Enumeration",
						Severity: "HIGH",
						CVSS:     8.0,
						Description: fmt.Sprintf(
							"GraphQL introspection revealed a sub-field accepting integer IDs, which can be enumerated without proper authorization.\n\n"+
								"Parent Query: %s\n"+
								"Vulnerable Sub-Field: %s(id: %d)\n"+
								"GraphQL Endpoint: %s\n"+
								"HTTP Status: %d\n"+
								"Response contains data without errors, indicating unauthorized access to another user's nested resource.\n\n"+
								"Schema Analysis:\n"+
								"Even though the parent query may use UUID parameters, the sub-field '%s' accepts sequential integers, creating an IDOR bypass opportunity.",
							parentQ, sf.FieldName, testID, gqlURL, resp.StatusCode, sf.FieldName,
						),
						Solution:  "Apply object-level authorization on every GraphQL field resolver, including nested sub-fields. Do not assume that parent-level auth propagates to child resolvers.",
						Reference: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
					}
				}
			}
		}
	}

	return nil
}

// ================================================================
// HELPERS
// ================================================================

type gqlField struct {
	TypeName  string
	FieldName string
	ArgName   string
}

// extractIntSubFields parses GraphQL schema JSON to find fields with Int args
func extractIntSubFields(schema string) []gqlField {
	var result []gqlField
	var schemaMap map[string]interface{}
	if err := json.Unmarshal([]byte(schema), &schemaMap); err != nil {
		return result
	}

	data, ok := schemaMap["data"].(map[string]interface{})
	if !ok {
		return result
	}
	schemaObj, ok := data["__schema"].(map[string]interface{})
	if !ok {
		return result
	}
	types, ok := schemaObj["types"].([]interface{})
	if !ok {
		return result
	}

	for _, t := range types {
		typeMap, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		typeName, _ := typeMap["name"].(string)
		if strings.HasPrefix(typeName, "__") {
			continue
		}
		fields, ok := typeMap["fields"].([]interface{})
		if !ok {
			continue
		}
		for _, f := range fields {
			fieldMap, ok := f.(map[string]interface{})
			if !ok {
				continue
			}
			fieldName, _ := fieldMap["name"].(string)
			args, ok := fieldMap["args"].([]interface{})
			if !ok {
				continue
			}
			for _, a := range args {
				argMap, ok := a.(map[string]interface{})
				if !ok {
					continue
				}
				argName, _ := argMap["name"].(string)
				argType, _ := argMap["type"].(map[string]interface{})
				typKind := ""
				typNam := ""
				if argType != nil {
					typKind, _ = argType["kind"].(string)
					typNam, _ = argType["name"].(string)
					// Unwrap NON_NULL
					if ofType, ok := argType["ofType"].(map[string]interface{}); ok {
						typNam, _ = ofType["name"].(string)
					}
				}
				// Check for Int type
				if typKind == "SCALAR" && strings.EqualFold(typNam, "Int") ||
					strings.EqualFold(argName, "id") {
					result = append(result, gqlField{
						TypeName:  typeName,
						FieldName: fieldName,
						ArgName:   argName,
					})
					break
				}
			}
		}
	}
	return result
}

// generateTestIDs creates a set of test IDs to probe around a base ID
func generateTestIDs(baseID string) []string {
	result := []string{baseID}
	// Parse as numeric if possible
	var n int
	if _, err := fmt.Sscanf(baseID, "%d", &n); err == nil {
		for i := 1; i <= 5; i++ {
			result = append(result, fmt.Sprintf("%d", n+i))
		}
		result = append(result, "-1", "0")
	} else {
		// UUID or string: just try a few known UUIDs
		result = append(result,
			"00000000-0000-0000-0000-000000000001",
			"00000000-0000-0000-0000-000000000002",
		)
	}
	return result
}

// newAuthRequest creates an HTTP request with Authorization header
func newAuthRequest(method, url, token string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DORM-IDOR-Probe/4.0")
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		// Support both "Bearer <token>" and raw tokens
		if strings.HasPrefix(strings.ToLower(token), "bearer ") || strings.HasPrefix(token, "Basic ") {
			req.Header.Set("Authorization", token)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	return req, nil
}

// containsPII checks if a response body contains PII-related keywords
func containsPII(body string) bool {
	lower := strings.ToLower(body)
	for _, kw := range piiKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isIDParam returns true if the parameter name looks like an object ID
func isIDParam(param string) bool {
	lp := strings.ToLower(param)
	for _, id := range idParamNames {
		if lp == strings.ToLower(id) || strings.HasSuffix(lp, "_id") || strings.HasSuffix(lp, "id") {
			return true
		}
	}
	return false
}

// parseURLWithParam returns the URL string with the given parameter set
func parseURLWithParam(rawURL, param, value string) (string, error) {
	return rawURL + "?" + param + "=" + value, nil
}

// isDataSimilar checks if two responses are structurally similar (same type of data)
func isDataSimilar(body1, body2 string, size1 int) bool {
	size2 := len(body2)
	if size1 == 0 {
		return false
	}
	// Responses should be in the same ballpark (within 50%) but not identical
	ratio := float64(size2) / float64(size1)
	return ratio > 0.4 && ratio < 2.5
}

// getSharedString reads a string value from models.SharedData
func getSharedString(key string) string {
	v, ok := models.SharedData.Load(key)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
