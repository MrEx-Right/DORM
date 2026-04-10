package plugins

import (
	"DORM/models"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type JWTWeaknessPlugin struct{}

func (p *JWTWeaknessPlugin) Name() string { return "JWT Security Scanner" }

func (p *JWTWeaknessPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	resp, err := client.Get(getURL(target, "/"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	token := findJWT(string(bodyBytes), resp.Header)

	if token == "" {
		return nil
	}

	origHeaderB64, origPayloadB64, _, valid := parseAndValidateJWT(token)
	if !valid {
		return nil
	}

	badToken := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.invalid_signature_block"
	reqCheck, _ := http.NewRequest("GET", getURL(target, "/"), nil)
	reqCheck.Header.Set("Authorization", "Bearer "+badToken)
	respCheck, err := client.Do(reqCheck)
	if err != nil {
		return nil
	}
	respCheck.Body.Close()

	if respCheck.StatusCode == 200 {
		return nil
	}

	weakSecrets := []string{
		"secret", "password", "123456", "jwt", "key", "123", "12345",
		"admin", "test", "app", "api", "auth", "server", "changeme",
		"token", "dev", "user", "access", "root", "supersecret",
	}

	for _, secret := range weakSecrets {

		forgedToken := signHS256(origHeaderB64, origPayloadB64, []byte(secret))

		req, _ := http.NewRequest("GET", getURL(target, "/"), nil)
		req.Header.Set("Authorization", "Bearer "+forgedToken)

		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Weak JWT Secret Detected",
					Severity:    "CRITICAL",
					CVSS:        9.8,
					Description: fmt.Sprintf("The JWT signing secret is extremely weak and was cracked via dictionary attack.\nSecret Key: '%s'\nThis allows full account takeover.", secret),
					Solution:    "Change the JWT secret immediately to a long, random string (e.g. 64 random chars).",
					Reference:   "CWE-798: Use of Hard-coded Credentials",
				}
			}
		}
	}

	headerBytes, _ := base64.RawURLEncoding.DecodeString(origHeaderB64)
	var headerMap map[string]interface{}
	json.Unmarshal(headerBytes, &headerMap)

	noneVariants := []string{"none", "None", "NONE"}

	for _, alg := range noneVariants {
		headerMap["alg"] = alg
		newHeaderJSON, _ := json.Marshal(headerMap)
		newHeaderB64 := base64.RawURLEncoding.EncodeToString(newHeaderJSON)

		noneToken := fmt.Sprintf("%s.%s.", newHeaderB64, origPayloadB64)

		req, _ := http.NewRequest("GET", getURL(target, "/"), nil)
		req.Header.Set("Authorization", "Bearer "+noneToken)

		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				return &models.Vulnerability{
					Target:      target,
					Name:        "JWT 'None' Algorithm Bypass",
					Severity:    "HIGH",
					CVSS:        8.1,
					Description: fmt.Sprintf("Server accepted a JWT with 'alg: %s' (Unsecured JWT). This allows forging tokens without a secret key.", alg),
					Solution:    "Configure the JWT validation library to explicitly reject the 'none' algorithm.",
					Reference:   "RFC 7519 Section 6",
				}
			}
		}
	}

	return nil
}
