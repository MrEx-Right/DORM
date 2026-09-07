package jwtengine

import (
	"DORM/models"
	"fmt"
)

// JWTWeakSecrets is a dictionary of commonly used/default JWT signing
// secrets, tried via HMAC brute force.
var JWTWeakSecrets = []string{
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

// RunWeakSecretAttack (Attack 1): brute-forces the JWT HS256 signing secret
// against the weak-secret dictionary.
func RunWeakSecretAttack(target models.ScanTarget, origHeaderB64, origPayloadB64 string, testToken func(tok, endpoint string) bool) *models.Vulnerability {
	for _, secret := range JWTWeakSecrets {
		forgedToken := models.SignHS256(origHeaderB64, origPayloadB64, []byte(secret))
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
	return nil
}
