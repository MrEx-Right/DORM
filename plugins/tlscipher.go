package plugins

import (
	"DORM/models"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type TLSCipherPlugin struct{}

func (p *TLSCipherPlugin) Name() string { return "Weak TLS Cipher Suites Scanner" }

func (p *TLSCipherPlugin) Run(target models.ScanTarget) *models.Vulnerability {

	if target.Port != 443 && target.Port != 8443 {
		return nil
	}

	address := fmt.Sprintf("%s:%d", target.IP, target.Port)

	weakCiphers := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:         "TLS_RSA_WITH_RC4_128_SHA (RC4 - Deprecated)",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:    "TLS_RSA_WITH_3DES_EDE_CBC_SHA (3DES - SWEET32 Vulnerable)",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:   "TLS_ECDHE_RSA_WITH_RC4_128_SHA (RC4 - Deprecated)",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (RC4 - Deprecated)",
	}

	var supportedWeakCiphers []string

	for cipherID, cipherName := range weakCiphers {
		config := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{cipherID},
			MaxVersion:         tls.VersionTLS12,
		}

		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, config)

		if err == nil {

			supportedWeakCiphers = append(supportedWeakCiphers, cipherName)
			conn.Close()
		}
	}

	if len(supportedWeakCiphers) > 0 {
		return &models.Vulnerability{
			Target:      target,
			Name:        "Weak TLS Cipher Suites Enabled",
			Severity:    "MEDIUM",
			CVSS:        5.9,
			Description: fmt.Sprintf("Cryptographic analysis revealed the server accepts connections using weak, legacy encryption algorithms.\n\nSupported Weak Ciphers:\n- %s", strings.Join(supportedWeakCiphers, "\n- ")),
			Solution:    "Reconfigure the web server (Nginx/Apache/IIS) to explicitly disable RC4, 3DES, and other legacy cipher suites. Enforce modern cryptographic standards (e.g., AES-GCM, ChaCha20).",
			Reference:   "OWASP Transport Layer Protection / SWEET32 (CVE-2016-2183)",
		}
	}

	return nil
}
