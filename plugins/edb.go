package plugins

import (
	"DORM/models"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// edbProductVersionRe requires an actual "product version" shape (e.g.
// "nginx/1.18.0", "Apache 2.4.6") before a banner is worth searching against
// Exploit-DB. A bare vendor/CDN name with no version (e.g. "cloudflare",
// emitted by nearly every site sitting behind Cloudflare's edge) previously
// went straight to SearchExploitDB, which does a naive substring match — any
// exploit description merely containing that word anywhere matched, so
// "cloudflare" alone was flagging huge numbers of unrelated sites as
// CRITICAL 9.8 against, e.g., a Cloudflare WARP desktop-client exploit that
// has nothing to do with the scanned website.
var edbProductVersionRe = regexp.MustCompile(`(?i)[a-zA-Z0-9\-.]+(?:/|\s+v?)[0-9]+(?:\.[0-9]+)+`)

type EDBPlugin struct{}

func (p *EDBPlugin) Name() string { return "Exploit-DB Scanner" }

func (p *EDBPlugin) Run(target models.ScanTarget) *models.Vulnerability {

	portStr := strconv.Itoa(target.Port)
	address := net.JoinHostPort(target.IP, portStr)

	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	if target.Port == 80 || target.Port == 443 || target.Port == 8080 {
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	if n == 0 {
		return nil
	}
	banner := string(buf[:n])

	lines := strings.Split(banner, "\n")
	cleanBanner := ""

	for _, line := range lines {

		if strings.Contains(line, "Server:") || strings.Contains(line, "SSH") || strings.Contains(line, "FTP") {
			cleanBanner = line
			break
		}
	}

	if cleanBanner == "" && len(lines) > 0 {
		cleanBanner = lines[0]
	}

	cleanBanner = strings.ReplaceAll(cleanBanner, "Server:", "")
	cleanBanner = strings.TrimSpace(cleanBanner)

	cleanBanner = strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 {
			return r
		}
		return -1
	}, cleanBanner)

	if len(cleanBanner) < 4 {
		return nil
	}

	versioned := edbProductVersionRe.FindString(cleanBanner)
	if versioned == "" {
		// No identifiable product+version — e.g. just "cloudflare" with no
		// version number. Searching Exploit-DB on a bare vendor name is
		// guaranteed to hit unrelated exploits, so skip rather than flag it.
		return nil
	}

	results := models.SearchExploitDB(versioned)

	if len(results) > 0 {
		return &models.Vulnerability{
			Target:      target,
			Name:        "Critical Exploit Detection (EDB)",
			Severity:    "CRITICAL",
			CVSS:        9.8,
			Description: fmt.Sprintf("Exploit-DB records found for service version (%s):\n\n%s", cleanBanner, strings.Join(results, "\n\n")),
			Solution:    "Update the service version or apply security patches immediately.",
			Reference:   "https://www.exploit-db.com/",
		}
	}

	return nil
}
