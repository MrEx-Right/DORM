package plugins

import (
	"DORM/models"
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DORM-BUSTER (HYBRID: EMBEDDED + FILE)
type DirBusterPlugin struct{}

func (p *DirBusterPlugin) Name() string { return "DORM-BUSTER (Hybrid Scan)" }

// dirBusterMaxWords bounds the worst-case request count. Without this cap,
// the bundled directory wordlists add up to ~390k+ lines, probed one at a
// time — a run that never finishes within any realistic pluginTimeout
// budget, confirmed by testing.
const dirBusterMaxWords = 20000

// dirBusterConcurrency bounds simultaneous in-flight probes so a large
// wordlist completes in a tractable amount of wall-clock time instead of
// one request at a time.
const dirBusterConcurrency = 20

// dirBusterWordlists are the path wordlists, in the order their words fill
// the cap: curated first, then the large lists. wordlists/ also holds lists
// for other plugins (passwords for brute force, LFI payloads, WordPress
// plugins); every *.txt used to be unioned alphabetically, so the first
// ~10k slots went to 10k-most-common.txt — passwords probed as paths —
// and the directory lists were never reached.
var dirBusterWordlists = []string{
	"common.txt",
	"Common-DB-Backups.txt",
	"raft-large-directories.txt",
	"raft-large-files-lowercase.txt",
	"DirBuster-2007_directory-list-2.3-medium.txt",
}

// sensitivePathRe matches paths whose mere presence is a disclosure:
// secrets, VCS metadata, backups, dumps, keys and server internals.
var sensitivePathRe = regexp.MustCompile(`(?i)(^|/)(\.env|\.git(/|$)|\.svn(/|$)|\.hg(/|$)|\.htpasswd|\.ssh/|id_[rd]sa|web\.config|wp-config|php\.ini|config\.(php|inc|json|ya?ml|ini)(\.|$)|docker-compose|phpinfo|server-status|server-info|\.ds_store)|\.(sql|bak|old|orig|backup|swp|sav|tar|tgz|gz|zip|rar|7z|pem|key|p12|pfx|kdbx|sqlite3?|db|log)$`)

// volatileRe matches what changes on every request (CSRF tokens, ids,
// timestamps), masked before two pages are compared.
var volatileRe = regexp.MustCompile(`[0-9a-fA-F-]{8,}|[0-9]+`)

// directoryListingRe matches the title or heading of an auto-generated
// directory index (Apache/nginx "Index of", Express serve-index
// "listing directory", Python "Directory listing for").
var directoryListingRe = regexp.MustCompile(`(?i)<title>\s*(index of /|listing directory /|directory listing for /)`)

func (p *DirBusterPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	defaultList := []string{
		"/.env", "/.git/config", "/.htaccess", "/web.config",
		"/config.php", "/config.php.bak", "/config.php.old",
		"/backup.sql", "/db.sql", "/dump.sql",
		"/.ssh/id_rsa", "/.ssh/id_rsa.pub",
		"/server-status", "/phpmyadmin/", "/docker-compose.yml",
		"/robots.txt", "/sitemap.xml", "/admin", "/login",
	}

	seen := make(map[string]bool)
	words := make([]string, 0, dirBusterMaxWords)
	addWord := func(word string) bool {
		if seen[word] {
			return true
		}
		if len(words) >= dirBusterMaxWords {
			return false
		}
		seen[word] = true
		words = append(words, word)
		return true
	}

	// Curated high-value paths always get a slot first, regardless of cap.
	for _, w := range defaultList {
		addWord(w)
	}

fileLoop:
	for _, name := range dirBusterWordlists {
		f, err := os.Open(filepath.Join("wordlists", name))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if len(word) == 0 || strings.HasPrefix(word, "#") {
				continue
			}
			if !strings.HasPrefix(word, "/") {
				word = "/" + word
			}
			// A word whose path part is just "/" ("/??????", "/?debug=1",
			// "/#top") requests the home page with a query or fragment:
			// it can only ever "find" the home page.
			if pathPart, _, _ := strings.Cut(strings.SplitN(word, "#", 2)[0], "?"); pathPart == "/" {
				continue
			}
			if !addWord(word) {
				_ = f.Close()
				break fileLoop
			}
		}
		_ = f.Close()
	}

	// Calibration probes: request two random, essentially-guaranteed-
	// nonexistent paths of different lengths first. Status code alone
	// (200/403) is meaningless against a target that answers every path the
	// same way — a SPA catch-all router (200 + index.html for anything
	// unmatched) or a "soft 404" — so if the calibration paths also come
	// back 200/403, a hit must differ from what such a page would be. Soft
	// 404 pages often name the requested path ("Sorry, /x does not exist"):
	// the two lengths tell how much the page grows per character of path,
	// so the expected soft-404 length is known for every word.
	calibPath := fmt.Sprintf("/dorm-calibration-%d-nonexistent", time.Now().UnixNano())
	calibPath2 := calibPath + "-with-a-longer-tail"
	calibLen := func(path string) (int, bool) {
		resp, err := models.GetClient().Get(getURL(target, path))
		if err != nil {
			return 0, false
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65536))
		_ = resp.Body.Close()
		return len(body), readErr == nil && (resp.StatusCode == 200 || resp.StatusCode == 403)
	}
	lenA, okA := calibLen(calibPath)
	lenB, okB := calibLen(calibPath2)
	calibNoisy := okA && okB
	perChar := float64(lenB-lenA) / float64(len(calibPath2)-len(calibPath))
	isSoft404 := func(path string, bodyLen int) bool {
		if !calibNoisy {
			return false
		}
		want := float64(lenA) + perChar*float64(len(path)-len(calibPath))
		if want > 65536 {
			want = 65536
		}
		return math.Abs(float64(bodyLen)-want) <= 1
	}

	// The home page itself: a path that answers with the same page
	// (/index.html, or /index.php redirecting to the same login as "/") is
	// the home page under another name, not a discovery.
	homePage := ""
	if homeResp, err := models.GetClient().Get(getURL(target, "/")); err == nil {
		home, readErr := io.ReadAll(io.LimitReader(homeResp.Body, 65536))
		_ = homeResp.Body.Close()
		if readErr == nil && homeResp.StatusCode == 200 {
			homePage = volatileRe.ReplaceAllString(string(home), "#")
		}
	}

	// STEP 3: Scanning Engine — bounded concurrency instead of one request
	// at a time, so a full pass over the (now capped) word list actually
	// fits inside a plugin timeout budget.
	var sensitive, discovered []string
	var foundMu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, dirBusterConcurrency)

	for _, word := range words {
		wg.Add(1)
		go func(word string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fullURL := getURL(target, word)
			req, _ := http.NewRequest("GET", fullURL, nil)

			resp, err := models.GetClient().Do(req)
			if err != nil {
				return
			}
			// 403 means the path is there but not served: nothing is
			// disclosed. Only a 200 with a fully read body counts.
			if resp.StatusCode != 200 {
				_ = resp.Body.Close()
				return
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65536))
			_ = resp.Body.Close()
			if readErr != nil {
				// The body broke off (a target falling over under load, a
				// client timeout): a truncated catch-all page differs in
				// length from the calibration page without being a file.
				return
			}
			pathPart, _, _ := strings.Cut(word, "?")
			if isSoft404(pathPart, len(body)) {
				// Same answer as the calibration probes for a path we know
				// can't exist — this target answers everything the same
				// way, so it's not a real finding.
				return
			}
			if homePage != "" && volatileRe.ReplaceAllString(string(body), "#") == homePage {
				return
			}
			foundMu.Lock()
			if sensitivePathRe.MatchString(pathPart) || directoryListingRe.Match(body) {
				sensitive = append(sensitive, fmt.Sprintf("%s (Code: %d)", word, resp.StatusCode))
			} else {
				discovered = append(discovered, fmt.Sprintf("%s (Code: %d)", word, resp.StatusCode))
			}
			foundMu.Unlock()
		}(word)
	}
	wg.Wait()

	list := func(paths []string) string {
		var b strings.Builder
		for i, p := range paths {
			if i == 20 {
				fmt.Fprintf(&b, "...and %d more.\n", len(paths)-20)
				break
			}
			b.WriteString("- " + p + "\n")
		}
		return b.String()
	}

	if len(sensitive) > 0 {
		description := fmt.Sprintf("Total %d critical files/directories found:\n", len(sensitive)) + list(sensitive)
		if len(discovered) > 0 {
			description += fmt.Sprintf("\nOther reachable paths (%d):\n", len(discovered)) + list(discovered)
		}
		return &models.Vulnerability{
			Target:      target,
			Name:        "Critical File/Directory Disclosure (Hybrid)",
			Severity:    "HIGH",
			CVSS:        7.5,
			Description: description,
			Solution:    "Delete found files from the server or check permissions (chmod/chown).",
			Reference:   "OWASP Forced Browsing",
		}
	}

	if len(discovered) > 0 {
		return &models.Vulnerability{
			Target:      target,
			Name:        "Forced Browsing: Reachable Paths",
			Severity:    "INFO",
			Description: fmt.Sprintf("Total %d paths answered 200 that the site does not link to:\n", len(discovered)) + list(discovered),
			Solution:    "Review whether these paths should be public.",
			Reference:   "OWASP Forced Browsing",
		}
	}

	return nil
}
