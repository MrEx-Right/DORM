package plugins

import (
	"DORM/models"
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DORM-BUSTER (HYBRID: EMBEDDED + FILE)
type DirBusterPlugin struct{}

func (p *DirBusterPlugin) Name() string { return "DORM-BUSTER (Hybrid Scan)" }

// dirBusterMaxWords bounds the worst-case request count. Without this cap,
// every *.txt file under wordlists/ is unioned unconditionally (~390k+ lines
// across the bundled wordlists) and probed one at a time — a run that never
// finishes within any realistic pluginTimeout budget, confirmed by testing.
const dirBusterMaxWords = 20000

// dirBusterConcurrency bounds simultaneous in-flight probes so a large
// wordlist completes in a tractable amount of wall-clock time instead of
// one request at a time.
const dirBusterConcurrency = 20

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

	folderPath := "wordlists"
	files, err := os.ReadDir(folderPath)

	if err == nil {
	fileLoop:
		for _, file := range files {

			if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
				f, err := os.Open(filepath.Join(folderPath, file.Name()))
				if err == nil {
					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						word := strings.TrimSpace(scanner.Text())

						if len(word) > 0 && !strings.HasPrefix(word, "#") {

							if !strings.HasPrefix(word, "/") {
								word = "/" + word
							}
							if !addWord(word) {
								_ = f.Close()
								break fileLoop
							}
						}
					}
					_ = f.Close()
				}
			}
		}
	}

	// Calibration probe: request a random, essentially-guaranteed-nonexistent
	// path first. Status code alone (200/403) is meaningless against a
	// target that answers every path the same way — a SPA catch-all router
	// (200 + index.html for anything unmatched) or a "soft 404" — so if the
	// calibration path also comes back 200/403, every real hit below must
	// have a body that differs in length from this baseline to count.
	calibPath := fmt.Sprintf("/dorm-calibration-%d-nonexistent", time.Now().UnixNano())
	calibNoisy := false
	var calibLen int64 = -1
	if calResp, calErr := models.GetClient().Get(getURL(target, calibPath)); calErr == nil {
		calibBody, _ := io.ReadAll(io.LimitReader(calResp.Body, 65536))
		_ = calResp.Body.Close()
		if calResp.StatusCode == 200 || calResp.StatusCode == 403 {
			calibNoisy = true
			calibLen = int64(len(calibBody))
		}
	}

	// STEP 3: Scanning Engine — bounded concurrency instead of one request
	// at a time, so a full pass over the (now capped) word list actually
	// fits inside a plugin timeout budget.
	var foundPaths []string
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
			if resp.StatusCode != 200 && resp.StatusCode != 403 {
				_ = resp.Body.Close()
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
			_ = resp.Body.Close()
			if calibNoisy && int64(len(body)) == calibLen {
				// Same status AND same body length as the calibration probe
				// for a path we know can't exist — this target answers
				// everything the same way, so it's not a real finding.
				return
			}
			statusMark := ""
			if resp.StatusCode == 403 {
				statusMark = " [FORBIDDEN]"
			}
			foundMu.Lock()
			foundPaths = append(foundPaths, fmt.Sprintf("%s (Code: %d)%s", word, resp.StatusCode, statusMark))
			foundMu.Unlock()
		}(word)
	}
	wg.Wait()

	if len(foundPaths) > 0 {
		description := fmt.Sprintf("Total %d critical files/directories found:\n", len(foundPaths))

		limit := 20
		if len(foundPaths) < 20 {
			limit = len(foundPaths)
		}

		for i := 0; i < limit; i++ {
			description += "- " + foundPaths[i] + "\n"
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

	return nil
}
