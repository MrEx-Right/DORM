package plugins

import (
	"DORM/models"
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DORM-BUSTER (HYBRID: EMBEDDED + FILE)
type DirBusterPlugin struct{}

func (p *DirBusterPlugin) Name() string { return "DORM-BUSTER (Hybrid Scan)" }

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

	uniqueWords := make(map[string]bool)

	for _, w := range defaultList {
		uniqueWords[w] = true
	}

	folderPath := "wordlists"
	files, err := os.ReadDir(folderPath)

	if err == nil {
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
							uniqueWords[word] = true
						}
					}
					f.Close()
				}
			}
		}
	}

	// STEP 3: Scanning Engine
	var foundPaths []string

	for word := range uniqueWords {
		fullURL := getURL(target, word)

		req, _ := http.NewRequest("GET", fullURL, nil)

		resp, err := models.GetClient().Do(req)
		if err == nil {

			if resp.StatusCode == 200 || resp.StatusCode == 403 {

				statusMark := ""
				if resp.StatusCode == 403 {
					statusMark = " [FORBIDDEN]"
				}

				foundPaths = append(foundPaths, fmt.Sprintf("%s (Code: %d)%s", word, resp.StatusCode, statusMark))
			}
			resp.Body.Close()
		}

	}

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
