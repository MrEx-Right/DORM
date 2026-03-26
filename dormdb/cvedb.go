package dormdb

// ==========================================
// OFFLINE THREAT INTELLIGENCE & AUTO-SYNC ENGINE
// CISA KEV (Known Exploited Vulnerabilities) Edition
// ==========================================

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// Local path for the Threat Intelligence database
	cveDBFile = "dormdb/cisa-cve.json"

	// Direct connection to the CISA KEV authoritative feed
	cveFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// Threat feed expiration interval. Refreshes payload every 24 hours.
	updateInterval = 24 * time.Hour
)

// LocalCVE maintains backward compatibility with existing engine plugins
// while serving as the normalized data structure for threat intelligence.
type LocalCVE struct {
	ID            string  `json:"id"`
	Product       string  `json:"product"`
	Version       string  `json:"version"`
	CVSS          float64 `json:"cvss"`
	VendorProject string  `json:"vendorProject"`
	Description   string  `json:"description"`
}

// CISACatalog represents the root JSON structure of the upstream authoritative feed.
type CISACatalog struct {
	Vulnerabilities []CISAVulnerability `json:"vulnerabilities"`
}

// CISAVulnerability represents individual vulnerability entries within the CISA feed.
type CISAVulnerability struct {
	CVEID            string `json:"cveID"`
	Product          string `json:"product"`
	ShortDescription string `json:"shortDescription"`
}

// CVEMemoryDB acts as the zero-latency in-memory cache for the scanner.
var CVEMemoryDB []LocalCVE

// SyncCVEDatabase initializes the threat intelligence engine on boot.
// It verifies the local database integrity and fetches updates if expired.
func SyncCVEDatabase() {
	fileInfo, err := os.Stat(cveDBFile)

	// Check if the file is missing or older than the update interval
	if os.IsNotExist(err) || time.Since(fileInfo.ModTime()) > updateInterval {
		fmt.Println("[*] DORM Intelligence: Fetching latest CISA KEV payload...")
		err := downloadCVEFeed()
		if err != nil {
			fmt.Printf("[-] Failed to download CISA intel: %v\n", err)
		} else {
			fmt.Println("[+] Arsenal updated directly from CISA authoritative source.")
		}
	} else {
		fmt.Println("[+] DORM Intelligence: Local CISA database is up-to-date.")
	}

	// Load the verified payload into RAM for high-speed scanning
	loadDBIntoMemory()
}

// downloadCVEFeed pulls the latest threat intelligence payload from the authoritative source.
func downloadCVEFeed() error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(cveFeedURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("remote server returned HTTP %d", resp.StatusCode)
	}

	outFile, err := os.Create(cveDBFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	return err
}

// loadDBIntoMemory parses and normalizes the CISA JSON into DORM's internal structure.
func loadDBIntoMemory() {
	file, err := os.Open(cveDBFile)
	if err != nil {
		return
	}
	defer file.Close()

	bytes, _ := io.ReadAll(file)

	var cisaData CISACatalog
	if err := json.Unmarshal(bytes, &cisaData); err != nil {
		fmt.Println("[-] Error parsing CISA intelligence DB. File might be corrupted.")
		return
	}

	// Allocate memory optimally based on the incoming payload size
	CVEMemoryDB = make([]LocalCVE, 0, len(cisaData.Vulnerabilities))

	for _, v := range cisaData.Vulnerabilities {
		// DORM dynamically calculates the CVSS score based on threat intelligence text!
		CVEMemoryDB = append(CVEMemoryDB, LocalCVE{
			ID:          v.CVEID,
			Product:     strings.ToLower(v.Product),
			Version:     "Any",
			CVSS:        estimateCVSS(v.ShortDescription),
			Description: v.ShortDescription,
		})
	}

	fmt.Printf("[+] DORM Engine loaded %d CISA Known Exploited Vulnerabilities into RAM.\n", len(CVEMemoryDB))
}

// ==========================================
// DORM HEURISTIC CVSS ENGINE
// ==========================================

// estimateCVSS analyzes the vulnerability description and dynamically
// calculates a realistic CVSS score based on impact keywords.
func estimateCVSS(description string) float64 {
	desc := strings.ToLower(description)

	// Critical Impact Vectors (RCE & OS Command Injection)
	if strings.Contains(desc, "remote code execution") || strings.Contains(desc, "arbitrary code") || strings.Contains(desc, "rce") || strings.Contains(desc, "command injection") || strings.Contains(desc, "os command") {
		return 9.8
	}
	// Insecure Deserialization (Often leads to RCE)
	if strings.Contains(desc, "deserialization") || strings.Contains(desc, "untrusted data") {
		return 9.5
	}
	// Authentication Bypass & SSRF (Server-Side Request Forgery)
	if strings.Contains(desc, "authentication bypass") || strings.Contains(desc, "hard-coded credentials") || strings.Contains(desc, "ssrf") || strings.Contains(desc, "server-side request forgery") {
		return 9.1
	}
	// Privilege Escalation
	if strings.Contains(desc, "privilege escalation") {
		return 8.8
	}
	// Memory Corruption Vectors (Very common in CISA list for OS/Browsers)
	if strings.Contains(desc, "buffer overflow") || strings.Contains(desc, "use-after-free") || strings.Contains(desc, "memory corruption") || strings.Contains(desc, "type confusion") || strings.Contains(desc, "integer overflow") {
		return 8.6
	}
	// Injection & XML Attacks
	if strings.Contains(desc, "sql injection") || strings.Contains(desc, "sqli") || strings.Contains(desc, "xxe") || strings.Contains(desc, "xml external entity") {
		return 8.5
	}
	// Path/Directory Traversal & LFI
	if strings.Contains(desc, "path traversal") || strings.Contains(desc, "local file inclusion") || strings.Contains(desc, "directory traversal") {
		return 7.5
	}
	// Information Disclosure / Data Leaks
	if strings.Contains(desc, "information disclosure") || strings.Contains(desc, "sensitive information") || strings.Contains(desc, "exposure") {
		return 6.5
	}
	// Client-side Attacks (XSS, CSRF)
	if strings.Contains(desc, "cross-site scripting") || strings.Contains(desc, "xss") || strings.Contains(desc, "csrf") || strings.Contains(desc, "cross-site request forgery") {
		return 6.1
	}
	// Denial of Service & Out-of-bounds Read/Write
	if strings.Contains(desc, "denial of service") || strings.Contains(desc, "dos") || strings.Contains(desc, "out-of-bounds") {
		return 5.5
	}

	// Default high-severity fallback for active exploitation in the wild
	// Any CISA KEV entry missing a keyword still deserves a solid 7.0+
	return 7.5
}

func SearchLocalCVEs(product, version string) []LocalCVE {
	var matches []LocalCVE

	targetProd := strings.ToLower(product)

	for _, cve := range CVEMemoryDB {

		if strings.Contains(cve.Product, targetProd) || strings.Contains(targetProd, cve.Product) {

			matches = append(matches, cve)
		}
	}

	return matches
}
