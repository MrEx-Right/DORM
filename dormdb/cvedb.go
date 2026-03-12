package dormdb

// ==========================================
// OFFLINE CVE DATABASE & AUTO-SYNC ENGINE
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
	// The local file where DORM stores its intelligence
	cveDBFile = "dormdb/cve_patern.json"

	// Example endpoint for a community-maintained, daily-updated JSON CVE feed.
	cveFeedURL = "https://raw.githubusercontent.com/trickest/cve/main/cve_daily_dump.json"

	// Expiration time: If the DB is older than 24 hours, DORM updates it.
	updateInterval = 24 * time.Hour
)

// LocalCVE represents the structure of our offline intelligence database
type LocalCVE struct {
	ID          string  `json:"id"`
	Product     string  `json:"product"`
	Version     string  `json:"version"`
	CVSS        float64 `json:"cvss"`
	Description string  `json:"description"`
}

// CVEMemoryDB acts as our zero-latency in-memory cache for the scanner
var CVEMemoryDB []LocalCVE

// SyncCVEDatabase is the bootstrapper called when DORM starts
func SyncCVEDatabase() {
	fmt.Println("[*] DORM Auto-Sync: Checking local vulnerability intelligence...")

	stat, err := os.Stat(cveDBFile)
	needsUpdate := false

	// Check if the file is missing or older than 24 hours
	if os.IsNotExist(err) {
		fmt.Println("[!] Intelligence DB not found. Initiating first-time download...")
		needsUpdate = true
	} else if time.Since(stat.ModTime()) > updateInterval {
		fmt.Println("[!] Intelligence DB is older than 24 hours. Fetching fresh payloads...")
		needsUpdate = true
	} else {
		fmt.Println("[+] Intelligence DB is up-to-date. Ready for action.")
	}

	if needsUpdate {
		if err := downloadCVEFeed(); err != nil {
			fmt.Printf("[-] Auto-Sync Failed: %v\n", err)
			fmt.Println("[-] DORM will proceed with existing offline data (if any).")
		} else {
			fmt.Println("[+] Auto-Sync Complete: Arsenal updated successfully!")
		}
	}

	// Load the DB into RAM for lightning-fast lookups during the scan
	loadDBIntoMemory()
}

// downloadCVEFeed fetches the latest threat intelligence payload
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

// loadDBIntoMemory parses the JSON file directly into DORM's RAM
func loadDBIntoMemory() {
	file, err := os.Open(cveDBFile)
	if err != nil {
		return
	}
	defer file.Close()

	bytes, _ := io.ReadAll(file)
	if err := json.Unmarshal(bytes, &CVEMemoryDB); err != nil {
		fmt.Println("[-] Error parsing intelligence DB. File might be corrupted.")
		return
	}

	fmt.Printf("[+] DORM Engine loaded %d zero-day and CVE signatures into RAM.\n", len(CVEMemoryDB))
}

// SearchLocalCVEs replaces the slow HTTP API calls. It queries RAM instantly.
func SearchLocalCVEs(product, version string) []LocalCVE {
	var results []LocalCVE
	searchProd := strings.ToLower(product)

	for _, cve := range CVEMemoryDB {
		// Exact match or contains for broad intelligence gathering
		if strings.Contains(strings.ToLower(cve.Product), searchProd) && cve.Version == version {
			results = append(results, cve)
		}
	}
	return results
}
