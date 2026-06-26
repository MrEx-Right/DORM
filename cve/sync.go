// Package cve provides the full CVEProject/cvelistV5 sync engine for DORM.
// It downloads the daily nightly snapshot (~280K CVEs), parses CVE JSON 5.0 format,
// builds an in-memory product index for O(1) search, and persists to cve_full.json.
package cve

import (
	"DORM/models"
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	FullDBFile     = "wordlists/cve_full.json"
	UpdateInterval = 24 * time.Hour
)

// --- CVE JSON 5.0 Parse Structs ---

type cve5Root struct {
	CveMetadata struct {
		CveID string `json:"cveId"`
		State string `json:"state"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Affected []struct {
				Vendor   string `json:"vendor"`
				Product  string `json:"product"`
				Versions []struct {
					Version string `json:"version"`
					Status  string `json:"status"`
				} `json:"versions"`
			} `json:"affected"`
			Metrics []struct {
				CvssV31 *struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssV3_1"`
				CvssV30 *struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssV3_0"`
			} `json:"metrics"`
		} `json:"cna"`
	} `json:"containers"`
}

// --- In-Memory Index ---

var (
	MemoryDB     []models.LocalCVE
	productIndex map[string][]int
	indexMu      sync.RWMutex
)

// --- URL Builder ---

// knownTimestamps lists the hour-tags CVEProject uses in release names,
// ordered newest-first so we always prefer the most recent snapshot.
var knownTimestamps = []string{"2300Z", "2200Z", "2100Z", "2000Z", "1900Z"}

// probeSnapshotURL finds the latest available nightly ZIP on GitHub
// by HEAD-checking candidate URLs (today + yesterday × known timestamps).
// Falls back to the oldest known URL if all probes fail (e.g., no network).
func probeSnapshotURL() string {
	client := &http.Client{Timeout: 8 * time.Second}
	now := time.Now().UTC()

	days := []string{
		now.Format("2006-01-02"),
		now.AddDate(0, 0, -1).Format("2006-01-02"),
		now.AddDate(0, 0, -2).Format("2006-01-02"),
	}

	for _, d := range days {
		for _, ts := range knownTimestamps {
			candidate := fmt.Sprintf(
				"https://github.com/CVEProject/cvelistV5/releases/download/cve_%s_%s/%s_all_CVEs_at_midnight.zip.zip",
				d, ts, d,
			)
			resp, err := client.Head(candidate)
			if err == nil && resp.StatusCode == 200 {
				fmt.Printf("[+] CVE Probe: Found release cve_%s_%s\n", d, ts)
				return candidate
			}
		}
	}

	// Absolute last resort: return yesterday 1900Z without probing
	d := now.AddDate(0, 0, -1).Format("2006-01-02")
	fmt.Println("[~] CVE Probe: All HEAD checks failed, using yesterday 1900Z as last resort.")
	return fmt.Sprintf(
		"https://github.com/CVEProject/cvelistV5/releases/download/cve_%s_1900Z/%s_all_CVEs_at_midnight.zip.zip",
		d, d,
	)
}

type githubRelease struct {
	Assets []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func getLatestURLs() (fullURL, deltaURL string, err error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/CVEProject/cvelistV5/releases/latest")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("github api returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", err
	}

	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, "all_CVEs") && strings.HasSuffix(asset.Name, ".zip.zip") {
			fullURL = asset.BrowserDownloadURL
		} else if strings.Contains(asset.Name, "delta_CVEs") && strings.HasSuffix(asset.Name, ".zip") {
			deltaURL = asset.BrowserDownloadURL
		}
	}

	if fullURL == "" {
		return "", "", fmt.Errorf("could not find full url")
	}
	return fullURL, deltaURL, nil
}

// SyncFullDatabase downloads and loads the CVEProject nightly snapshot.
// Blocks until complete; safe to call at startup.
func SyncFullDatabase() {
	os.MkdirAll("wordlists", os.ModePerm)

	fileInfo, err := os.Stat(FullDBFile)
	hasLocal := err == nil

	if hasLocal && time.Since(fileInfo.ModTime()) < UpdateInterval {
		fmt.Println("[+] CVE Database: Local snapshot is fresh, loading from disk...")
		loadFromDisk()
		return
	}

	fullURL, deltaURL, err := getLatestURLs()
	if err != nil {
		fmt.Printf("[-] CVE GitHub API failed: %v — probing known release timestamps...\n", err)
		fullURL = probeSnapshotURL()
	}

	if hasLocal && deltaURL != "" {
		fmt.Printf("[*] CVE Database: Downloading delta snapshot...\n    %s\n", deltaURL)
		if err := downloadAndProcessDelta(deltaURL); err != nil {
			fmt.Printf("[-] CVE Delta failed: %v. Falling back to full download...\n", err)
		} else {
			loadFromDisk()
			return
		}
	}

	fmt.Printf("[*] CVE Database: Downloading nightly snapshot...\n    %s\n", fullURL)

	if err := downloadAndProcess(fullURL); err != nil {
		fmt.Printf("[-] CVE Snapshot failed: %v\n", err)
		if hasLocal {
			fmt.Println("[~] CVE Database: Loading previous snapshot as fallback...")
			loadFromDisk()
		} else {
			fmt.Println("[~] CVE Database: No local snapshot available.")
		}
		return
	}

	loadFromDisk()
}

// --- Download & Process ---

func downloadAndProcess(zipURL string) error {
	client := &http.Client{Timeout: 15 * time.Minute}

	resp, err := client.Get(zipURL)
	if err != nil {
		return fmt.Errorf("network error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed with HTTP %d for URL: %s", resp.StatusCode, zipURL)
	}

	fmt.Println("[*] CVE Database: Reading ZIP into memory...")
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read error: %v", err)
	}
	fmt.Printf("[*] CVE Database: Downloaded %.1f MB, parsing...\n", float64(len(zipData))/1024/1024)

	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("zip open error: %v", err)
	}

	records, err := processEntries(zipReader)
	if err != nil {
		return err
	}

	fmt.Printf("[+] CVE Database: Parsed %d CVEs, writing to disk...\n", len(records))
	outBytes, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("marshal error: %v", err)
	}
	return os.WriteFile(FullDBFile, outBytes, 0644)
}

func downloadAndProcessDelta(zipURL string) error {
	client := &http.Client{Timeout: 15 * time.Minute}

	resp, err := client.Get(zipURL)
	if err != nil {
		return fmt.Errorf("network error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d from GitHub", resp.StatusCode)
	}

	fmt.Println("[*] CVE Database: Reading delta ZIP into memory...")
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read error: %v", err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("zip open error: %v", err)
	}

	deltaRecords, err := processEntries(zipReader)
	if err != nil {
		return err
	}

	fmt.Printf("[*] CVE Database: Parsed %d delta CVEs. Merging with local DB...\n", len(deltaRecords))

	existingData, err := os.ReadFile(FullDBFile)
	if err != nil {
		return fmt.Errorf("failed to read local db for merge: %v", err)
	}

	var localDB []models.LocalCVE
	if err := json.Unmarshal(existingData, &localDB); err != nil {
		return fmt.Errorf("failed to parse local db: %v", err)
	}

	cveMap := make(map[string]int)
	for i, rec := range localDB {
		cveMap[rec.ID] = i
	}

	updates, adds := 0, 0
	for _, deltaRec := range deltaRecords {
		if idx, exists := cveMap[deltaRec.ID]; exists {
			localDB[idx] = deltaRec
			updates++
		} else {
			localDB = append(localDB, deltaRec)
			cveMap[deltaRec.ID] = len(localDB) - 1
			adds++
		}
	}
	fmt.Printf("[+] CVE Database: %d updated, %d added. Writing to disk...\n", updates, adds)

	outBytes, err := json.Marshal(localDB)
	if err != nil {
		return fmt.Errorf("marshal error: %v", err)
	}

	err = os.WriteFile(FullDBFile, outBytes, 0644)
	if err == nil {
		now := time.Now()
		os.Chtimes(FullDBFile, now, now)
	}
	return err
}

func processEntries(zipReader *zip.Reader) ([]models.LocalCVE, error) {
	var records []models.LocalCVE
	processed, skipped := 0, 0

	for _, f := range zipReader.File {
		base := path.Base(f.Name)

		// Handle nested ZIP (.zip.zip case)
		if strings.HasSuffix(strings.ToLower(f.Name), ".zip") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			innerData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}
			innerReader, err := zip.NewReader(bytes.NewReader(innerData), int64(len(innerData)))
			if err != nil {
				continue
			}
			inner, _ := processEntries(innerReader)
			records = append(records, inner...)
			continue
		}

		if !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		if !strings.HasPrefix(base, "CVE-") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		rec := parseCVE5(data)
		if rec == nil {
			skipped++
			continue
		}

		records = append(records, *rec)
		processed++
		if processed%20000 == 0 {
			fmt.Printf("[*] CVE Database: Processed %d records...\n", processed)
		}
	}
	fmt.Printf("[+] CVE Database: %d parsed, %d skipped\n", processed, skipped)
	return records, nil
}

// --- CVE JSON 5.0 Parser ---

func parseCVE5(data []byte) *models.LocalCVE {
	var root cve5Root
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	if root.CveMetadata.State != "PUBLISHED" {
		return nil
	}

	desc := ""
	for _, d := range root.Containers.CNA.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
		if d.Lang == "en-US" && desc == "" {
			desc = d.Value
		}
	}
	if desc == "" {
		return nil
	}

	var cvss float64
	severity := ""
	for _, m := range root.Containers.CNA.Metrics {
		if m.CvssV31 != nil && m.CvssV31.BaseScore > 0 {
			cvss = m.CvssV31.BaseScore
			severity = strings.ToUpper(m.CvssV31.BaseSeverity)
			break
		}
		if m.CvssV30 != nil && m.CvssV30.BaseScore > 0 && cvss == 0 {
			cvss = m.CvssV30.BaseScore
			severity = strings.ToUpper(m.CvssV30.BaseSeverity)
		}
	}
	if cvss == 0 {
		cvss = EstimateCVSS(desc)
	}
	if severity == "" {
		severity = CVSSToSeverity(cvss)
	}

	vendor, product, version := "", "", ""
	if len(root.Containers.CNA.Affected) > 0 {
		aff := root.Containers.CNA.Affected[0]
		vendor = strings.ToLower(strings.TrimSpace(aff.Vendor))
		product = strings.ToLower(strings.TrimSpace(aff.Product))
		if len(aff.Versions) > 0 {
			version = aff.Versions[0].Version
		}
	}
	if product == "" || product == "n/a" || product == "none" {
		return nil
	}

	if len(desc) > 400 {
		desc = desc[:397] + "..."
	}

	return &models.LocalCVE{
		ID:            root.CveMetadata.CveID,
		VendorProject: vendor,
		Product:       product,
		Version:       version,
		CVSS:          cvss,
		Severity:      severity,
		Description:   desc,
	}
}

// --- Load from Disk + Build Index ---

func loadFromDisk() {
	data, err := os.ReadFile(FullDBFile)
	if err != nil {
		fmt.Printf("[-] CVE Database: Cannot read %s: %v\n", FullDBFile, err)
		return
	}

	var records []models.LocalCVE
	if err := json.Unmarshal(data, &records); err != nil {
		fmt.Printf("[-] CVE Database: JSON parse error: %v\n", err)
		return
	}

	index := make(map[string][]int, len(records)*2)
	for i, rec := range records {
		index[rec.Product] = append(index[rec.Product], i)
		if rec.VendorProject != "" {
			vKey := rec.VendorProject + ":" + rec.Product
			index[vKey] = append(index[vKey], i)
		}
	}

	indexMu.Lock()
	MemoryDB = records
	productIndex = index
	indexMu.Unlock()

	fmt.Printf("[+] CVE Database: %d CVEs ready in RAM (product index: %d keys).\n", len(records), len(index))
}

// --- Search ---

// Search performs a fast indexed product CVE lookup.
func Search(product, version string) []models.LocalCVE {
	product = strings.ToLower(strings.TrimSpace(product))
	if product == "" {
		return nil
	}

	indexMu.RLock()
	defer indexMu.RUnlock()

	if productIndex == nil {
		return searchLinear(product)
	}

	seen := make(map[int]struct{})
	var matches []models.LocalCVE

	for _, idx := range productIndex[product] {
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		matches = append(matches, MemoryDB[idx])
		if len(matches) >= 25 {
			return matches
		}
	}
	return matches
}

func searchLinear(product string) []models.LocalCVE {
	var out []models.LocalCVE
	for _, cve := range MemoryDB {
		if strings.Contains(cve.Product, product) || strings.Contains(product, cve.Product) {
			out = append(out, cve)
			if len(out) >= 10 {
				break
			}
		}
	}
	return out
}

// GetStats returns database statistics.
func GetStats() map[string]interface{} {
	indexMu.RLock()
	defer indexMu.RUnlock()
	return map[string]interface{}{
		"total_cves": len(MemoryDB),
		"index_keys": len(productIndex),
		"db_file":    FullDBFile,
	}
}

// GetFirst returns the first n CVE records (thread-safe).
func GetFirst(n int) []models.LocalCVE {
	indexMu.RLock()
	defer indexMu.RUnlock()
	if n > len(MemoryDB) {
		n = len(MemoryDB)
	}
	result := make([]models.LocalCVE, n)
	copy(result, MemoryDB[:n])
	return result
}

// --- Helpers ---

func EstimateCVSS(description string) float64 {
	desc := strings.ToLower(description)
	switch {
	case strings.Contains(desc, "remote code execution") || strings.Contains(desc, "arbitrary code") || strings.Contains(desc, "rce"):
		return 9.8
	case strings.Contains(desc, "deserialization") || strings.Contains(desc, "untrusted data"):
		return 9.5
	case strings.Contains(desc, "authentication bypass") || strings.Contains(desc, "ssrf"):
		return 9.1
	case strings.Contains(desc, "privilege escalation"):
		return 8.8
	case strings.Contains(desc, "buffer overflow") || strings.Contains(desc, "use-after-free"):
		return 8.6
	case strings.Contains(desc, "sql injection") || strings.Contains(desc, "xxe"):
		return 8.5
	case strings.Contains(desc, "path traversal") || strings.Contains(desc, "local file inclusion"):
		return 7.5
	case strings.Contains(desc, "information disclosure") || strings.Contains(desc, "sensitive information"):
		return 6.5
	case strings.Contains(desc, "cross-site scripting") || strings.Contains(desc, "xss") || strings.Contains(desc, "csrf"):
		return 6.1
	case strings.Contains(desc, "denial of service") || strings.Contains(desc, "dos"):
		return 5.5
	default:
		return 7.5
	}
}

func CVSSToSeverity(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "CRITICAL"
	case cvss >= 7.0:
		return "HIGH"
	case cvss >= 4.0:
		return "MEDIUM"
	case cvss > 0:
		return "LOW"
	default:
		return "INFO"
	}
}
