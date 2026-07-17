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
	FullDBFile     = "cve/cve_full.json"
	// CVEProject publishes multiple snapshots per day; 6h ensures we always
	// pick up the latest one without hammering GitHub on every restart.
	UpdateInterval = 6 * time.Hour
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
// CVEProject publishes at various times throughout the day (checked 2026-07-16:
// 1100Z confirmed). The list covers every hour from 23:00 down to 00:00 UTC.
var knownTimestamps = []string{
	"2300Z", "2200Z", "2100Z", "2000Z", "1900Z",
	"1800Z", "1700Z", "1600Z", "1500Z", "1400Z",
	"1300Z", "1200Z", "1100Z", "1000Z", "0900Z",
	"0800Z", "0700Z", "0600Z", "0500Z", "0400Z",
	"0300Z", "0200Z", "0100Z", "0000Z",
}

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

	// Two-pass asset selection:
	// Pass 1 — collect all candidates.
	// Pass 2 — prefer end-of-day delta (most comprehensive) over intraday ones.
	var endOfDayDeltaURL string
	var anyDeltaURL string

	for _, asset := range release.Assets {
		name := asset.Name
		switch {
		case strings.Contains(name, "all_CVEs") && strings.HasSuffix(name, ".zip.zip"):
			fullURL = asset.BrowserDownloadURL

		case strings.Contains(name, "delta_CVEs") &&
			strings.HasSuffix(name, ".zip") &&
			!strings.HasSuffix(name, ".zip.zip"):
			// end-of-day delta is the gold standard — covers every CVE change
			// published throughout the day, not just the midnight snapshot delta.
			if strings.Contains(name, "at_end_of_day") {
				endOfDayDeltaURL = asset.BrowserDownloadURL
			} else {
				anyDeltaURL = asset.BrowserDownloadURL
			}
		}
	}

	// Prefer end-of-day delta; fall back to any other delta variant.
	if endOfDayDeltaURL != "" {
		deltaURL = endOfDayDeltaURL
		fmt.Println("[+] CVE Database: End-of-day delta available, using it.")
	} else if anyDeltaURL != "" {
		deltaURL = anyDeltaURL
	}

	if fullURL == "" {
		return "", "", fmt.Errorf("could not find full url")
	}
	return fullURL, deltaURL, nil
}

// SyncFullDatabase downloads and loads the CVEProject nightly snapshot.
// Blocks until complete; safe to call at startup.
func SyncFullDatabase() {
	os.MkdirAll("cve", os.ModePerm)

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
	outBytes, err := json.MarshalIndent(records, "", "  ")
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

	outBytes, err := json.MarshalIndent(localDB, "", "  ")
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
	processed := 0
	skipReasons := map[string]int{
		"state":   0, // REJECTED / RESERVED
		"no_desc": 0, // no usable description in any language
		"no_prod": 0, // no product AND no vendor AND no desc hint
	}

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

		rec, skipReason := parseCVE5(data)
		if rec == nil {
			skipReasons[skipReason]++
			continue
		}

		records = append(records, *rec)
		processed++
		if processed%20000 == 0 {
			fmt.Printf("[*] CVE Database: Processed %d records...\n", processed)
		}
	}
	totalSkipped := skipReasons["state"] + skipReasons["no_desc"] + skipReasons["no_prod"]
	fmt.Printf("[+] CVE Database: %d parsed, %d skipped (state=%d, no_desc=%d, no_product=%d)\n",
		processed, totalSkipped, skipReasons["state"], skipReasons["no_desc"], skipReasons["no_prod"])
	return records, nil
}

// --- CVE JSON 5.0 Parser ---

// parseCVE5 parses a single CVE JSON 5.0 file into a LocalCVE record.
// Returns (nil, reason) when the entry should be discarded.
// Skip reasons:
//   - "state"   : entry is REJECTED or RESERVED (no real data)
//   - "no_desc" : no description found in any language
//   - "no_prod" : cannot derive a product identifier by any fallback
func parseCVE5(data []byte) (*models.LocalCVE, string) {
	var root cve5Root
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, "state"
	}

	// Only REJECTED and RESERVED are genuinely useless.
	state := root.CveMetadata.State
	if state == "REJECTED" || state == "RESERVED" {
		return nil, "state"
	}

	// --- Description: prefer English, fall back to any language ---
	desc := ""
	var anyLangDesc string
	for _, d := range root.Containers.CNA.Descriptions {
		switch d.Lang {
		case "en":
			desc = d.Value
		case "en-US", "en-GB":
			if desc == "" {
				desc = d.Value
			}
		default:
			if anyLangDesc == "" {
				anyLangDesc = d.Value
			}
		}
	}
	if desc == "" {
		desc = anyLangDesc // last resort: non-English description
	}
	if desc == "" {
		return nil, "no_desc"
	}

	// --- CVSS score ---
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

	// --- Product resolution: 3-tier fallback ---
	vendor, product, version := "", "", ""
	if len(root.Containers.CNA.Affected) > 0 {
		aff := root.Containers.CNA.Affected[0]
		vendor = strings.ToLower(strings.TrimSpace(aff.Vendor))
		product = strings.ToLower(strings.TrimSpace(aff.Product))
		if len(aff.Versions) > 0 {
			version = aff.Versions[0].Version
		}
	}

	// Tier 1: clean up placeholder values
	if product == "n/a" || product == "none" || product == "unspecified" {
		product = ""
	}
	if vendor == "n/a" || vendor == "none" || vendor == "unspecified" {
		vendor = ""
	}

	// Tier 2: fall back to vendor when product is missing
	if product == "" && vendor != "" {
		product = vendor
	}

	// Tier 3: extract a hint from the description.
	// Looks for patterns like "in X ", "in the X ", "plugin X", "software X".
	if product == "" {
		product = extractProductHint(desc)
	}

	if product == "" {
		return nil, "no_prod"
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
	}, ""
}

// extractProductHint attempts to derive a product name from a CVE description
// by scanning for common grammatical patterns used in vulnerability write-ups.
func extractProductHint(desc string) string {
	descLower := strings.ToLower(desc)

	// Patterns: "vulnerability in X", "issue in X", "flaw in X", "bug in X",
	//           "in the X plugin", "in X before", "affecting X"
	patterns := []struct{ prefix, stop string }{
		{"vulnerability in the ", " "},
		{"vulnerability in ", " "},
		{"issue in the ", " "},
		{"issue in ", " "},
		{"flaw in the ", " "},
		{"flaw in ", " "},
		{"in the ", " plugin"},
		{"in the ", " component"},
		{"in the ", " module"},
		{"affecting ", " "},
	}

	for _, p := range patterns {
		idx := strings.Index(descLower, p.prefix)
		if idx < 0 {
			continue
		}
		start := idx + len(p.prefix)
		end := strings.Index(descLower[start:], p.stop)
		if end < 0 {
			// take up to next space or end
			end = strings.IndexAny(descLower[start:], " ,.(")
		}
		if end < 0 {
			end = len(descLower) - start
		}
		hint := strings.TrimSpace(desc[start : start+end])
		hint = strings.ToLower(hint)
		// Sanity: reject if it looks like noise
		if len(hint) >= 2 && len(hint) <= 60 &&
			!strings.ContainsAny(hint, "<>{}") {
			return hint
		}
	}
	return ""
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

// Search performs a fast indexed CVE lookup by product name.
// It queries both the plain product key and any vendor:product composite key,
// returning up to 50 deduplicated results for the caller to filter further.
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

	// Collect candidate index positions from all matching keys.
	// Keys to probe: exact product, and any "vendor:product" entry.
	keysToProbe := []string{product}
	for k := range productIndex {
		// vendor:product composite keys contain a colon
		if strings.HasSuffix(k, ":"+product) {
			keysToProbe = append(keysToProbe, k)
		}
	}

	for _, key := range keysToProbe {
		for _, idx := range productIndex[key] {
			if _, ok := seen[idx]; ok {
				continue
			}
			seen[idx] = struct{}{}
			matches = append(matches, MemoryDB[idx])
			if len(matches) >= 50 {
				return matches
			}
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
