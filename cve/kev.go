package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// --- KEV Data Structures ---

type CisaKEVCatalog struct {
	Vulnerabilities []KEVVulnerability `json:"vulnerabilities"`
}

type KEVVulnerability struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	Action            string `json:"requiredAction"`
	RansomwareUse     string `json:"knownRansomwareCampaignUse"`
}

type EPSSResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// Our unified model sent to the frontend
type KEVRecord struct {
	CVEID             string  `json:"cveID"`
	VendorProject     string  `json:"vendorProject"`
	Product           string  `json:"product"`
	VulnerabilityName string  `json:"vulnerabilityName"`
	DateAdded         string  `json:"dateAdded"`
	ShortDescription  string  `json:"shortDescription"`
	RansomwareUse     string  `json:"ransomwareUse"`
	EPSSScore         float64 `json:"epssScore"`
	CVSSScore         float64 `json:"cvssScore"`
}

type KEVBuckets struct {
	SinceYesterday []KEVRecord `json:"sinceYesterday"`
	Last7Days      []KEVRecord `json:"last7Days"`
	Last30Days     []KEVRecord `json:"last30Days"`
}

var (
	kevCache       *KEVBuckets
	kevCacheMutex  sync.RWMutex
	lastKEVFetch   time.Time
	kevCacheTTL    = 6 * time.Hour
)

// GetRecentKEVs returns the bucketed KEV records. Uses caching to avoid rate limits.
func GetRecentKEVs() (*KEVBuckets, error) {
	kevCacheMutex.RLock()
	if kevCache != nil && time.Since(lastKEVFetch) < kevCacheTTL {
		defer kevCacheMutex.RUnlock()
		return kevCache, nil
	}
	kevCacheMutex.RUnlock()

	kevCacheMutex.Lock()
	defer kevCacheMutex.Unlock()

	// Double check pattern
	if kevCache != nil && time.Since(lastKEVFetch) < kevCacheTTL {
		return kevCache, nil
	}

	buckets, err := fetchAndBuildKEVBuckets()
	if err != nil {
		return nil, err
	}

	kevCache = buckets
	lastKEVFetch = time.Now()

	return kevCache, nil
}

func fetchAndBuildKEVBuckets() (*KEVBuckets, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", "https://raw.githubusercontent.com/EugenMayer/cisa-known-exploited-mirror/main/known_exploited_vulnerabilities.json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CISA KEV: %v", err)
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)

	var catalog CisaKEVCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("failed to decode CISA KEV: %v", err)
	}

	// 2. Sort vulnerabilities by DateAdded descending (newest first)
	sort.SliceStable(catalog.Vulnerabilities, func(i, j int) bool {
		return catalog.Vulnerabilities[i].DateAdded > catalog.Vulnerabilities[j].DateAdded
	})

	now := time.Now()
	// Parse the dates and bucket them
	var bucket1, bucket2, bucket3 []KEVVulnerability

	for _, v := range catalog.Vulnerabilities {
		addedDate, err := time.Parse("2006-01-02", v.DateAdded)
		if err != nil {
			continue
		}

		daysDiff := now.Sub(addedDate).Hours() / 24.0

		// Bucket logic: Cumulative!
		if daysDiff <= 2.0 {
			// Since Yesterday (Up to 48 hours to be safe with timezones)
			bucket1 = append(bucket1, v)
		}
		if daysDiff <= 7.0 {
			// Last 7 days (includes <= 2.0)
			bucket2 = append(bucket2, v)
		}
		if daysDiff <= 30.0 {
			// Last 30 days (includes <= 7.0)
			bucket3 = append(bucket3, v)
		}
	}

	// If buckets are completely empty (maybe CISA hasn't updated in months), let's grab the most recent 10 and put them in 30 days.
	if len(bucket1) == 0 && len(bucket2) == 0 && len(bucket3) == 0 {
		for i := 0; i < 15 && i < len(catalog.Vulnerabilities); i++ {
			bucket3 = append(bucket3, catalog.Vulnerabilities[i])
		}
	}

	// 3. Fetch EPSS scores for these CVEs
	allCVEsToFetch := make([]string, 0)
	for _, v := range bucket1 {
		allCVEsToFetch = append(allCVEsToFetch, v.CVEID)
	}
	for _, v := range bucket2 {
		allCVEsToFetch = append(allCVEsToFetch, v.CVEID)
	}
	for _, v := range bucket3 {
		allCVEsToFetch = append(allCVEsToFetch, v.CVEID)
	}

	epssMap := fetchEPSSScores(client, allCVEsToFetch)

	// 4. Build final response
	buckets := &KEVBuckets{
		SinceYesterday: mapToKEVRecords(bucket1, epssMap),
		Last7Days:      mapToKEVRecords(bucket2, epssMap),
		Last30Days:     mapToKEVRecords(bucket3, epssMap),
	}

	return buckets, nil
}

func fetchEPSSScores(client *http.Client, cveIDs []string) map[string]float64 {
	epssMap := make(map[string]float64)
	if len(cveIDs) == 0 {
		return epssMap
	}

	// FIRST EPSS API accepts comma separated CVEs
	cveString := strings.Join(cveIDs, ",")
	url := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cveString)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return epssMap
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return epssMap
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)

	var epssResp EPSSResponse
	if err := json.Unmarshal(body, &epssResp); err != nil {
		return epssMap
	}

	for _, d := range epssResp.Data {
		var score float64
		fmt.Sscanf(d.EPSS, "%f", &score)
		epssMap[d.CVE] = score
	}

	return epssMap
}

func mapToKEVRecords(vulns []KEVVulnerability, epssMap map[string]float64) []KEVRecord {
	var records []KEVRecord
	for _, v := range vulns {
		score, _ := epssMap[v.CVEID]
		var cvssScore float64
		if localCve := GetCVEByID(v.CVEID); localCve != nil {
			cvssScore = localCve.CVSS
		}
		records = append(records, KEVRecord{
			CVEID:             v.CVEID,
			VendorProject:     v.VendorProject,
			Product:           v.Product,
			VulnerabilityName: v.VulnerabilityName,
			DateAdded:         v.DateAdded,
			ShortDescription:  v.ShortDescription,
			RansomwareUse:     v.RansomwareUse,
			EPSSScore:         score,
			CVSSScore:         cvssScore,
		})
	}
	if records == nil {
		records = make([]KEVRecord, 0)
	}
	return records
}
