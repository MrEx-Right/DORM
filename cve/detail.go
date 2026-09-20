// Package cve — live CVE detail lookups.
//
// The local index (sync.go / cve_full.json) only stores a truncated
// (≤400 char) description and a handful of fields, so there is nothing
// worth showing when a user drills into a specific CVE from a search
// result. This file adds an on-demand lookup against the NVD REST API
// (services.nvd.nist.gov), which carries the full description, CVSS
// vector, CWE weaknesses, references, and CISA KEV linkage for a given
// CVE ID — a proper source for a detail view instead of the bare JSON.
package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type CVEDetail struct {
	CVEID        string   `json:"cveID"`
	Description  string   `json:"description"`
	Published    string   `json:"published"`
	LastModified string   `json:"lastModified"`
	CVSSVersion  string   `json:"cvssVersion"`
	CVSSVector   string   `json:"cvssVector"`
	CVSSScore    float64  `json:"cvssScore"`
	Severity     string   `json:"severity"`
	CWEs         []string `json:"cwes"`
	References   []CVERef `json:"references"`
	IsKEV        bool     `json:"isKev"`
	KEVName      string   `json:"kevName,omitempty"`
}

type CVERef struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// --- NVD API response structures (only the fields we use) ---

type nvdAPIResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []nvdCvssMetric `json:"cvssMetricV31"`
				CvssMetricV30 []nvdCvssMetric `json:"cvssMetricV30"`
				CvssMetricV2  []nvdCvssMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			References []struct {
				URL  string   `json:"url"`
				Tags []string `json:"tags"`
			} `json:"references"`
			CisaExploitAdd        string `json:"cisaExploitAdd"`
			CisaVulnerabilityName string `json:"cisaVulnerabilityName"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCvssMetric struct {
	CvssData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// --- Cache: CVE detail data almost never changes, so cache indefinitely
// for the lifetime of the process to stay well under NVD's unauthenticated
// rate limit (5 requests / 30s) when the same CVE is viewed repeatedly. ---

var (
	detailCache   = make(map[string]*CVEDetail)
	detailCacheMu sync.RWMutex
)

// GetCVEDetail fetches full CVE details from the NVD API for the given
// CVE ID, using a per-process cache to avoid redundant network calls.
func GetCVEDetail(id string) (*CVEDetail, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	if id == "" {
		return nil, fmt.Errorf("empty CVE ID")
	}

	detailCacheMu.RLock()
	if cached, ok := detailCache[id]; ok {
		detailCacheMu.RUnlock()
		return cached, nil
	}
	detailCacheMu.RUnlock()

	detail, err := fetchCVEDetailFromNVD(id)
	if err != nil {
		return nil, err
	}

	detailCacheMu.Lock()
	detailCache[id] = detail
	detailCacheMu.Unlock()

	return detail, nil
}

func fetchCVEDetailFromNVD(id string) (*CVEDetail, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read NVD response: %v", err)
	}

	var nvdResp nvdAPIResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("failed to decode NVD response: %v", err)
	}

	if nvdResp.TotalResults == 0 || len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found in NVD", id)
	}

	cve := nvdResp.Vulnerabilities[0].CVE

	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}

	detail := &CVEDetail{
		CVEID:        cve.ID,
		Description:  desc,
		Published:    cve.Published,
		LastModified: cve.LastModified,
	}

	// Prefer the newest CVSS version available.
	switch {
	case len(cve.Metrics.CvssMetricV31) > 0:
		m := cve.Metrics.CvssMetricV31[0].CvssData
		detail.CVSSVersion, detail.CVSSVector, detail.CVSSScore, detail.Severity = m.Version, m.VectorString, m.BaseScore, m.BaseSeverity
	case len(cve.Metrics.CvssMetricV30) > 0:
		m := cve.Metrics.CvssMetricV30[0].CvssData
		detail.CVSSVersion, detail.CVSSVector, detail.CVSSScore, detail.Severity = m.Version, m.VectorString, m.BaseScore, m.BaseSeverity
	case len(cve.Metrics.CvssMetricV2) > 0:
		m := cve.Metrics.CvssMetricV2[0].CvssData
		detail.CVSSVersion, detail.CVSSVector, detail.CVSSScore, detail.Severity = m.Version, m.VectorString, m.BaseScore, CVSSToSeverity(m.BaseScore)
	}

	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && strings.HasPrefix(d.Value, "CWE-") {
				detail.CWEs = append(detail.CWEs, d.Value)
			}
		}
	}

	for _, r := range cve.References {
		detail.References = append(detail.References, CVERef{URL: r.URL, Tags: r.Tags})
	}

	if cve.CisaExploitAdd != "" {
		detail.IsKEV = true
		detail.KEVName = cve.CisaVulnerabilityName
	}

	return detail, nil
}
