// Package sci provides the Supply Chain Interface for DORM.
// It performs deep technology fingerprinting of a target URL, detects all
// components (frontend libraries, backend frameworks, CDN, infrastructure, analytics)
// and enriches each component with CVE data from the local CVE database.
package sci

import (
	"DORM/models"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ─── Data Structures ──────────────────────────────────────────────────────────

// SCIComponent represents a single detected technology component with its CVE data.
type SCIComponent struct {
	Name        string           `json:"name"`
	Version     string           `json:"version"`
	Category    string           `json:"category"`    // Frontend, Backend, Infrastructure, CDN, Analytics, Security, Database
	Source      string           `json:"source"`      // header, html-meta, js-global, script-src, response-body
	CVEs        []models.LocalCVE `json:"cves"`
	CVECount    int              `json:"cve_count"`
	HighestCVSS float64          `json:"highest_cvss"`
	RiskLevel   string           `json:"risk_level"` // CRITICAL, HIGH, MEDIUM, LOW, SAFE
}

// SupplyChainResult is the full analysis result for a target.
type SupplyChainResult struct {
	Target       string         `json:"target"`
	Components   []SCIComponent `json:"components"`
	TotalCVEs    int            `json:"total_cves"`
	RiskSummary  RiskSummary    `json:"risk_summary"`
	ScanDuration string         `json:"scan_duration"`
	Error        string         `json:"error,omitempty"`
}

// RiskSummary provides aggregated risk metrics.
type RiskSummary struct {
	TotalComponents int `json:"total_components"`
	WithCVEs        int `json:"with_cves"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	Safe            int `json:"safe"`
}

// ─── Detection Signatures ─────────────────────────────────────────────────────

type techSignature struct {
	Name           string `json:"name"`
	Category       string `json:"category"`
	HeaderKey      string `json:"header_key,omitempty"`
	HeaderValue    string `json:"header_value,omitempty"`
	BodyPattern    string `json:"body_pattern,omitempty"`
	VersionPattern string `json:"version_pattern,omitempty"`
}

//go:embed signature/*.json
var signatureFiles embed.FS

var signatures []techSignature

func init() {
	files, err := signatureFiles.ReadDir("signature")
	if err != nil {
		fmt.Printf("[SCI] Warning: Could not read signature directory: %v\n", err)
		return
	}

	for _, file := range files {
		data, err := signatureFiles.ReadFile("signature/" + file.Name())
		if err == nil {
			var sig techSignature
			if err := json.Unmarshal(data, &sig); err == nil {
				signatures = append(signatures, sig)
			}
		}
	}
}

// ─── HTTP Client ──────────────────────────────────────────────────────────────

var sciClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// ─── Core Analysis ────────────────────────────────────────────────────────────

// AnalyzeTarget performs a comprehensive supply chain analysis for the given URL.
// It uses models.DeepScanTarget for the core tech profile and augments with
// direct HTTP analysis (headers, body, JS files).
func AnalyzeTarget(targetURL string) SupplyChainResult {
	start := time.Now()

	// Normalize URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	result := SupplyChainResult{Target: targetURL}

	// ── Step 1: Fetch main page ────────────────────────────────────────────
	body, headers, err := fetchPage(targetURL)
	if err != nil {
		// Try HTTP fallback
		httpURL := strings.Replace(targetURL, "https://", "http://", 1)
		body, headers, err = fetchPage(httpURL)
		if err != nil {
			result.Error = fmt.Sprintf("Could not reach target: %v", err)
			result.ScanDuration = time.Since(start).Round(time.Millisecond).String()
			return result
		}
	}

	// ── Step 2: Run signature detection ───────────────────────────────────
	detected := runSignatureDetection(body, headers)

	// ── Step 3: Augment with models.DeepScanTarget (mevcut tech profiler) ─
	if models.DeepScanTarget != nil {
		profile := models.DeepScanTarget(targetURL)
		if profile != nil {
			for _, tech := range profile.Techs {
				if tech.Product == "" {
					continue
				}
				// Check if already detected — if yes, only fill in version
				found := false
				for i := range detected {
					if strings.EqualFold(detected[i].Name, tech.Product) {
						if detected[i].Version == "" && tech.Version != "" {
							detected[i].Version = tech.Version
						}
						found = true
						break
					}
				}
				if !found {
					detected = append(detected, SCIComponent{
						Name:     tech.Product,
						Version:  tech.Version,
						Category: "Backend",
						Source:   "deep-scan",
					})
				}
			}
		}
	}

	// ── Step 4: CVE Enrichment ─────────────────────────────────────────────
	if models.SearchLocalCVEs != nil {
		for i := range detected {
			if detected[i].Version == "" {
				detected[i].RiskLevel = "SAFE"
				continue
			}

			seen := make(map[string]struct{})
			cves := models.SearchLocalCVEs(detected[i].Name, detected[i].Version)
			var relevant []models.LocalCVE
			for _, c := range cves {
				key := c.ID
				if _, dup := seen[key]; dup {
					continue
				}
				// Version matching
				vulnerable := false
				if c.Version != "" {
					vulnerable = isVersionLE(detected[i].Version, c.Version) || detected[i].Version == c.Version
				}
				if !vulnerable {
					vulnerable = isVersionVulnerable(detected[i].Version, c.Description)
				}
				
				if vulnerable {
					relevant = append(relevant, c)
					seen[key] = struct{}{}
					if c.CVSS > detected[i].HighestCVSS {
						detected[i].HighestCVSS = c.CVSS
					}
				}
			}
			detected[i].CVEs = relevant
			detected[i].CVECount = len(relevant)
			detected[i].RiskLevel = cvssToRisk(detected[i].HighestCVSS, len(relevant))
		}
	} else {
		for i := range detected {
			detected[i].RiskLevel = "UNKNOWN"
		}
	}

	// ── Step 5: Sort by risk (CRITICAL first) ─────────────────────────────
	sortComponents(detected)

	// ── Step 6: Build summary ──────────────────────────────────────────────
	result.Components = detected
	result.RiskSummary = buildSummary(detected)
	for _, c := range detected {
		result.TotalCVEs += c.CVECount
	}
	result.ScanDuration = time.Since(start).Round(time.Millisecond).String()
	return result
}

// ─── HTTP Fetch ────────────────────────────────────────────────────────────────

func fetchPage(targetURL string) (string, http.Header, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := sciClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // Max 5MB
	return string(bodyBytes), resp.Header, nil
}

// ─── Signature Detection ──────────────────────────────────────────────────────

func runSignatureDetection(body string, headers http.Header) []SCIComponent {
	detectedMap := make(map[string]*SCIComponent) // deduplicate by Name+Category

	bodyLower := strings.ToLower(body)

	for _, sig := range signatures {
		comp := &SCIComponent{
			Name:     sig.Name,
			Category: sig.Category,
		}
		matched := false

		// ── Header-based detection ──────────────────────────────────────
		if sig.HeaderKey != "" {
			headerVal := headers.Get(sig.HeaderKey)
			if headerVal != "" {
				// Empty HeaderValue means "header presence is enough"
				if sig.HeaderValue == "" || strings.Contains(strings.ToLower(headerVal), strings.ToLower(sig.HeaderValue)) {
					matched = true
					comp.Source = "header:" + sig.HeaderKey

					// Try to extract version
					if sig.VersionPattern != "" {
						re := regexp.MustCompile(`(?i)` + sig.VersionPattern)
						m := re.FindStringSubmatch(headerVal)
						if len(m) > 1 {
							comp.Version = m[1]
						} else {
							// Try in full header set
							for _, hVal := range flatHeaders(headers) {
								m2 := re.FindStringSubmatch(hVal)
								if len(m2) > 1 {
									comp.Version = m2[1]
									break
								}
							}
						}
					}
				}
			}
		}

		// ── Body-based detection ────────────────────────────────────────
		if sig.BodyPattern != "" {
			re := regexp.MustCompile(`(?i)` + sig.BodyPattern)
			if re.MatchString(bodyLower) {
				matched = true
				if comp.Source == "" {
					comp.Source = "html-body"
				}

				// Try version from body
				if sig.VersionPattern != "" && comp.Version == "" {
					reV := regexp.MustCompile(`(?i)` + sig.VersionPattern)
					m := reV.FindStringSubmatch(body)
					if len(m) > 1 {
						comp.Version = m[1]
					}
				}
			}
		}

		if !matched {
			continue
		}

		// Dedup key
		key := strings.ToLower(comp.Name + "|" + comp.Category)
		if existing, ok := detectedMap[key]; ok {
			// Prefer the one with a version
			if existing.Version == "" && comp.Version != "" {
				existing.Version = comp.Version
			}
		} else {
			detectedMap[key] = comp
		}
	}

	// Convert map to slice
	result := make([]SCIComponent, 0, len(detectedMap))
	for _, c := range detectedMap {
		result = append(result, *c)
	}
	return result
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func flatHeaders(h http.Header) []string {
	var out []string
	for k, vals := range h {
		for _, v := range vals {
			out = append(out, k+": "+v)
		}
	}
	return out
}

func cvssToRisk(cvss float64, cveCount int) string {
	if cveCount == 0 {
		return "SAFE"
	}
	switch {
	case cvss >= 9.0:
		return "CRITICAL"
	case cvss >= 7.0:
		return "HIGH"
	case cvss >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func sortComponents(comps []SCIComponent) {
	order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4, "UNKNOWN": 5}
	sort.SliceStable(comps, func(i, j int) bool {
		oi := order[comps[i].RiskLevel]
		oj := order[comps[j].RiskLevel]
		if oi != oj {
			return oi < oj
		}
		return comps[i].HighestCVSS > comps[j].HighestCVSS
	})
}

func buildSummary(comps []SCIComponent) RiskSummary {
	s := RiskSummary{TotalComponents: len(comps)}
	for _, c := range comps {
		if c.CVECount > 0 {
			s.WithCVEs++
		}
		switch c.RiskLevel {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		case "LOW":
			s.Low++
		default:
			s.Safe++
		}
	}
	return s
}

// isVersionLE returns true if v1 <= v2 (semantic version comparison).
func isVersionLE(v1, v2 string) bool {
	p1 := strings.Split(v1, ".")
	p2 := strings.Split(v2, ".")
	maxLen := len(p1)
	if len(p2) > maxLen {
		maxLen = len(p2)
	}
	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(p1) {
			fmt.Sscanf(p1[i], "%d", &n1)
		}
		if i < len(p2) {
			fmt.Sscanf(p2[i], "%d", &n2)
		}
		if n1 < n2 {
			return true
		}
		if n1 > n2 {
			return false
		}
	}
	return true // equal
}

// isVersionVulnerable checks NLP version constraints in a CVE description.
func isVersionVulnerable(targetVersion, description string) bool {
	if targetVersion == "" {
		return false
	}
	desc := strings.ToLower(description)
	if strings.Contains(desc, targetVersion) {
		return true
	}
	re := regexp.MustCompile(`(?:prior to|before|through|up to|<=|<)\s*v?([0-9]+(?:\.[0-9]+)*)`)
	matches := re.FindAllStringSubmatch(desc, -1)
	for _, m := range matches {
		if len(m) > 1 {
			limit := m[1]
			if strings.Contains(m[0], "through") || strings.Contains(m[0], "up to") || strings.Contains(m[0], "<=") {
				if targetVersion == limit || isVersionLE(targetVersion, limit) {
					return true
				}
			} else {
				if isVersionLE(targetVersion, limit) && targetVersion != limit {
					return true
				}
			}
		}
	}
	return false
}
