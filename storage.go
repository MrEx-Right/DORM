package main

import (
	"DORM/models"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ScanRecord represents a single execution of the scanner.

type ScanRecord struct {
	ID              string                  `json:"id"`
	Target          string                  `json:"target"`
	StartTime       time.Time               `json:"start_time"`
	EndTime         time.Time               `json:"end_time"`
	Status          string                  `json:"status"`
	Vulnerabilities []*models.Vulnerability `json:"vulnerabilities"`
	TotalVulns      int                     `json:"total_vulns"`
	SeverityStats   map[string]int          `json:"severity_stats"`
}

type DBScanRecord struct {
	ID              string `gorm:"primaryKey"`
	Target          string
	StartTime       time.Time
	EndTime         time.Time
	Status          string
	TotalVulns      int
	SeverityStats   []byte
	Vulnerabilities []byte
	CreatedAt       time.Time `gorm:"index"`
}

// StorageManager handles thread-safe DB operations.
type StorageManager struct {
	db    *gorm.DB
	Mutex sync.RWMutex
}

// DB is the global singleton instance of the StorageManager.
var DB *StorageManager

// InitDB initializes the SQLite storage engine.
func InitDB(path string) {

	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("[!] Failed to connect to database: %v", err)
	}

	err = database.AutoMigrate(&DBScanRecord{})
	if err != nil {
		log.Fatalf("[!] Database migration failed: %v", err)
	}

	DB = &StorageManager{
		db: database,
	}
}

func (r *DBScanRecord) toAppModel() ScanRecord {
	var vulns []*models.Vulnerability
	var stats map[string]int

	if len(r.Vulnerabilities) > 0 {
		json.Unmarshal(r.Vulnerabilities, &vulns)
	}
	if len(r.SeverityStats) > 0 {
		json.Unmarshal(r.SeverityStats, &stats)
	}

	if stats == nil {
		stats = make(map[string]int)
	}
	if vulns == nil {
		vulns = []*models.Vulnerability{}
	}

	return ScanRecord{
		ID:              r.ID,
		Target:          r.Target,
		StartTime:       r.StartTime,
		EndTime:         r.EndTime,
		Status:          r.Status,
		TotalVulns:      r.TotalVulns,
		Vulnerabilities: vulns,
		SeverityStats:   stats,
	}
}

func fromAppModel(app ScanRecord) DBScanRecord {
	vulnsJSON, _ := json.Marshal(app.Vulnerabilities)
	statsJSON, _ := json.Marshal(app.SeverityStats)

	return DBScanRecord{
		ID:              app.ID,
		Target:          app.Target,
		StartTime:       app.StartTime,
		EndTime:         app.EndTime,
		Status:          app.Status,
		TotalVulns:      app.TotalVulns,
		SeverityStats:   statsJSON,
		Vulnerabilities: vulnsJSON,
		CreatedAt:       app.StartTime,
	}
}

// --- STORAGE OPERATIONS ---

func (s *StorageManager) GetAll() ([]ScanRecord, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	var dbRecords []DBScanRecord

	if err := s.db.Order("created_at desc").Find(&dbRecords).Error; err != nil {
		return nil, err
	}

	var records []ScanRecord
	for _, r := range dbRecords {
		records = append(records, r.toAppModel())
	}

	return records, nil
}

func (s *StorageManager) GetByID(id string) (*ScanRecord, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	var dbRecord DBScanRecord
	if err := s.db.First(&dbRecord, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("scan record not found for ID: %s", id)
	}

	appModel := dbRecord.toAppModel()
	return &appModel, nil
}

func (s *StorageManager) SaveScan(record ScanRecord) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	dbRecord := fromAppModel(record)
	return s.db.Create(&dbRecord).Error
}

func (s *StorageManager) UpdateScan(id string, updatedRecord ScanRecord) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	dbRecord := fromAppModel(updatedRecord)
	dbRecord.ID = id

	result := s.db.Save(&dbRecord)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("cannot update: scan ID %s not found", id)
	}
	return nil
}

func (s *StorageManager) DeleteScan(id string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	result := s.db.Where("id = ?", id).Delete(&DBScanRecord{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("cannot delete: scan ID %s not found", id)
	}

	return nil
}

func NewScanRecord(target string) ScanRecord {
	return ScanRecord{
		ID:              uuid.New().String(),
		Target:          target,
		StartTime:       time.Now(),
		Status:          "Running",
		SeverityStats:   make(map[string]int),
		Vulnerabilities: []*models.Vulnerability{},
	}
}

// ==========================================
// OFFLINE THREAT INTELLIGENCE & AUTO-SYNC ENGINE
// CISA KEV (Known Exploited Vulnerabilities) Edition
// ==========================================

const (
	// Local path for the Threat Intelligence database
	cveDBFile = "wordlists/cisa-cve.json"

	// Direct connection to the CISA KEV authoritative feed
	cveFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// Threat feed expiration interval. Refreshes payload every 24 hours.
	updateInterval = 24 * time.Hour
)



type CISACatalog struct {
	Vulnerabilities []CISAVulnerability `json:"vulnerabilities"`
}

type CISAVulnerability struct {
	CVEID            string `json:"cveID"`
	Product          string `json:"product"`
	ShortDescription string `json:"shortDescription"`
}

var CVEMemoryDB []models.LocalCVE

func SyncCVEDatabase() {
	fileInfo, err := os.Stat(cveDBFile)

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

	loadDBIntoMemory()
}

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

	CVEMemoryDB = make([]models.LocalCVE, 0, len(cisaData.Vulnerabilities))

	for _, v := range cisaData.Vulnerabilities {
		CVEMemoryDB = append(CVEMemoryDB, models.LocalCVE{
			ID:          v.CVEID,
			Product:     strings.ToLower(v.Product),
			Version:     "Any",
			CVSS:        estimateCVSS(v.ShortDescription),
			Description: v.ShortDescription,
		})
	}

	fmt.Printf("[+] DORM Engine loaded %d CISA Known Exploited Vulnerabilities into RAM.\n", len(CVEMemoryDB))
}

func estimateCVSS(description string) float64 {
	desc := strings.ToLower(description)

	if strings.Contains(desc, "remote code execution") || strings.Contains(desc, "arbitrary code") || strings.Contains(desc, "rce") || strings.Contains(desc, "command injection") || strings.Contains(desc, "os command") {
		return 9.8
	}
	if strings.Contains(desc, "deserialization") || strings.Contains(desc, "untrusted data") {
		return 9.5
	}
	if strings.Contains(desc, "authentication bypass") || strings.Contains(desc, "hard-coded credentials") || strings.Contains(desc, "ssrf") || strings.Contains(desc, "server-side request forgery") {
		return 9.1
	}
	if strings.Contains(desc, "privilege escalation") {
		return 8.8
	}
	if strings.Contains(desc, "buffer overflow") || strings.Contains(desc, "use-after-free") || strings.Contains(desc, "memory corruption") || strings.Contains(desc, "type confusion") || strings.Contains(desc, "integer overflow") {
		return 8.6
	}
	if strings.Contains(desc, "sql injection") || strings.Contains(desc, "sqli") || strings.Contains(desc, "xxe") || strings.Contains(desc, "xml external entity") {
		return 8.5
	}
	if strings.Contains(desc, "path traversal") || strings.Contains(desc, "local file inclusion") || strings.Contains(desc, "directory traversal") {
		return 7.5
	}
	if strings.Contains(desc, "information disclosure") || strings.Contains(desc, "sensitive information") || strings.Contains(desc, "exposure") {
		return 6.5
	}
	if strings.Contains(desc, "cross-site scripting") || strings.Contains(desc, "xss") || strings.Contains(desc, "csrf") || strings.Contains(desc, "cross-site request forgery") {
		return 6.1
	}
	if strings.Contains(desc, "denial of service") || strings.Contains(desc, "dos") || strings.Contains(desc, "out-of-bounds") {
		return 5.5
	}

	return 7.5
}

func SearchLocalCVEs(product, version string) []models.LocalCVE {
	var matches []models.LocalCVE

	targetProd := strings.ToLower(product)

	for _, cve := range CVEMemoryDB {

		if strings.Contains(cve.Product, targetProd) || strings.Contains(targetProd, cve.Product) {

			matches = append(matches, cve)
		}
	}

	return matches
}

// ==========================================
// EXPLOIT-DB INTEGRATION AND SEARCH ENGINE
// ==========================================

type Exploit struct {
	ID          string
	Description string
}

var (
	exploitDatabase []Exploit
	isExploitLoaded bool
	exploitMutex    sync.Mutex
)

func LoadExploitDB() error {
	exploitMutex.Lock()
	defer exploitMutex.Unlock()

	if isExploitLoaded {
		return nil
	}

	fmt.Println("[*] Downloading Exploit-DB database (files_exploits.csv)...")

	url := "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download error: %v", err)
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("CSV reading error: %v", err)
	}

	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) < 3 {
			continue
		}
		exploitDatabase = append(exploitDatabase, Exploit{
			ID:          record[0],
			Description: strings.ToLower(record[2]),
		})
	}

	isExploitLoaded = true
	fmt.Printf("[+] Exploit-DB Ready! %d records loaded into RAM.\n", len(exploitDatabase))
	return nil
}

func SearchExploitDB(query string) []string {
	if !isExploitLoaded {
		LoadExploitDB()
	}

	query = strings.ToLower(query)
	searchTerms := strings.Fields(query)

	var results []string
	count := 0

	for _, item := range exploitDatabase {
		match := true

		for _, term := range searchTerms {
			if !strings.Contains(item.Description, term) {
				match = false
				break
			}
		}

		if match {
			link := fmt.Sprintf("https://www.exploit-db.com/exploits/%s", item.ID)
			results = append(results, fmt.Sprintf("FOUND: %s\n   Link: %s", item.Description, link))

			count++
			if count >= 5 {
				break
			}
		}
	}

	return results
}
