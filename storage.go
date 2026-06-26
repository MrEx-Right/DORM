package main

import (
	"DORM/models"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

func (s *StorageManager) DeleteAllScans() error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	return s.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&DBScanRecord{}).Error
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
