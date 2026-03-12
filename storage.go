package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ScanRecord represents a single execution of the scanner.

type ScanRecord struct {
	ID              string           `json:"id"`
	Target          string           `json:"target"`
	StartTime       time.Time        `json:"start_time"`
	EndTime         time.Time        `json:"end_time"`
	Status          string           `json:"status"` // e.g., "Running", "Completed", "Stopped"
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	TotalVulns      int              `json:"total_vulns"`
	SeverityStats   map[string]int   `json:"severity_stats"` // e.g., {"CRITICAL": 2, "HIGH": 5}
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
	var vulns []*Vulnerability
	var stats map[string]int

	if len(r.Vulnerabilities) > 0 {
		json.Unmarshal(r.Vulnerabilities, &vulns)
	}
	if len(r.SeverityStats) > 0 {
		json.Unmarshal(r.SeverityStats, &stats)
	}

	// Null pointer hatası almamak için boş initialize ediyoruz
	if stats == nil {
		stats = make(map[string]int)
	}
	if vulns == nil {
		vulns = []*Vulnerability{}
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

// GetAll retrieves all scan records from the local storage.
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

// GetByID retrieves a specific scan record by its unique ID.
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

// SaveScan creates a new scan record and persists it to storage.
func (s *StorageManager) SaveScan(record ScanRecord) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	dbRecord := fromAppModel(record)
	return s.db.Create(&dbRecord).Error
}

// UpdateScan modifies an existing scan record.
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

// DeleteScan removes a scan record permanently from storage.
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

// NewScanRecord is a factory function to initialize a standard ScanRecord object.
func NewScanRecord(target string) ScanRecord {
	return ScanRecord{
		ID:              uuid.New().String(),
		Target:          target,
		StartTime:       time.Now(),
		Status:          "Running",
		SeverityStats:   make(map[string]int),
		Vulnerabilities: []*Vulnerability{},
	}
}
