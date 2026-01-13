package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid" //go get github.com/google/uuid
)

// ScanRecord represents a single execution of the scanner.
// It stores metadata, status, and the list of findings.
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

// StorageManager handles thread-safe I/O operations for the scan history.
// It uses a simple JSON flat-file database mechanism.
type StorageManager struct {
	FilePath string
	Mutex    sync.RWMutex
}

// DB is the global singleton instance of the StorageManager.
var DB *StorageManager

// InitDB initializes the storage engine and ensures the persistence file exists.
func InitDB(path string) {
	DB = &StorageManager{
		FilePath: path,
	}
	// Check if the file exists; if not, create an empty JSON array.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		DB.SaveAll([]ScanRecord{})
	}
}

// GetAll retrieves all scan records from the local storage.
// It uses a read-lock to ensure concurrent safety.
func (s *StorageManager) GetAll() ([]ScanRecord, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	file, err := os.ReadFile(s.FilePath)
	if err != nil {
		return nil, err
	}

	var records []ScanRecord
	if len(file) == 0 {
		return []ScanRecord{}, nil
	}

	err = json.Unmarshal(file, &records)
	return records, err
}

// GetByID retrieves a specific scan record by its unique ID.
func (s *StorageManager) GetByID(id string) (*ScanRecord, error) {
	records, err := s.GetAll()
	if err != nil {
		return nil, err
	}

	for _, r := range records {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("scan record not found for ID: %s", id)
}

// SaveScan creates a new scan record and persists it to storage.
// Newest scans are prepended to the list.
func (s *StorageManager) SaveScan(record ScanRecord) error {
	records, _ := s.GetAll()

	// Prepend the new record so the history shows the latest first.
	records = append([]ScanRecord{record}, records...)

	return s.SaveAll(records)
}

// UpdateScan modifies an existing scan record (e.g., adding vulnerabilities or changing status).
func (s *StorageManager) UpdateScan(id string, updatedRecord ScanRecord) error {
	records, _ := s.GetAll()

	found := false
	for i, r := range records {
		if r.ID == id {
			records[i] = updatedRecord
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("cannot update: scan ID %s not found", id)
	}

	return s.SaveAll(records)
}

// DeleteScan removes a scan record permanently from storage.
func (s *StorageManager) DeleteScan(id string) error {
	records, _ := s.GetAll()

	var newRecords []ScanRecord
	found := false
	for _, r := range records {
		if r.ID != id {
			newRecords = append(newRecords, r)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("cannot delete: scan ID %s not found", id)
	}

	return s.SaveAll(newRecords)
}

// SaveAll writes the entire slice of records to the JSON file.
// It uses a write-lock to prevent data corruption during concurrent writes.
func (s *StorageManager) SaveAll(records []ScanRecord) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.FilePath, data, 0644)
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
