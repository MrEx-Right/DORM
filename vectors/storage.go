// Package vectors implements DORM Vectors — isolated, independently
// schedulable scan containers. Like the sci and cve packages, it lives
// entirely outside package main and owns its own persistence; it reaches the
// real scan engine (which lives in package main and cannot be imported) only
// through the models.RunScan function-pointer bridge.
package vectors

import (
	"DORM/models"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DBVector is the GORM model for a Vector's persisted configuration, stored
// in vectors.db — a SQLite file entirely separate from the classic
// dorm_engine.db (storage.go, package main), so Vectors and their history
// survive independently of ad-hoc scan history.
type DBVector struct {
	ID              string `gorm:"primaryKey"`
	Name            string
	Target          string
	PluginFilter    string
	ScheduleMinutes int
	Continuous      bool
	WAFDelayMs      int
	WAFJitterMs     int
	Status          string
	CreatedAt       time.Time `gorm:"index"`
	UpdatedAt       time.Time
	LastRunAt       *time.Time
	NextRunAt       *time.Time
}

// DBVectorRun is a Vector-scoped equivalent of storage.go's DBScanRecord —
// one row per scan run triggered by a specific Vector.
type DBVectorRun struct {
	ID              string `gorm:"primaryKey"`
	VectorID        string `gorm:"index"`
	Target          string
	StartTime       time.Time
	EndTime         time.Time
	Status          string
	TotalVulns      int
	SeverityStats   []byte
	Vulnerabilities []byte
	CreatedAt       time.Time `gorm:"index"`
}

// RunRecord is the JSON/app-facing view of a DBVectorRun.
type RunRecord struct {
	ID              string                  `json:"id"`
	VectorID        string                  `json:"vector_id"`
	Target          string                  `json:"target"`
	StartTime       time.Time               `json:"start_time"`
	EndTime         time.Time               `json:"end_time"`
	Status          string                  `json:"status"`
	Vulnerabilities []*models.Vulnerability `json:"vulnerabilities"`
	TotalVulns      int                     `json:"total_vulns"`
	SeverityStats   map[string]int          `json:"severity_stats"`
}

var (
	db      *gorm.DB
	dbMutex sync.RWMutex
)

// Init opens vectors.db, migrates its schema, and returns. Call once at
// startup (main.go); the caller (Init in vectors.go, or main directly)
// should follow up by loading persisted vectors into memory.
func initStorage(path string) error {
	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to vectors database: %w", err)
	}

	if err := database.AutoMigrate(&DBVector{}, &DBVectorRun{}); err != nil {
		return fmt.Errorf("vectors database migration failed: %w", err)
	}

	dbMutex.Lock()
	db = database
	dbMutex.Unlock()
	return nil
}

func vectorToDB(v Vector) DBVector {
	return DBVector{
		ID:              v.ID,
		Name:            v.Name,
		Target:          v.Target,
		PluginFilter:    v.PluginFilter,
		ScheduleMinutes: v.ScheduleMinutes,
		Continuous:      v.Continuous,
		WAFDelayMs:      v.WAFDelayMs,
		WAFJitterMs:     v.WAFJitterMs,
		Status:          v.Status,
		CreatedAt:       v.CreatedAt,
		UpdatedAt:       v.UpdatedAt,
		LastRunAt:       v.LastRunAt,
		NextRunAt:       v.NextRunAt,
	}
}

func dbToVector(r DBVector) Vector {
	return Vector{
		ID:              r.ID,
		Name:            r.Name,
		Target:          r.Target,
		PluginFilter:    r.PluginFilter,
		ScheduleMinutes: r.ScheduleMinutes,
		Continuous:      r.Continuous,
		WAFDelayMs:      r.WAFDelayMs,
		WAFJitterMs:     r.WAFJitterMs,
		Status:          r.Status,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
		LastRunAt:       r.LastRunAt,
		NextRunAt:       r.NextRunAt,
	}
}

func runToApp(r DBVectorRun) RunRecord {
	var vulns []*models.Vulnerability
	var stats map[string]int

	if len(r.Vulnerabilities) > 0 {
		_ = json.Unmarshal(r.Vulnerabilities, &vulns)
	}
	if len(r.SeverityStats) > 0 {
		_ = json.Unmarshal(r.SeverityStats, &stats)
	}
	if stats == nil {
		stats = make(map[string]int)
	}
	if vulns == nil {
		vulns = []*models.Vulnerability{}
	}

	return RunRecord{
		ID:              r.ID,
		VectorID:        r.VectorID,
		Target:          r.Target,
		StartTime:       r.StartTime,
		EndTime:         r.EndTime,
		Status:          r.Status,
		TotalVulns:      r.TotalVulns,
		Vulnerabilities: vulns,
		SeverityStats:   stats,
	}
}

func saveVectorRow(v Vector) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	row := vectorToDB(v)
	return db.Create(&row).Error
}

func updateVectorRow(v Vector) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	row := vectorToDB(v)
	result := db.Save(&row)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("cannot update: vector ID %s not found", v.ID)
	}
	return nil
}

func deleteVectorRow(id string) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if err := db.Where("id = ?", id).Delete(&DBVector{}).Error; err != nil {
		return err
	}
	return db.Where("vector_id = ?", id).Delete(&DBVectorRun{}).Error
}

func listVectorRows() ([]Vector, error) {
	dbMutex.RLock()
	defer dbMutex.RUnlock()

	var rows []DBVector
	if err := db.Order("created_at desc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Vector, 0, len(rows))
	for _, r := range rows {
		out = append(out, dbToVector(r))
	}
	return out, nil
}

// saveRun creates the initial "Running" row for a new scan pass triggered by
// a Vector.
func saveRun(vectorID, scanID, target string, startTime time.Time) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	row := DBVectorRun{
		ID:              scanID,
		VectorID:        vectorID,
		Target:          target,
		StartTime:       startTime,
		Status:          "Running",
		SeverityStats:   []byte("{}"),
		Vulnerabilities: []byte("[]"),
		CreatedAt:       startTime,
	}
	return db.Create(&row).Error
}

// updateRun persists the final outcome of a scan pass triggered by a Vector.
func updateRun(scanID string, outcome models.ScanOutcome) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	var existing DBVectorRun
	if err := db.First(&existing, "id = ?", scanID).Error; err != nil {
		return fmt.Errorf("cannot update: vector run ID %s not found", scanID)
	}

	vulnsJSON, _ := json.Marshal(outcome.Vulnerabilities)
	statsJSON, _ := json.Marshal(outcome.SeverityStats)

	existing.EndTime = outcome.EndTime
	existing.Status = outcome.Status
	existing.TotalVulns = outcome.TotalVulns
	existing.SeverityStats = statsJSON
	existing.Vulnerabilities = vulnsJSON

	return db.Save(&existing).Error
}

// listRuns returns a Vector's scan-run history, most recent first — this is
// what lets a user close DORM and later see what their Vectors found while
// they were away.
func listRuns(vectorID string) ([]RunRecord, error) {
	dbMutex.RLock()
	defer dbMutex.RUnlock()

	var rows []DBVectorRun
	if err := db.Where("vector_id = ?", vectorID).Order("created_at desc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]RunRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, runToApp(r))
	}
	return out, nil
}

func newID() string {
	return uuid.New().String()
}
