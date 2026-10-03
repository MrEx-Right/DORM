package templates

import (
	"encoding/json"
	"time"
)

// ScanTemplate is a user-defined, reusable vulnerability check — DORM's
// UI-built equivalent of a single-request Nuclei YAML template. It is built
// entirely through dropdowns/toggles/textboxes in the "Scan Templates" page,
// never hand-written as a config file.
type ScanTemplate struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Severity    string      `json:"severity"`
	CVSS        float64     `json:"cvss"`
	Description string      `json:"description"`
	Solution    string      `json:"solution"`
	Reference   string      `json:"reference"`
	Request     RequestSpec `json:"request"`
	Matcher     MatcherSpec `json:"matcher"`
	CreatedAt   time.Time   `json:"createdAt"`
	UpdatedAt   time.Time   `json:"updatedAt"`
}

// RequestSpec describes the single HTTP request a template sends. Any
// occurrence of the literal "{{payload}}" in Path, Body or a header value is
// substituted once per entry in Payloads — or left as a single blank-payload
// pass if Payloads is empty.
type RequestSpec struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	Payloads []string          `json:"payloads"`
}

// MatcherSpec is a single matcher group deciding whether a response counts
// as a hit. Values are combined with Condition (AND/OR); Negate flips the
// final result (e.g. "vulnerable if this string is ABSENT").
type MatcherSpec struct {
	Type      string   `json:"type"`      // status_code | word | regex
	Part      string   `json:"part"`      // body | header | status
	Condition string   `json:"condition"` // AND | OR
	Values    []string `json:"values"`
	Negate    bool     `json:"negate"`
}

// templateConfig is the JSON shape stored in DBScanTemplate.Config — every
// template field except the identity/timestamp columns GORM tracks natively.
type templateConfig struct {
	Severity    string      `json:"severity"`
	CVSS        float64     `json:"cvss"`
	Description string      `json:"description"`
	Solution    string      `json:"solution"`
	Reference   string      `json:"reference"`
	Request     RequestSpec `json:"request"`
	Matcher     MatcherSpec `json:"matcher"`
}

// DBScanTemplate is the GORM model backing the templates table inside
// DORM's single shared dorm_engine.db, managed by the existing
// StorageManager (storage.go) — not a separate parallel store.
type DBScanTemplate struct {
	ID        string `gorm:"primaryKey"`
	Name      string `gorm:"uniqueIndex"`
	Config    []byte
	CreatedAt time.Time `gorm:"index"`
	UpdatedAt time.Time
}

func (r *DBScanTemplate) ToAppModel() (ScanTemplate, error) {
	var cfg templateConfig
	if len(r.Config) > 0 {
		if err := json.Unmarshal(r.Config, &cfg); err != nil {
			return ScanTemplate{}, err
		}
	}
	return ScanTemplate{
		ID:          r.ID,
		Name:        r.Name,
		Severity:    cfg.Severity,
		CVSS:        cfg.CVSS,
		Description: cfg.Description,
		Solution:    cfg.Solution,
		Reference:   cfg.Reference,
		Request:     cfg.Request,
		Matcher:     cfg.Matcher,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

func FromAppModel(t ScanTemplate) (DBScanTemplate, error) {
	cfg := templateConfig{
		Severity:    t.Severity,
		CVSS:        t.CVSS,
		Description: t.Description,
		Solution:    t.Solution,
		Reference:   t.Reference,
		Request:     t.Request,
		Matcher:     t.Matcher,
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return DBScanTemplate{}, err
	}
	return DBScanTemplate{
		ID:        t.ID,
		Name:      t.Name,
		Config:    data,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}, nil
}
