package vectors

import (
	"DORM/models"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Vector is one isolated, independently-schedulable scan container: its own
// (single) target, plugin filter, WAF settings, and either a fixed interval
// or a "continuous" mode (start the next run immediately after the previous
// one finishes). Every Vector's lifecycle (scheduling ticks, run/stop) is
// driven by its own goroutine — only the underlying engine's network-issuing
// phase is serialized process-wide (scanExecMu in scanrunner.go, package
// main) because DORM's plugin surface reads global HTTP-client/shared-data
// singletons that this package never touches directly.
type Vector struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Target          string     `json:"target"`
	PluginFilter    string     `json:"plugin_filter"`
	ScheduleMinutes int        `json:"schedule_minutes"` // 0 = manual/one-shot, ignored when Continuous is true
	Continuous      bool       `json:"continuous"`       // start the next run immediately after this one finishes
	WAFDelayMs      int        `json:"waf_delay_ms"`
	WAFJitterMs     int        `json:"waf_jitter_ms"`
	Status          string     `json:"status"` // Idle | Scheduled | Running
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastRunAt       *time.Time `json:"last_run_at,omitempty"`
	NextRunAt       *time.Time `json:"next_run_at,omitempty"`
}

var (
	mu           sync.Mutex
	vectorsByID  = make(map[string]*Vector)
	cancels      = make(map[string]context.CancelFunc)
	stopSchedule = make(map[string]chan struct{})
)

// Init opens vectors.db, migrates its schema, restores every persisted
// Vector into memory, and restarts scheduler goroutines for any with an
// automatic interval. Call once from main() — after this, Vectors survive
// closing and reopening DORM independently of the classic scan history.
func Init(path string) error {
	if err := initStorage(path); err != nil {
		return err
	}

	list, err := listVectorRows()
	if err != nil {
		return fmt.Errorf("failed to load vectors: %w", err)
	}

	mu.Lock()
	for i := range list {
		v := list[i]
		// No run survives a process restart — reset any stale "Running" status.
		v.Status = idleStatus(v)
		vectorsByID[v.ID] = &v
	}
	mu.Unlock()

	for _, v := range list {
		if v.ScheduleMinutes > 0 && !v.Continuous {
			startScheduleLoop(v.ID)
		}
	}

	fmt.Printf("[Vectors] Loaded %d vector(s) from vectors.db\n", len(list))
	return nil
}

// idleStatus returns the at-rest status a Vector should show when it isn't
// actively running: "Scheduled" if it has an automatic interval or
// continuous mode, else "Idle".
func idleStatus(v Vector) string {
	if v.ScheduleMinutes > 0 || v.Continuous {
		return "Scheduled"
	}
	return "Idle"
}

// List returns a snapshot of every known Vector, newest first.
func List() []Vector {
	mu.Lock()
	defer mu.Unlock()

	out := make([]Vector, 0, len(vectorsByID))
	for _, v := range vectorsByID {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func Get(id string) (*Vector, bool) {
	mu.Lock()
	defer mu.Unlock()
	v, ok := vectorsByID[id]
	if !ok {
		return nil, false
	}
	cp := *v
	return &cp, true
}

// Create persists a new Vector and starts its scheduler goroutine if it has
// a fixed interval (continuous mode re-triggers itself from Run() instead).
func Create(in Vector) (*Vector, error) {
	now := time.Now()
	v := Vector{
		ID:              newID(),
		Name:            strings.TrimSpace(in.Name),
		Target:          strings.TrimSpace(in.Target),
		PluginFilter:    in.PluginFilter,
		ScheduleMinutes: in.ScheduleMinutes,
		Continuous:      in.Continuous,
		WAFDelayMs:      in.WAFDelayMs,
		WAFJitterMs:     in.WAFJitterMs,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if v.Continuous {
		v.ScheduleMinutes = 0
	}
	if v.Name == "" {
		v.Name = v.Target
	}
	v.Status = idleStatus(v)
	if v.ScheduleMinutes > 0 && !v.Continuous {
		next := now.Add(time.Duration(v.ScheduleMinutes) * time.Minute)
		v.NextRunAt = &next
	}

	if err := saveVectorRow(v); err != nil {
		return nil, err
	}

	mu.Lock()
	vectorsByID[v.ID] = &v
	mu.Unlock()

	if v.ScheduleMinutes > 0 && !v.Continuous {
		startScheduleLoop(v.ID)
	}

	cp := v
	return &cp, nil
}

// Update replaces a Vector's configuration in place, restarting its
// scheduler goroutine if the interval or continuous mode changed.
func Update(id string, in Vector) (*Vector, error) {
	mu.Lock()
	existing, ok := vectorsByID[id]
	if !ok {
		mu.Unlock()
		return nil, fmt.Errorf("vector not found: %s", id)
	}

	updated := *existing
	updated.Name = strings.TrimSpace(in.Name)
	updated.Target = strings.TrimSpace(in.Target)
	updated.PluginFilter = in.PluginFilter
	updated.ScheduleMinutes = in.ScheduleMinutes
	updated.Continuous = in.Continuous
	if updated.Continuous {
		updated.ScheduleMinutes = 0
	}
	updated.WAFDelayMs = in.WAFDelayMs
	updated.WAFJitterMs = in.WAFJitterMs
	updated.UpdatedAt = time.Now()
	if updated.Name == "" {
		updated.Name = updated.Target
	}
	scheduleChanged := existing.ScheduleMinutes != updated.ScheduleMinutes || existing.Continuous != updated.Continuous
	if updated.Status != "Running" {
		updated.Status = idleStatus(updated)
	}
	if updated.ScheduleMinutes > 0 && !updated.Continuous {
		next := time.Now().Add(time.Duration(updated.ScheduleMinutes) * time.Minute)
		updated.NextRunAt = &next
	} else {
		updated.NextRunAt = nil
	}

	vectorsByID[id] = &updated
	mu.Unlock()

	if err := updateVectorRow(updated); err != nil {
		return nil, err
	}

	if scheduleChanged {
		stopScheduleLoop(id)
		if updated.ScheduleMinutes > 0 && !updated.Continuous {
			startScheduleLoop(id)
		}
	}

	cp := updated
	return &cp, nil
}

// Delete stops any active run and scheduler loop for a Vector, then removes
// it and its scan history from vectors.db.
func Delete(id string) error {
	_ = Stop(id)
	stopScheduleLoop(id)

	mu.Lock()
	delete(vectorsByID, id)
	delete(broadcasters, id)
	mu.Unlock()

	return deleteVectorRow(id)
}

// Run triggers one scan pass for the given Vector in its own goroutine, with
// its own cancellable context — this is the fix for DORM's pre-existing bug
// where starting any new scan silently cancelled whatever was already
// running. Two Vectors (or a Vector and the classic ad-hoc scan) can now be
// independently active; only the underlying engine's network phase is
// serialized (scanExecMu, package main).
//
// Passive CVE correlation always runs for Vector-triggered scans — there is
// no per-Vector toggle for it.
func Run(id string) error {
	if models.RunScan == nil {
		return fmt.Errorf("scan engine is not wired up")
	}

	mu.Lock()
	v, ok := vectorsByID[id]
	if !ok {
		mu.Unlock()
		return fmt.Errorf("vector not found: %s", id)
	}
	if v.Status == "Running" {
		mu.Unlock()
		return fmt.Errorf("vector already running: %s", id)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancels[id] = cancel

	now := time.Now()
	v.Status = "Running"
	v.LastRunAt = &now
	if v.ScheduleMinutes > 0 && !v.Continuous {
		next := now.Add(time.Duration(v.ScheduleMinutes) * time.Minute)
		v.NextRunAt = &next
	}
	cfg := models.ScanRunConfig{
		Targets:      []string{v.Target},
		PluginFilter: v.PluginFilter,
		WAFDelayMs:   v.WAFDelayMs,
		WAFJitterMs:  v.WAFJitterMs,
		CVERadar:     true, // always on for Vector-triggered scans
	}
	continuous := v.Continuous
	statusSnapshot := *v
	mu.Unlock()

	_ = updateVectorRow(statusSnapshot)

	broadcaster := getBroadcaster(id)
	scanID := newID()

	go func() {
		emit := func(payload string) { broadcaster.Publish(payload) }
		outcome := models.RunScan(ctx, scanID, cfg, emit, func(target string) {
			_ = saveRun(id, scanID, target, time.Now())
		})
		_ = updateRun(scanID, outcome)
		broadcaster.Publish(`{"Status": "DONE"}`)

		mu.Lock()
		delete(cancels, id)
		cur, exists := vectorsByID[id]
		if exists {
			cur.Status = idleStatus(*cur)
			final := *cur
			mu.Unlock()
			_ = updateVectorRow(final)
		} else {
			mu.Unlock()
		}

		// Continuous mode: immediately start the next run, back-to-back,
		// unless the user explicitly stopped this one or the Vector was
		// deleted in the meantime.
		if exists && continuous && outcome.Status != "Stopped" {
			_ = Run(id)
		}
	}()

	return nil
}

// Stop cancels only this Vector's currently active run, if any. For a
// continuous Vector this also stops the back-to-back chain — the run in
// flight finishes as "Stopped" and Run() will not requeue it.
func Stop(id string) error {
	mu.Lock()
	cancel, ok := cancels[id]
	mu.Unlock()
	if !ok {
		return fmt.Errorf("vector is not running: %s", id)
	}
	cancel()
	return nil
}

// History returns a Vector's past scan runs, most recent first.
func History(id string) ([]RunRecord, error) {
	return listRuns(id)
}

// startScheduleLoop launches the (single) goroutine that periodically
// triggers Run() for a Vector with a fixed interval. It skips a tick if the
// Vector is already running. Continuous-mode Vectors don't use this loop at
// all — they re-trigger themselves from inside Run()'s completion handler.
func startScheduleLoop(id string) {
	mu.Lock()
	if _, exists := stopSchedule[id]; exists {
		mu.Unlock()
		return
	}
	v, ok := vectorsByID[id]
	if !ok || v.ScheduleMinutes <= 0 || v.Continuous {
		mu.Unlock()
		return
	}
	interval := time.Duration(v.ScheduleMinutes) * time.Minute
	stop := make(chan struct{})
	stopSchedule[id] = stop
	mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				mu.Lock()
				v, ok := vectorsByID[id]
				busy := ok && v.Status == "Running"
				mu.Unlock()
				if ok && !busy {
					_ = Run(id)
				}
			}
		}
	}()
}

func stopScheduleLoop(id string) {
	mu.Lock()
	stop, ok := stopSchedule[id]
	if ok {
		delete(stopSchedule, id)
	}
	mu.Unlock()
	if ok {
		close(stop)
	}
}
