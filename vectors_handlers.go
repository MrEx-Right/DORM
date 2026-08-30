package main

import (
	"DORM/vectors"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// ==========================================
// DORM VECTORS — HTTP API
// ==========================================
// Same thin-handler-delegates-to-package style already used by handleSCI
// (sci.AnalyzeTarget) and handleSiteMap (sitemapper.GetSiteMap): all Vector
// domain logic lives in DORM/vectors, these handlers only do HTTP plumbing.
// Follows the flat, query-param-driven route convention already used by the
// history API (/api/history/delete, /api/history/delete_all).

type vectorRequest struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Target          string `json:"target"`
	PluginFilter    string `json:"plugin_filter"`
	ScheduleMinutes int    `json:"schedule_minutes"`
	Continuous      bool   `json:"continuous"`
	WAFDelayMs      int    `json:"waf_delay_ms"`
	WAFJitterMs     int    `json:"waf_jitter_ms"`
}

func (req vectorRequest) toVector() vectors.Vector {
	return vectors.Vector{
		Name:            strings.TrimSpace(req.Name),
		Target:          strings.TrimSpace(req.Target),
		PluginFilter:    req.PluginFilter,
		ScheduleMinutes: req.ScheduleMinutes,
		Continuous:      req.Continuous,
		WAFDelayMs:      req.WAFDelayMs,
		WAFJitterMs:     req.WAFJitterMs,
	}
}

// GET /api/vectors — list every Vector.
func handleVectorsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(vectors.List())
}

// POST /api/vectors/create — create a new Vector.
func handleVectorCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req vectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		http.Error(w, `{"error":"A target is required"}`, http.StatusBadRequest)
		return
	}

	v, err := vectors.Create(req.toVector())
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// POST /api/vectors/update — update an existing Vector's configuration.
func handleVectorUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req vectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, `{"error":"Missing 'id'"}`, http.StatusBadRequest)
		return
	}

	v, err := vectors.Update(req.ID, req.toVector())
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// POST /api/vectors/delete?id=... — delete a Vector and its scan history.
func handleVectorDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"Missing 'id' parameter"}`, http.StatusBadRequest)
		return
	}

	if err := vectors.Delete(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(`{"status":"success"}`))
}

// POST /api/vectors/run?id=... — trigger an immediate run for one Vector.
func handleVectorRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"Missing 'id' parameter"}`, http.StatusBadRequest)
		return
	}

	if err := vectors.Run(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
		return
	}
	_, _ = w.Write([]byte(`{"status":"started"}`))
}

// POST /api/vectors/stop?id=... — cancel this Vector's active run only.
func handleVectorStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"Missing 'id' parameter"}`, http.StatusBadRequest)
		return
	}

	if err := vectors.Stop(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
		return
	}
	_, _ = w.Write([]byte(`{"status":"stopped"}`))
}

// GET /api/vectors/history?id=... — a Vector's past scan runs, most recent first.
func handleVectorHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"Missing 'id' parameter"}`, http.StatusBadRequest)
		return
	}

	records, err := vectors.History(id)
	if err != nil {
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	if records == nil {
		records = []vectors.RunRecord{}
	}
	_ = json.NewEncoder(w).Encode(records)
}

// GET /api/vectors/events?id=... — live SSE feed of one Vector's current (or
// most recently started) run. Mirrors handleDOMEvents' flush/heartbeat loop
// (handlers.go) and the classic /scan SSE payload shape, so the frontend can
// reuse the same event-handling code.
func handleVectorEvents(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"Missing 'id' parameter"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	events := vectors.Subscribe(id)
	defer vectors.Unsubscribe(id, events)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case payload, ok := <-events:
			if !ok {
				return
			}
			_, _ = w.Write([]byte("data: " + payload + "\n\n"))
			flusher.Flush()
		case <-ticker.C:
			_, _ = w.Write([]byte(": heartbeat\n\n"))
			flusher.Flush()
		}
	}
}
