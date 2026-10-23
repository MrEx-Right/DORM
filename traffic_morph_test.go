package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"DORM/bypassers"
	"DORM/models"
)

func setMorphEnabledForTest(t *testing.T, on bool) {
	t.Helper()
	morph.mu.Lock()
	prev, prevMode := morph.enabled, morph.personaMode
	morph.enabled = on
	morph.mu.Unlock()
	t.Cleanup(func() {
		morph.mu.Lock()
		morph.enabled, morph.personaMode = prev, prevMode
		morph.mu.Unlock()
	})
}

func postMorph(t *testing.T, h http.HandlerFunc, url string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, url, nil))
	return rec
}

func TestMorphStartsOff(t *testing.T) {
	morph.mu.Lock()
	on := morph.enabled
	morph.mu.Unlock()
	if on {
		t.Fatal("Traffic Morph must be off at launch")
	}
	for i := 0; i < 20; i++ {
		if ua := morphUserAgent(); ua != morphPlainUA {
			t.Fatalf("off: got UA %q, want the fixed %q", ua, morphPlainUA)
		}
	}
}

func TestMorphToggleSwitchesUserAgent(t *testing.T) {
	setMorphEnabledForTest(t, false)
	pool := bypassers.UserAgents()

	if rec := postMorph(t, handleIdentityEnabled, "/api/identity/enabled?on=true"); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		ua := morphUserAgent()
		if !slices.Contains(pool, ua) {
			t.Fatalf("on: UA %q is not from the persona pool", ua)
		}
		seen[ua] = true
	}
	if len(seen) < 2 {
		t.Fatalf("on (rotate): only %d distinct UAs in 200 requests", len(seen))
	}

	if rec := postMorph(t, handleIdentityEnabled, "/api/identity/enabled?on=false"); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	if ua := morphUserAgent(); ua != morphPlainUA {
		t.Fatalf("off again: got %q", ua)
	}
	if ua := models.GetScanUserAgent(); ua != morphPlainUA && ua != "" {
		t.Fatalf("headless Chrome / raw probes: got %q", ua)
	}
}

// Sticky persona survives an off/on cycle instead of being re-drawn.
func TestMorphStickyKeptAcrossToggle(t *testing.T) {
	setMorphEnabledForTest(t, true)
	postMorph(t, handleIdentityPersona, "/api/identity/persona?mode=sticky")
	sticky := morphUserAgent()
	postMorph(t, handleIdentityEnabled, "/api/identity/enabled?on=false")
	if ua := morphUserAgent(); ua != morphPlainUA {
		t.Fatalf("off: got %q", ua)
	}
	postMorph(t, handleIdentityEnabled, "/api/identity/enabled?on=true")
	if ua := morphUserAgent(); ua != sticky {
		t.Fatalf("back on: sticky persona changed %q -> %q", sticky, ua)
	}
}

func TestMorphOffRefusesNewIdentity(t *testing.T) {
	setMorphEnabledForTest(t, false)
	morph.mu.Lock()
	gen, token := morph.generation, morph.isolationToken
	morph.mu.Unlock()

	rec := postMorph(t, handleIdentityRotate, "/api/identity/rotate")
	if rec.Code != http.StatusConflict {
		t.Fatalf("NEW IDENTITY while off: got %d, want 409", rec.Code)
	}
	morph.mu.Lock()
	defer morph.mu.Unlock()
	if morph.generation != gen || morph.isolationToken != token {
		t.Fatal("a refused NEW IDENTITY still changed the identity")
	}
}

func TestMorphEnabledRejectsBadInput(t *testing.T) {
	setMorphEnabledForTest(t, false)
	for _, q := range []string{"", "?on=", "?on=yes", "?on=1x"} {
		if rec := postMorph(t, handleIdentityEnabled, "/api/identity/enabled"+q); rec.Code != http.StatusBadRequest {
			t.Errorf("%q: got %d, want 400", q, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	handleIdentityEnabled(rec, httptest.NewRequest(http.MethodGet, "/api/identity/enabled?on=true", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: got %d, want 405", rec.Code)
	}
	if morphUserAgent() != morphPlainUA {
		t.Fatal("a rejected request switched Traffic Morph on")
	}
}

// A User-Agent that is itself a test payload is sent as is, on or off.
func TestMorphKeepsPayloadUserAgent(t *testing.T) {
	var got []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.UserAgent())
	}))
	defer backend.Close()
	rt := &UARoundTripper{Proxied: http.DefaultTransport, Background: true}

	for _, on := range []bool{false, true} {
		setMorphEnabledForTest(t, on)
		req, _ := http.NewRequest(http.MethodGet, backend.URL, nil)
		req.Header.Set("User-Agent", "' OR 1=1--")
		resp, err := rt.RoundTrip(models.KeepUserAgent(req))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if len(got) != 2 || got[0] != "' OR 1=1--" || got[1] != "' OR 1=1--" {
		t.Fatalf("payload UA not kept: %q", got)
	}
}

func TestMorphIdentityReportsState(t *testing.T) {
	for _, on := range []bool{false, true} {
		setMorphEnabledForTest(t, on)
		rec := httptest.NewRecorder()
		handleIdentity(rec, httptest.NewRequest(http.MethodGet, "/api/identity", nil))
		var d struct {
			Enabled     bool `json:"enabled"`
			Persona     struct{ Current, CurrentLabel string }
			Consistency struct{ Verdict string }
		}
		if err := json.NewDecoder(rec.Body).Decode(&d); err != nil {
			t.Fatal(err)
		}
		if d.Enabled != on {
			t.Fatalf("enabled=%v reported as %v", on, d.Enabled)
		}
		if !on && (d.Persona.Current != morphPlainUA || d.Consistency.Verdict != "OFF") {
			t.Fatalf("off: persona %q verdict %q", d.Persona.Current, d.Consistency.Verdict)
		}
		if on && d.Consistency.Verdict == "OFF" {
			t.Fatal("on: verdict still OFF")
		}
	}
}
