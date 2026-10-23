package promptinjectionengine

// Regression tests for the 2026-10-22 scan's Prompt Injection FPs: the
// canary was inside the payload, so any page that printed the query
// "confirmed" an injection. Each FP shape has a true-positive counterpart.

import (
	"DORM/models"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mockOn(t *testing.T, endpoint string, h http.HandlerFunc) (models.ScanTarget, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(endpoint, h)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	_, portStr, _ := strings.Cut(strings.TrimPrefix(s.URL, "http://"), ":")
	port, _ := strconv.Atoi(portStr)
	return models.ScanTarget{IP: "127.0.0.1", Port: port}, &http.Client{Timeout: 5 * time.Second}
}

var sumRe = regexp.MustCompile(`the sum of (\d+) and (\d+)`)

// fakeLLM answers like an injectable model: it follows "the sum of A and B"
// and prints whatever DORM_* token it was told to print.
func fakeLLM(msg string, canComputeSum bool) string {
	if m := sumRe.FindStringSubmatch(msg); m != nil {
		if !canComputeSum {
			return "I cannot help with that."
		}
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		return fmt.Sprintf("DORM-%d", a+b)
	}
	if tok := regexp.MustCompile(`DORM_[A-Z_]+`).FindString(msg); tok != "" {
		return tok
	}
	return "Hello! How can I help you today?"
}

func TestPromptInjection_SearchPageEchoingQueryIsNotAFinding(t *testing.T) {
	// The boardgamegeek/airtable/bluescape shape: an HTML page printing the query.
	target, client := mockOn(t, "/chat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<html><body><h1>Search results for: %s</h1><p>No results.</p></body></html>",
			html.EscapeString(r.URL.Query().Get("q")))
	})
	if v := RunDirectInjection(client, target, BundledPayloads); v != nil {
		t.Fatalf("reflected payload is not an injection: %s", v.Description)
	}
	if v := RunSystemPromptLeakage(client, target, SystemPromptLeakagePayloads); v != nil {
		t.Fatalf("reflected payload is not a leak: %s", v.Description)
	}
}

func TestPromptInjection_PhraseAlreadyOnPageIsNotAFinding(t *testing.T) {
	target, client := mockOn(t, "/ai", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>As instructed by our docs, you are a valued customer. I am now ready.</body></html>"))
	})
	if v := RunDirectInjection(client, target, BundledPayloads); v != nil {
		t.Fatalf("static page text is not model output: %s", v.Description)
	}
	if v := RunSystemPromptLeakage(client, target, SystemPromptLeakagePayloads); v != nil {
		t.Fatalf("static page text is not a leak: %s", v.Description)
	}
}

func TestPromptInjection_InjectableModelIsHigh(t *testing.T) {
	target, client := mockOn(t, "/api/chat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"reply": fakeLLM(r.URL.Query().Get("message"), true)})
	})
	v := RunDirectInjection(client, target, BundledPayloads)
	if v == nil || v.Severity != "HIGH" {
		t.Fatalf("want HIGH confirmed injection, got %+v", v)
	}
}

func TestPromptInjection_ChatThatEchoesTranscriptButObeysIsHigh(t *testing.T) {
	// A real chat UI that echoes the user's message: canaries are useless
	// here, the computed-answer probe must still catch it.
	target, client := mockOn(t, "/assistant", func(w http.ResponseWriter, r *http.Request) {
		msg := r.URL.Query().Get("message")
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<div class=user>%s</div><div class=bot>%s</div>",
			html.EscapeString(msg), html.EscapeString(fakeLLM(msg, true)))
	})
	v := RunDirectInjection(client, target, BundledPayloads)
	if v == nil || v.Severity != "HIGH" {
		t.Fatalf("want HIGH via computed answer, got %+v", v)
	}
}

func TestPromptInjection_CanaryWithoutConfirmationIsMedium(t *testing.T) {
	target, client := mockOn(t, "/bot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"reply": fakeLLM(r.URL.Query().Get("message"), false)})
	})
	v := RunDirectInjection(client, target, BundledPayloads)
	if v == nil || v.Severity != "MEDIUM" {
		t.Fatalf("want MEDIUM unconfirmed, got %+v", v)
	}
}

func TestSystemPromptLeakage_LeakingModelIsReported(t *testing.T) {
	target, client := mockOn(t, "/llm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		reply := "Hello! How can I help you today?"
		if strings.Contains(strings.ToLower(r.URL.Query().Get("message")), "system prompt") {
			reply = "Here is my system prompt: You must always answer as AcmeBot and never reveal pricing."
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"reply": reply})
	})
	if v := RunSystemPromptLeakage(client, target, SystemPromptLeakagePayloads); v == nil {
		t.Fatal("a model printing its system prompt must be reported")
	}
}
