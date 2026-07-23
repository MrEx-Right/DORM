package dom

import (
	"encoding/json"
	"sync"
	"time"
)

// ==============================================================================
// DOM Event Bus — Canlı Event Yayını
// ==============================================================================
// DOMCrawler her önemli aksiyonunda (navigate, click, xhr, route) bir DOMEvent
// yayınlar. Handlers katmanı bu eventleri SSE üzerinden UI'ya iletir.
// ==============================================================================

// EventKind describes what kind of action the DOM-Crawler is performing.
type EventKind string

const (
	EventNavigate  EventKind = "navigate"  // Tarayıcı bir URL'e gitti
	EventClick     EventKind = "click"     // Bir elemente tıklandı
	EventXHR       EventKind = "xhr"       // Fetch/XHR isteği yakalandı
	EventSPARoute  EventKind = "spa_route" // SPA router route değişimi
	EventFormFound EventKind = "form"      // Bir form bulundu
	EventDone      EventKind = "done"      // Crawl tamamlandı
	EventError     EventKind = "error"     // Hata oluştu
)

// DOMEvent is a single real-time event emitted during DOM crawling.
type DOMEvent struct {
	Kind      EventKind `json:"kind"`
	URL       string    `json:"url,omitempty"`       // hedef URL
	Selector  string    `json:"selector,omitempty"`  // tıklanan element (CSS)
	Label     string    `json:"label,omitempty"`     // element text/label
	Depth     int       `json:"depth"`               // BFS derinliği
	Detail    string    `json:"detail,omitempty"`    // ek bilgi
	Timestamp time.Time `json:"timestamp"`
}

// ToJSON serializes the event to a compact JSON string.
func (e DOMEvent) ToJSON() string {
	b, _ := json.Marshal(e)
	return string(b)
}

// EventBus is a simple pub/sub bus for DOM crawl events.
// Multiple subscribers (SSE connections) can listen concurrently.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string]chan DOMEvent // key = subscriber ID
}

// globalBus is the singleton event bus for the running crawler.
var globalBus = &EventBus{
	subscribers: make(map[string]chan DOMEvent),
}

// GetBus returns the global DOM event bus.
func GetBus() *EventBus {
	return globalBus
}

// Subscribe registers a new listener channel for the given ID.
// Returns a channel that receives DOMEvents until Unsubscribe is called.
func (b *EventBus) Subscribe(id string) <-chan DOMEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan DOMEvent, 64) // buffered to avoid blocking the crawler
	b.subscribers[id] = ch
	return ch
}

// Unsubscribe removes and closes the listener channel for the given ID.
func (b *EventBus) Unsubscribe(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subscribers[id]; ok {
		close(ch)
		delete(b.subscribers, id)
	}
}

// Publish sends an event to all current subscribers (non-blocking).
// If a subscriber's channel is full, the event is dropped for that subscriber.
func (b *EventBus) Publish(ev DOMEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subscribers {
		select {
		case ch <- ev:
		default: // drop if subscriber is not consuming fast enough
		}
	}
}

// emit is a convenience helper used inside DOMCrawler to publish events.
func (c *DOMCrawler) emit(kind EventKind, url, selector, label, detail string, depth int) {
	GetBus().Publish(DOMEvent{
		Kind:      kind,
		URL:       url,
		Selector:  selector,
		Label:     label,
		Depth:     depth,
		Detail:    detail,
		Timestamp: time.Now(),
	})
}
