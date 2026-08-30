package vectors

import "sync"

// Broadcaster fans one Vector's scan events out to any number of live SSE
// subscribers (e.g. multiple browser tabs watching the same Vector) — the
// same publish/subscribe idiom as dom.GetBus() (dom/eventbus.go), scoped
// per-Vector instead of process-wide.
type Broadcaster struct {
	mu   sync.Mutex
	subs map[chan string]struct{}
}

func newBroadcaster() *Broadcaster {
	return &Broadcaster{subs: make(map[chan string]struct{})}
}

func (b *Broadcaster) Publish(payload string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- payload:
		default: // a slow/stalled subscriber never blocks the scan itself
		}
	}
}

func (b *Broadcaster) subscribe() chan string {
	ch := make(chan string, 32)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Broadcaster) unsubscribe(ch chan string) {
	b.mu.Lock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
		close(ch)
	}
	b.mu.Unlock()
}

var broadcasters = make(map[string]*Broadcaster)

func getBroadcaster(vectorID string) *Broadcaster {
	mu.Lock()
	defer mu.Unlock()
	b, ok := broadcasters[vectorID]
	if !ok {
		b = newBroadcaster()
		broadcasters[vectorID] = b
	}
	return b
}

// Subscribe registers a new live-event listener for a Vector's scan runs.
// Call Unsubscribe with the same channel when the SSE client disconnects.
func Subscribe(vectorID string) chan string {
	return getBroadcaster(vectorID).subscribe()
}

// Unsubscribe removes a listener previously returned by Subscribe.
func Unsubscribe(vectorID string, ch chan string) {
	getBroadcaster(vectorID).unsubscribe(ch)
}
