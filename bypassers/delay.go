package bypassers

import (
	"math/rand"
	"time"
)

// DelayConfig holds the settings for request throttling.
type DelayConfig struct {
	BaseDelayMs int
	JitterMs    int // Maximum random variance added to base delay
}

// GlobalDelayConfig holds the active configuration applied from the UI.
var GlobalDelayConfig = DelayConfig{
	BaseDelayMs: 0,
	JitterMs:    0,
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Sleep executes a pause based on the GlobalDelayConfig.
// It applies a base delay plus a random jitter to simulate human/random traffic.
func Sleep() {
	if GlobalDelayConfig.BaseDelayMs <= 0 {
		return
	}

	delay := GlobalDelayConfig.BaseDelayMs
	if GlobalDelayConfig.JitterMs > 0 {
		// Random value between 0 and JitterMs
		jitter := rand.Intn(GlobalDelayConfig.JitterMs + 1)
		
		// Randomly add or subtract the jitter (while ensuring we don't go below 0)
		if rand.Intn(2) == 0 {
			delay += jitter
		} else {
			delay -= jitter
			if delay < 0 {
				delay = 0
			}
		}
	}

	time.Sleep(time.Duration(delay) * time.Millisecond)
}
