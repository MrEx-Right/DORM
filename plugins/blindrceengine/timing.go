package blindrceengine

import (
	"DORM/models"
	"net/http"
	"time"
)

// MeasureBaseline samples 3 clean GETs against endpoint and returns their
// average RTT, used to tell a genuine sleep-induced delay apart from normal
// network/server jitter.
func MeasureBaseline(target models.ScanTarget, endpoint string) time.Duration {
	client := models.GetClient()
	u := models.GetURL(target, endpoint)
	var total time.Duration
	samples := 0
	for i := 0; i < 3; i++ {
		start := time.Now()
		resp, err := client.Get(u)
		elapsed := time.Since(start)
		if err == nil {
			_ = resp.Body.Close()
			total += elapsed
			samples++
		}
	}
	if samples == 0 {
		return 500 * time.Millisecond // fallback
	}
	return total / time.Duration(samples)
}

// TimingResult carries the outcome of a dual-timing (sleep-2 → sleep-7)
// confirmation probe against a single injection point.
type TimingResult struct {
	Confirmed bool
	T1        time.Duration
	T2        time.Duration
	Ratio     float64
}

// ConfirmTiming implements the adaptive delta analysis shared by every
// fuzzing phase: fire the small (sleep-2) probe first, and only if its RTT
// clears the baseline-adjusted threshold, fire the large (sleep-7) probe and
// check proportionality (ratio ~3.5 = 7/2, within a tolerance band). small
// and large are supplied by the caller so the same logic serves GET, spider
// GET, and POST call sites without duplicating the ratio-check three times.
func ConfirmTiming(baseline time.Duration, small, large func() (*http.Response, error)) TimingResult {
	start := time.Now()
	resp, err := small()
	t1 := time.Since(start)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}

	minDelta := 2*time.Second - (baseline / 2)
	if t1 < minDelta {
		return TimingResult{T1: t1} // baseline noise — not interesting
	}

	start2 := time.Now()
	resp2, err2 := large()
	t2 := time.Since(start2)
	if err2 == nil && resp2 != nil {
		_ = resp2.Body.Close()
	}

	ratio := float64(t2) / float64(t1)
	return TimingResult{
		Confirmed: ratio >= 2.5 && ratio <= 5.5,
		T1:        t1,
		T2:        t2,
		Ratio:     ratio,
	}
}
