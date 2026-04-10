package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

type RaceConditionPlugin struct{}

func (p *RaceConditionPlugin) Name() string { return "Race Condition (State Mutation)" }

func (p *RaceConditionPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	commonEndpoints := []string{
		"/api/vote",
		"/api/coupon/apply",
		"/api/transfer",
		"/api/order",
		"/register",
		"/login",
		"/cart/add",
		"/",
	}

	concurrencyLevel := 15
	client := models.GetClient()

	for _, endpoint := range commonEndpoints {
		targetURL := getURL(target, endpoint)

		probeReq, _ := http.NewRequest("POST", targetURL, strings.NewReader("{}"))
		probeReq.Header.Set("Content-Type", "application/json")
		probeResp, err := client.Do(probeReq)

		if err != nil {
			continue
		}
		probeResp.Body.Close()

		if probeResp.StatusCode == 404 || probeResp.StatusCode == 405 {
			continue
		}

		// 3. Prepare the Attack (The Gate Pattern)
		var wg sync.WaitGroup
		startGate := make(chan struct{})

		statusCodes := make([]int, concurrencyLevel)
		bodyLengths := make([]int64, concurrencyLevel)

		for i := 0; i < concurrencyLevel; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				req, _ := http.NewRequest("POST", targetURL, strings.NewReader(`{"id": 1, "action": "test", "amount": 1}`))
				req.Header.Set("User-Agent", "DORM-Race-Tester/2.0")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Cache-Control", "no-cache")

				<-startGate

				resp, err := client.Do(req)
				if err == nil {
					defer resp.Body.Close()
					statusCodes[index] = resp.StatusCode

					body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
					bodyLengths[index] = int64(len(body))
				}
			}(i)
		}

		close(startGate)
		wg.Wait()

		successCount := 0
		blockCount := 0
		serverErrCount := 0

		uniqueLengths := make(map[int64]int)

		for i, code := range statusCodes {
			if code == 0 {
				continue
			}

			if code >= 200 && code < 300 {
				successCount++
				uniqueLengths[bodyLengths[i]]++
			} else if code == 409 || code == 429 {
				blockCount++
			} else if code >= 500 {
				serverErrCount++
			}
		}

		if serverErrCount > concurrencyLevel/2 {
			continue
		}

		if successCount > 0 && blockCount > 0 {
			continue
		}

		isInteresting := false

		if successCount > 1 && len(uniqueLengths) > 1 {
			isInteresting = true
		}

		if isInteresting {
			return &models.Vulnerability{
				Target:      target,
				Name:        "Race Condition / State Inconsistency",
				Severity:    "HIGH",
				CVSS:        7.5,
				Description: fmt.Sprintf("The endpoint %s exhibited inconsistent behavior under high concurrency.\nSuccessful Requests (2xx): %d\nUnique Response Lengths: %d\nThis suggests that parallel requests are affecting the application state unpredictably.", endpoint, successCount, len(uniqueLengths)),
				Solution:    "Implement database row-level locking or atomic transactions.",
				Reference:   "CWE-362: Race Condition",
			}
		}
	}

	return nil
}
