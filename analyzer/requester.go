package analyzer

import (
	"fmt"
	"net/http"
)

// AnalyzeRequest parses and logs or manipulates outgoing requests
func AnalyzeRequest(req *http.Request) {
	// For now, we just passively log or inspect the request.
	// In the future, this can inject active payloads before they hit the target.
	
	// Example: check if the request contains sensitive info in URL
	if req.URL != nil {
		query := req.URL.Query()
		if query.Has("password") || query.Has("token") {
			fmt.Printf("[Analyzer] [WARNING] Outgoing request contains sensitive parameters in URL: %s\n", req.URL.String())
		}
	}
}
