package templates

// BuilderOptions lists the fixed dropdown values the "Scan Templates"
// builder UI renders — one source of truth shared by the frontend instead
// of hardcoding the same option lists client-side.
type BuilderOptions struct {
	Methods      []string `json:"methods"`
	Severities   []string `json:"severities"`
	MatcherTypes []string `json:"matcherTypes"`
	MatcherParts []string `json:"matcherParts"`
	Conditions   []string `json:"conditions"`
}

func GetBuilderOptions() BuilderOptions {
	return BuilderOptions{
		Methods:      []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
		Severities:   []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
		MatcherTypes: []string{"status_code", "word", "regex"},
		MatcherParts: []string{"body", "header", "status"},
		Conditions:   []string{"OR", "AND"},
	}
}
