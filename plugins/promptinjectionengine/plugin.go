package promptinjectionengine

import "DORM/models"

type PromptInjectionPlugin struct{}

func (p *PromptInjectionPlugin) Name() string { return "AI/LLM Prompt Injection Scanner" }

func (p *PromptInjectionPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	// LoadPayloads is a pure in-memory read (bundled ∪ cached-synced) — it
	// never performs network I/O. Any GitHub sync happens separately, once,
	// in the background at process start (see sync.go / StartBackgroundSync).
	payloads := LoadPayloads()

	if v := RunDirectInjection(client, target, payloads); v != nil {
		return v
	}
	return RunSystemPromptLeakage(client, target, SystemPromptLeakagePayloads)
}
