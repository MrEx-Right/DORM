package bypassers

// EncodingConfig holds on/off toggles for optional payload-encoding bypass
// techniques (the "WAF Bypass" sidebar). Unlike DelayConfig these are
// opt-in per scan — default is disabled until the UI (or an API caller)
// turns them on.
type EncodingConfig struct {
	NullByteEnabled      bool
	UEPEnabled           bool // Double URL Encoding
	CaseAlternateEnabled bool
	HPPEnabled           bool // HTTP Parameter Pollution
}

// GlobalEncodingConfig holds the active configuration applied from the UI.
var GlobalEncodingConfig EncodingConfig
