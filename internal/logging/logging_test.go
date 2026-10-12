package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateFormat(t *testing.T) {
	for _, ok := range []string{"", FormatConsole, FormatJSON} {
		if err := ValidateFormat(ok); err != nil {
			t.Errorf("ValidateFormat(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"JSON", "text", "logfmt", " json"} {
		if err := ValidateFormat(bad); err == nil {
			t.Errorf("ValidateFormat(%q) = nil, want an error", bad)
		}
	}
}

// TestNewJSONEmitsOneObjectPerLine checks that the json format writes plain
// zerolog JSON (one object per line, standard field names), which is what
// scripts/topology/rtt_tor_check.py parses from `journalctl -o cat`.
func TestNewJSONEmitsOneObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(FormatJSON, &buf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info().Str("source_gid", "fe80::1").Uint64("t2", 42).Msg("first")
	logger.Warn().Msg("second")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("line 0 is not JSON: %v (%q)", err, lines[0])
	}
	for key, want := range map[string]any{
		"level": "info", "message": "first", "source_gid": "fe80::1", "t2": float64(42),
	} {
		if rec[key] != want {
			t.Errorf("rec[%q] = %v, want %v", key, rec[key], want)
		}
	}
	if _, ok := rec["time"]; !ok {
		t.Error("JSON record has no time field")
	}
}

func TestNewConsoleIsNotJSON(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(FormatConsole, &buf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info().Msg("hello")
	if json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Errorf("console output unexpectedly valid JSON: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("console output %q lacks the message", buf.String())
	}
}

func TestNewRejectsInvalidFormat(t *testing.T) {
	if _, err := New("xml", &bytes.Buffer{}); err == nil {
		t.Fatal("New(xml) = nil error, want an error")
	}
}
