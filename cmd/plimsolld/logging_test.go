package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/printable"
)

func envOf(v string) func(string) string {
	return func(key string) string {
		if key == "PLIMSOLL_LOG_FORMAT" {
			return v
		}
		return ""
	}
}

// The audit stream has consumers — prospector-report and internal/report.Parse —
// that read newline-delimited JSON. A default no tool can parse would make the
// metadata-only record useless in exactly the situation it exists for, which is
// what shipped until this was fixed.
func TestAuditStreamDefaultsToParseableJSON(t *testing.T) {
	var buf bytes.Buffer
	slog.New(newLogHandler(envOf(""), &buf)).Info("code run", "trace_id", "9af31c02", "isolation", "process")

	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
		t.Fatalf("default audit line is not JSON: %v\nline: %s", err, buf.String())
	}
	if line["msg"] != "code run" || line["trace_id"] != "9af31c02" {
		t.Errorf("audit line lost its fields: %v", line)
	}
}

func TestTextFormatIsOptInAndTolerant(t *testing.T) {
	for _, v := range []string{"text", "TEXT", " text "} {
		var buf bytes.Buffer
		slog.New(newLogHandler(envOf(v), &buf)).Info("code run", "trace_id", "9af31c02")
		if got := buf.String(); !strings.Contains(got, "trace_id=9af31c02") {
			t.Errorf("PLIMSOLL_LOG_FORMAT=%q did not select the text handler: %s", v, got)
		}
	}
}

// An unrecognized value must fall to the parseable default rather than to text,
// so a typo cannot silently break the audit consumers.
func TestUnknownLogFormatFallsToJSON(t *testing.T) {
	var buf bytes.Buffer
	slog.New(newLogHandler(envOf("jsonl"), &buf)).Info("code run")
	if !json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Errorf("unknown format did not fall back to JSON: %s", buf.String())
	}
}

// F8 of the security scan of 2026-11-20, in the daemon's own lines: a value from outside
// (a file's name, a provider's error text) reaches the log stream with its control and
// bidirectional characters escaped, in both formats. JSON escaped the C0 range already
// and the text format quoted it, but neither escaped DEL, C1 or the bidirectional
// controls. The line still parses, and an ordinary value is as it was.
func TestLogLinesEscapeOutsideText(t *testing.T) {
	hostile := "a\x1b[2K\rforged\u202e\u009b\x7f"
	for _, format := range []string{"", "text"} {
		var buf bytes.Buffer
		slog.New(newLogHandler(envOf(format), &buf)).Error("cannot load", "path", hostile, "error", errors.New(hostile), "names", []string{hostile}, "trace_id", "9af31c02")
		line := strings.TrimSuffix(buf.String(), "\n")
		if strings.ContainsFunc(line, printable.Escaped) {
			t.Errorf("format %q: a raw control or format character in %q", format, line)
		}
		if format == "text" {
			if !strings.Contains(line, "path="+printable.Text(hostile)) || !strings.Contains(line, "trace_id=9af31c02") {
				t.Errorf("text line %q", line)
			}
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON: %v: %s", err, line)
		}
		want := printable.Text(hostile)
		if m["path"] != want || m["error"] != want || m["trace_id"] != "9af31c02" || m["msg"] != "cannot load" || m["level"] != "ERROR" {
			t.Errorf("JSON line %v", m)
		}
		if names, _ := m["names"].([]any); len(names) != 1 || names[0] != want {
			t.Errorf("JSON line's list %v", m["names"])
		}
		if _, ok := m["time"].(string); !ok {
			t.Errorf("JSON line's time %v", m["time"])
		}
	}
}
