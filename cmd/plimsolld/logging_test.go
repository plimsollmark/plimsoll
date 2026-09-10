package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
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
