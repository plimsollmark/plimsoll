package rpc

import (
	"log/slog"
	"strings"
	"testing"
)

func TestSanitizeTraceIDAccepts(t *testing.T) {
	// Representative shapes: a short gateway id, a UUID, an OTel trace id, and a
	// namespaced id a caller might build from them.
	for _, id := range []string{
		"9af31c02",
		"3f1b7c0e-9a41-4d8e-8f0a-5b2c1d3e4f50",
		"4bf92f3577b34da6a3ce929d0e0e4736",
		"gateway:run.2026-08-09_a1b2",
		strings.Repeat("a", maxTraceIDBytes),
	} {
		got, rejected := sanitizeTraceID(id)
		if rejected || got != id {
			t.Errorf("sanitizeTraceID(%q) = (%q, %v), want (%q, false)", id, got, rejected, id)
		}
	}
}

func TestSanitizeTraceIDRejects(t *testing.T) {
	// Each of these is a way the field could smuggle something into a stream whose
	// whole claim is that it holds no path, body, or credential. Rejection must be
	// total: a partially stripped id would look joinable and join to nothing.
	for name, id := range map[string]string{
		"path":            "/v1/customers/8821",
		"query":           "id=8821&ssn=123-45-6789",
		"url":             "https://api.internal/v1/customers/8821",
		"bearer token":    "Bearer sk_live_9af3c1d2e3f4",
		"json body":       `{"ssn":"123-45-6789"}`,
		"space delimited": "run 8821",
		"newline":         "9af31c02\ntrace_id=spoofed",
		"tab":             "9af31c02\tinjected",
		"control byte":    "9af31c02\x00",
		"percent escape":  "%2Fv1%2Fcustomers",
		"non-ascii":       "café",
		"over length":     strings.Repeat("a", maxTraceIDBytes+1),
	} {
		got, rejected := sanitizeTraceID(id)
		if !rejected {
			t.Errorf("%s: sanitizeTraceID(%q) accepted, want rejected", name, id)
		}
		if got != "" {
			t.Errorf("%s: sanitizeTraceID(%q) = %q, want the value dropped whole", name, id, got)
		}
	}
}

func TestSanitizeTraceIDEmptyIsNotARejection(t *testing.T) {
	// A caller that does not correlate is the normal case, not an error: it must
	// not raise trace_id_rejected, which is an operator signal that a join broke.
	got, rejected := sanitizeTraceID("")
	if got != "" || rejected {
		t.Fatalf("sanitizeTraceID(\"\") = (%q, %v), want (\"\", false)", got, rejected)
	}
}

func TestTraceAttrs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []slog.Attr
	}{
		{"absent logs nothing", "", nil},
		{"conforming logs the id", "9af31c02", []slog.Attr{slog.String("trace_id", "9af31c02")}},
		{"rejected logs the fact, not the value", "/v1/customers/8821", []slog.Attr{slog.Bool("trace_id_rejected", true)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := traceAttrs(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("traceAttrs(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			for i := range got {
				if got[i].Key != tc.want[i].Key || got[i].Value.String() != tc.want[i].Value.String() {
					t.Fatalf("traceAttrs(%q)[%d] = %v, want %v", tc.raw, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestTraceAttrsNeverEchoesARejectedValue(t *testing.T) {
	// The regression that matters: rejecting must not leak the thing we rejected.
	// A naive "log what we dropped so the operator can debug it" would put the raw
	// path straight into the metadata-only stream.
	const hostile = "/v1/customers/8821?ssn=123-45-6789"
	for _, attr := range traceAttrs(hostile) {
		if strings.Contains(attr.Value.String(), "customers") || strings.Contains(attr.Value.String(), "ssn") {
			t.Fatalf("rejected value leaked into attr %v", attr)
		}
	}
}
