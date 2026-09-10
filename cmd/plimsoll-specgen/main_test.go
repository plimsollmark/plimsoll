package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/specgen"
)

func TestWriteDirHealthCheckLifecycle(t *testing.T) {
	dir := t.TempDir()
	withHealth := &specgen.Result{
		Preamble:    "// sdk\n",
		Description: "tool description\n",
		HealthCheck: "GET /readyz",
	}
	if err := writeDir(dir, withHealth); err != nil {
		t.Fatalf("write with health check: %v", err)
	}
	healthPath := filepath.Join(dir, "health_check.txt")
	if got, err := os.ReadFile(healthPath); err != nil || string(got) != "GET /readyz\n" {
		t.Fatalf("health_check.txt = %q, %v; want %q", got, err, "GET /readyz\n")
	}

	// Regeneration into the same directory must revoke the old designation when the
	// current spec has no unambiguous health route.
	withoutHealth := &specgen.Result{Preamble: "// sdk\n", Description: "tool description\n"}
	if err := writeDir(dir, withoutHealth); err != nil {
		t.Fatalf("rewrite without health check: %v", err)
	}
	if _, err := os.Stat(healthPath); !os.IsNotExist(err) {
		t.Fatalf("stale health_check.txt remains after regeneration: %v", err)
	}
}

func TestBundleJSONIncludesHealthCheck(t *testing.T) {
	res := &specgen.Result{
		Title:       "Example",
		Version:     "1.0.0",
		Global:      "api",
		HealthCheck: "GET /capacity",
		HealthNote:  "example note",
	}
	var got bytes.Buffer
	if err := printBundleJSON(&got, res); err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(got.Bytes(), &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if bundle["health_check"] != "GET /capacity" {
		t.Fatalf("health_check = %#v, want %q", bundle["health_check"], "GET /capacity")
	}
	if bundle["health_note"] != "example note" {
		t.Fatalf("health_note = %#v, want %q", bundle["health_note"], "example note")
	}
}
