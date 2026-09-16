package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/report"
)

// testRegistry loads a two-profile grants registry: hue exposes a /v1/lights
// collection sibling, inventory exposes only a per-item orders route.
func testRegistry(t *testing.T) *grants.Registry {
	t.Helper()
	t.Setenv("HUE_TOKEN", "x")
	t.Setenv("INV_TOKEN", "y")
	body := `{"profiles":{
	  "hue":{"base_url":"https://hue.local","allow":["GET /v1/lights/*","GET /v1/lights","GET /v1/sensors/*"],"allowed_callers":["*"],"token":{"type":"static","env":"HUE_TOKEN"}},
	  "inventory":{"base_url":"https://inv.local","allow":["GET /api/orders/*"],"allowed_callers":["*"],"token":{"type":"static","env":"INV_TOKEN"}}
	}}`
	path := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(path)
	if err != nil {
		t.Fatalf("load grants: %v", err)
	}
	return reg
}

// TestAttachPrompts proves the Phase 3 surfacing rules: an API-change finding gets a
// design prompt grounded in its profile's routes, an agent-fixable finding does not,
// an unknown profile is skipped without error, and a historical record naming a
// retired remedy (aggregate, filter, parallel; deleted 2026-09-16) renders without a
// prompt, since the detector that would have justified one no longer exists.
func TestAttachPrompts(t *testing.T) {
	reg := testRegistry(t)
	records := []report.Record{
		{
			Profile: "inventory", // grants only the per-item route: no collection sibling
			Findings: []report.Finding{{
				Pattern: "fan_out", Remedy: "batch", Method: "GET",
				Route: "/api/orders/*", Detail: "fan-out with no granted collection route", AgentFixable: false,
				ExtraCalls: 29,
			}},
		},
		{
			Profile: "inventory",
			Findings: []report.Finding{{
				Pattern: "aggregate_in_code", Remedy: "aggregate", Method: "GET",
				Route: "/api/orders/*", Detail: "historical record from before 2026-09-16", AgentFixable: false,
			}},
		},
		{
			Profile: "hue",
			Findings: []report.Finding{{
				Pattern: "fan_out", Remedy: "batch", Method: "GET", Route: "/v1/lights/*",
				Detail: "fan-out", AgentFixable: true, SuggestedRoute: "/v1/lights",
			}},
		},
		{
			Profile: "ghost", // unknown profile: must be skipped, not panic
			Findings: []report.Finding{{
				Pattern: "fan_out", Remedy: "batch", Method: "GET", Route: "/x/*", AgentFixable: false,
			}},
		},
	}

	attachPrompts(records, reg)

	// API-change finding got a grounded prompt naming its declared routes.
	prompt := records[0].Findings[0].DesignPrompt
	if prompt == "" {
		t.Fatal("API-change finding got no design prompt")
	}
	if !strings.Contains(prompt, "API designer") || !strings.Contains(prompt, "/api/orders/*") {
		t.Errorf("prompt not grounded in the profile routes:\n%s", prompt)
	}
	// A read fan-out's prompt offers the server-side aggregate as a conditional
	// alternative, which is where the retired aggregate-in-code idea now lives.
	if !strings.Contains(prompt, "server-side aggregate") {
		t.Errorf("read fan-out prompt should offer the aggregate alternative:\n%s", prompt)
	}
	// A historical retired-remedy record renders but gets no prompt.
	if records[1].Findings[0].DesignPrompt != "" {
		t.Error("a retired-remedy record must not receive a design prompt")
	}
	// Agent-fixable finding is left alone (the fix is a route switch).
	if records[2].Findings[0].DesignPrompt != "" {
		t.Error("agent-fixable finding should not receive a design prompt")
	}
	// Unknown profile is skipped.
	if records[3].Findings[0].DesignPrompt != "" {
		t.Error("unknown profile should receive no prompt")
	}
}
