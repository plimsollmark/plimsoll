// Package dashboards holds the Grafana dashboard JSON plimsoll ships for the
// Prospector (API Efficiency Advisor) metrics, and the tests that keep it valid and
// in step with the metrics the daemon actually exports.
package dashboards

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

//go:embed prospector.json
var prospectorJSON []byte

// knownMetrics is every plimsoll metric series the dashboard is allowed to query.
// It is the exposition surface of cmd/plimsolld's writeHostCallMetrics /
// writeAdviceMetrics: keep the two in step, so a panel can never chart a metric the
// daemon does not emit.
var knownMetrics = map[string]bool{
	"plimsoll_host_calls_total":                   true,
	"plimsoll_host_call_latency_seconds_bucket":   true,
	"plimsoll_host_call_latency_seconds_sum":      true,
	"plimsoll_host_call_latency_seconds_count":    true,
	"plimsoll_advice_findings_total":              true,
	"plimsoll_advice_extra_calls_total":           true,
	"plimsoll_advice_added_latency_seconds_total": true,
	"plimsoll_advice_bytes_moved_total":           true,
}

type dashboard struct {
	Title         string `json:"title"`
	UID           string `json:"uid"`
	SchemaVersion int    `json:"schemaVersion"`
	Panels        []struct {
		ID      int    `json:"id"`
		Type    string `json:"type"`
		Title   string `json:"title"`
		GridPos struct {
			H, W, X, Y int
		} `json:"gridPos"`
		Targets []struct {
			Expr       string          `json:"expr"`
			RefID      string          `json:"refId"`
			Datasource json.RawMessage `json:"datasource"`
		} `json:"targets"`
	} `json:"panels"`
	Templating struct {
		List []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"list"`
	} `json:"templating"`
}

func load(t *testing.T) dashboard {
	t.Helper()
	// Must be valid JSON: this alone satisfies the roadmap's "dashboard JSON validates".
	var raw map[string]any
	if err := json.Unmarshal(prospectorJSON, &raw); err != nil {
		t.Fatalf("prospector.json is not valid JSON: %v", err)
	}
	var d dashboard
	if err := json.Unmarshal(prospectorJSON, &d); err != nil {
		t.Fatalf("prospector.json does not match the dashboard shape: %v", err)
	}
	return d
}

func TestDashboardTopLevel(t *testing.T) {
	d := load(t)
	if d.Title == "" {
		t.Error("dashboard has no title")
	}
	if d.UID == "" {
		t.Error("dashboard has no uid (needed for stable provisioning)")
	}
	if d.SchemaVersion == 0 {
		t.Error("dashboard has no schemaVersion")
	}
	if len(d.Panels) == 0 {
		t.Fatal("dashboard has no panels")
	}
}

func TestDashboardTemplating(t *testing.T) {
	d := load(t)
	names := map[string]string{}
	for _, v := range d.Templating.List {
		names[v.Name] = v.Type
	}
	if names["datasource"] != "datasource" {
		t.Errorf("expected a datasource template variable, got %v", names)
	}
	if names["profile"] != "query" {
		t.Errorf("expected a profile query variable, got %v", names)
	}
}

func TestDashboardPanelsWellFormed(t *testing.T) {
	d := load(t)
	seen := map[int]bool{}
	var queryPanels int
	for _, p := range d.Panels {
		if p.Type == "" {
			t.Errorf("panel %d has no type", p.ID)
		}
		if seen[p.ID] {
			t.Errorf("duplicate panel id %d", p.ID)
		}
		seen[p.ID] = true
		if p.Type == "row" {
			continue // rows carry no query and their zero-height gridPos is expected
		}
		if p.GridPos.H == 0 || p.GridPos.W == 0 {
			t.Errorf("panel %q (%d) has a zero-size gridPos", p.Title, p.ID)
		}
		if len(p.Targets) == 0 {
			t.Errorf("panel %q (%d) has no targets", p.Title, p.ID)
			continue
		}
		queryPanels++
		for _, tgt := range p.Targets {
			if strings.TrimSpace(tgt.Expr) == "" {
				t.Errorf("panel %q (%d) has a target with an empty expr", p.Title, p.ID)
			}
			// Every target must bind the templated datasource so the dashboard imports
			// cleanly against any Prometheus source the operator selects.
			if !strings.Contains(string(tgt.Datasource), "${datasource}") {
				t.Errorf("panel %q (%d) target %s does not reference ${datasource}: %s",
					p.Title, p.ID, tgt.RefID, tgt.Datasource)
			}
		}
	}
	if queryPanels == 0 {
		t.Fatal("dashboard has no query panels")
	}
}

// metricRef matches a plimsoll_* metric name in a PromQL expression.
var metricRef = regexp.MustCompile(`plimsoll_[a-z_]+`)

// TestDashboardMetricsAreExported ties every metric a panel queries to the set the
// daemon actually emits, so a renamed or dropped metric fails this test instead of
// silently producing an empty panel.
func TestDashboardMetricsAreExported(t *testing.T) {
	d := load(t)
	referenced := map[string]bool{}
	for _, p := range d.Panels {
		for _, tgt := range p.Targets {
			for _, m := range metricRef.FindAllString(tgt.Expr, -1) {
				referenced[m] = true
				if !knownMetrics[m] {
					t.Errorf("panel %q queries unknown metric %q (not exported by cmd/plimsolld)", p.Title, m)
				}
			}
		}
	}
	if len(referenced) == 0 {
		t.Fatal("no plimsoll_* metrics referenced by any panel")
	}
	// The dashboard must exercise the Phase 4 advice metrics, not only the Phase 0
	// host-call series — otherwise it isn't the advisor dashboard the roadmap asks for.
	if !referenced["plimsoll_advice_added_latency_seconds_total"] {
		t.Error("dashboard never charts pattern waste (plimsoll_advice_added_latency_seconds_total)")
	}
}
