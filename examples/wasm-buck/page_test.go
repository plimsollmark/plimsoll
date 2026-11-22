package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/pagetest"
)

// The committed docs/examples/wasm-buck/index.html carries every literal run of page.html, the
// template a run writes it from, in the template's order (internal/pagetest says why).
func TestCommittedPageCarriesEveryLineOfItsTemplate(t *testing.T) {
	pagetest.CarriesTemplate(t, pageTemplate, filepath.Join("..", "..", "docs", "examples", "wasm-buck", "index.html"),
		"go run ./examples/wasm-buck")
}

func committedPage(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "wasm-buck", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The numbers on the committed page come from a run; this test checks that its
// embedded record agrees with fingerprints.json, the fixture
// sandbox/docker_wasm_buck_test.go asserts under docker, so a page left over from an
// older controller, compile or plant fails without docker.
func TestCommittedPageAgreesWithTheFixture(t *testing.T) {
	page := committedPage(t)
	const open, end = `<script type="application/json" id="data">`, `</script>`
	i := strings.Index(page, open)
	if i < 0 {
		t.Fatal("the committed page has no embedded run data")
	}
	body := page[i+len(open):]
	var data struct {
		Wasm struct {
			SHA256    string `json:"sha256"`
			SecondRun string `json:"second_run"`
		} `json:"wasm"`
		Scenarios []scenarioRow `json:"scenarios"`
		Trace     trace         `json:"trace"`
	}
	if err := json.Unmarshal([]byte(body[:strings.Index(body, end)]), &data); err != nil {
		t.Fatal(err)
	}
	var fx fixture
	if err := json.Unmarshal(fixtureJSON, &fx); err != nil {
		t.Fatal(err)
	}
	if data.Wasm.SHA256 != fx.ControllerWasmSHA256 || data.Wasm.SecondRun != fx.ControllerWasmSHA256 {
		t.Errorf("page shows controller.wasm %s and %s, fixture records %s", data.Wasm.SHA256, data.Wasm.SecondRun, fx.ControllerWasmSHA256)
	}
	if len(data.Scenarios) != len(fx.Scenarios) {
		t.Fatalf("page has %d scenarios, fixture %d", len(data.Scenarios), len(fx.Scenarios))
	}
	for k, s := range fx.Scenarios {
		got := data.Scenarios[k]
		if got.ID != s.ID || got.Fingerprint != s.Fingerprint || got.SecondRun != s.Fingerprint || got.JavaScript != s.Fingerprint || !got.Identical {
			t.Errorf("%s: page shows %+v, fixture records %s for C and JavaScript alike", s.ID, got, s.Fingerprint)
		}
		if got.Score < fx.MinScore {
			t.Errorf("%s: page shows score %.3f, below the floor %.2f", s.ID, got.Score, fx.MinScore)
		}
	}
	if want := int(fx.TEndS/fx.TickS + 0.5); len(data.Trace.V) != want || len(data.Trace.I) != want || len(data.Trace.Duty) != want {
		t.Errorf("the replayed trace has %d/%d/%d ticks, want %d", len(data.Trace.V), len(data.Trace.I), len(data.Trace.Duty), want)
	}
}
