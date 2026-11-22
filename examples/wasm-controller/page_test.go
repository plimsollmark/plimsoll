package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/pagetest"
)

// The committed docs/examples/wasm-controller/index.html carries every literal run of page.html, the
// template a run writes it from, in the template's order (internal/pagetest says why).
func TestCommittedPageCarriesEveryLineOfItsTemplate(t *testing.T) {
	pagetest.CarriesTemplate(t, pageTemplate, filepath.Join("..", "..", "docs", "examples", "wasm-controller", "index.html"),
		"go run ./examples/wasm-controller")
}

// The numbers on the committed page come from a run, which needs docker; this test
// does not. It checks that the page's embedded record agrees with fingerprints.json,
// the fixture sandbox/docker_wasm_controller_test.go asserts under docker, so a page
// left over from an older controller, compile or plant fails here.
func TestCommittedPageAgreesWithTheFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "wasm-controller", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	const open, end = `<script type="application/json" id="data">`, `</script>`
	page := string(raw)
	i := strings.Index(page, open)
	if i < 0 {
		t.Fatal("the committed page has no embedded run data")
	}
	body := page[i+len(open):]
	var data struct {
		Wasm struct {
			SHA256 string `json:"sha256"`
		} `json:"wasm"`
		Scenarios []scenarioRow `json:"scenarios"`
	}
	if err := json.Unmarshal([]byte(body[:strings.Index(body, end)]), &data); err != nil {
		t.Fatal(err)
	}
	var fx fixture
	if err := json.Unmarshal(fixtureJSON, &fx); err != nil {
		t.Fatal(err)
	}
	if data.Wasm.SHA256 != fx.ControllerWasmSHA256 {
		t.Errorf("page shows controller.wasm %s, fixture records %s", data.Wasm.SHA256, fx.ControllerWasmSHA256)
	}
	if len(data.Scenarios) != len(fx.Scenarios) {
		t.Fatalf("page has %d scenarios, fixture %d", len(data.Scenarios), len(fx.Scenarios))
	}
	for k, s := range fx.Scenarios {
		got := data.Scenarios[k]
		if got.ID != s.ID || got.Fingerprint != s.Fingerprint || got.SecondRun != s.Fingerprint {
			t.Errorf("%s: page shows %s %s/%s, fixture records %s", s.ID, got.ID, got.Fingerprint, got.SecondRun, s.Fingerprint)
		}
		if got.MathCos != s.MathCosFingerprint || got.JavaScript != s.MathCosFingerprint {
			t.Errorf("%s: page shows Math.cos %s and JavaScript %s, fixture records %s for both", s.ID, got.MathCos, got.JavaScript, s.MathCosFingerprint)
		}
		if identical := s.Fingerprint == s.MathCosFingerprint; identical != (len(got.VsJS.Rows) == 0) {
			t.Errorf("%s: page lists %d differing rows against the JavaScript law, but the fixture's fingerprints say identical=%t", s.ID, len(got.VsJS.Rows), identical)
		}
	}
}
