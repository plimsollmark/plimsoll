package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The page is written from page.html by a run that needs docker, but the artifact
// people read is the committed docs/examples/wasm-buck/index.html. Every literal run
// of the template must appear in the committed page, in the template's order, so
// prose edited in one and not the other fails here.
func TestCommittedPageCarriesEveryLineOfItsTemplate(t *testing.T) {
	page, at := committedPage(t), 0
	for _, run := range templateLiterals(pageTemplate) {
		i := strings.Index(page[at:], run)
		if i < 0 {
			t.Fatalf("the committed page does not carry this template text "+
				"(edit both, or regenerate with `go run ./examples/wasm-buck`):\n%s", firstMissingLine(run, page))
		}
		at += i + len(run)
	}
}

func committedPage(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "wasm-buck", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// templateLiterals returns the text between {{actions}}, which Execute copies
// through untouched.
func templateLiterals(tmpl string) []string {
	var literals []string
	for i, part := range strings.Split(tmpl, "{{") {
		if i > 0 {
			end := strings.Index(part, "}}")
			if end < 0 {
				continue
			}
			part = part[end+2:]
		}
		if strings.TrimSpace(part) != "" {
			literals = append(literals, part)
		}
	}
	return literals
}

// firstMissingLine names the first line of a missing run that the page lacks
// anywhere, or the whole run when only the order changed.
func firstMissingLine(run, page string) string {
	for _, line := range strings.Split(run, "\n") {
		if strings.TrimSpace(line) != "" && !strings.Contains(page, line) {
			return line
		}
	}
	return run
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
