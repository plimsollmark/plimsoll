package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The page is written from page.html by a run that needs docker, but the artifact
// people read is the committed docs/examples/wasm-controller/index.html. Editing the prose in
// one and not the other is the drift this test exists to catch: every literal run of
// the template must appear in the committed page, in the template's order. It says
// nothing about the numbers, which only a real run can produce.
func TestCommittedPageCarriesEveryLineOfItsTemplate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "wasm-controller", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	page, at := string(raw), 0
	for _, run := range templateLiterals(pageTemplate) {
		i := strings.Index(page[at:], run)
		if i < 0 {
			t.Fatalf("the committed page does not carry this template text "+
				"(edit both, or regenerate with `go run ./examples/wasm-controller`):\n%s", excerpt(firstMissingLine(run, page)))
		}
		at += i + len(run)
	}
}

// templateLiterals returns the parts of the template that Execute copies through
// untouched: the text between {{actions}}, which must survive verbatim into the page.
func templateLiterals(tmpl string) []string {
	var literals []string
	for i, part := range strings.Split(tmpl, "{{") {
		if i > 0 {
			end := strings.Index(part, "}}")
			if end < 0 {
				continue // an unterminated action; Parse would have failed first
			}
			part = part[end+2:]
		}
		if strings.TrimSpace(part) != "" {
			literals = append(literals, part)
		}
	}
	return literals
}

// firstMissingLine narrows a missing literal run to the first of its lines the page
// does not contain anywhere, so the failure names the edited sentence rather than the
// whole block it sits in. It falls back to the run itself when every line is present
// individually, which means the order changed rather than the text.
func firstMissingLine(run, page string) string {
	for _, line := range strings.Split(run, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.Contains(page, line) {
			return line
		}
	}
	return run
}

func excerpt(run string) string {
	line := strings.TrimSpace(strings.ReplaceAll(run, "\n", " "))
	if len(line) > 160 {
		line = line[:160] + "…"
	}
	return line
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
