package main

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
	"github.com/plimsollmark/plimsoll/examples/adapter/qualify"
)

// The lookup over the published evidence, as -verify -adapter answers it: the second
// adapter is qualified; the first is not, failing in exactly the requirements and
// scenarios the program expects its runs to fail (runPlan's WantFail, read through the
// requirements file); an adapter broken on purpose ran one scenario of eight; and the
// second adapter with one byte added has no qualification at all.
func TestLookupOverPublishedEvidence(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	reqPath := filepath.Join("examples", "adapter", "contract", "requirements.json")
	verified, reqs, err := verifyDir(filepath.Join("docs", "examples", "adapter"), reqPath)
	if err != nil {
		t.Fatal(err)
	}
	adapters := filepath.Join("examples", "adapter", "adapter")
	ask := func(adapter string) (int, string) {
		t.Helper()
		var out bytes.Buffer
		status, err := lookup(&out, verified, reqs, reqPath, adapter)
		if err != nil {
			t.Fatalf("%s: %v", adapter, err)
		}
		return status, out.String()
	}
	scenarios := len(fleetsim.ScenarioOrder)

	status, out := ask(filepath.Join(adapters, "adapter-v2.js"))
	if status != exitQualified || !strings.Contains(out, fmt.Sprintf("REQ-004 held in %d of %d runs", scenarios, scenarios)) || !strings.Contains(out, "qualified: every requirement") {
		t.Fatalf("the second adapter: status %d\n%s", status, out)
	}

	if !strings.Contains(out, "sha256 "+reqs.SHA256()+"), pinned by every statement") {
		t.Fatalf("the second adapter's answer does not name the pinned requirements file:\n%s", out)
	}

	// The first adapter: each requirement's misses are the scenarios whose expected
	// failures include its rule.
	status, out = ask(filepath.Join(adapters, "adapter-v1.js"))
	if status != exitNotQualified {
		t.Fatalf("the first adapter: status %d\n%s", status, out)
	}
	for _, q := range reqs.Requirements {
		misses := 0
		for _, r := range runPlan() {
			if r.Group == "first" && slices.ContainsFunc(q.Rules, func(rule string) bool { return slices.Contains(r.WantFail, rule) }) {
				misses++
			}
		}
		if want := fmt.Sprintf("%s held in %d of %d runs", q.ID, scenarios-misses, scenarios); !strings.Contains(out, want) {
			t.Errorf("the first adapter: want %q in\n%s", want, out)
		}
	}
	if !strings.Contains(out, "REQ-004 held in 7 of 8 runs") || !strings.Contains(out, "Not held in: "+fleetsim.ScenarioLostAck+" (run ") {
		t.Fatalf("the first adapter's lost answer:\n%s", out)
	}

	status, out = ask(filepath.Join(adapters, "broken", "wrong-target.js"))
	if status != exitNotQualified || !strings.Contains(out, fmt.Sprintf("%d of %d scenarios not run", scenarios-1, scenarios)) || !strings.Contains(out, "REQ-005 held in 0 of 1 run:") {
		t.Fatalf("an adapter broken on purpose: status %d\n%s", status, out)
	}

	src, err := os.ReadFile(filepath.Join(adapters, "adapter-v2.js"))
	if err != nil {
		t.Fatal(err)
	}
	changed := filepath.Join(t.TempDir(), "adapter-v2.js")
	if err := os.WriteFile(changed, append(src, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	status, out = ask(changed)
	if status != exitNoQualification || !strings.Contains(out, "no qualification for adapter digest "+qualify.Digest(string(src)+"\n")) || !strings.Contains(out, "rerun required") {
		t.Fatalf("the second adapter with one byte added: status %d\n%s", status, out)
	}

	// The boundary probe is judged by its own rules and qualifies nothing.
	if status, out = ask(filepath.Join(adapters, "probe.js")); status != exitNoQualification {
		t.Fatalf("the probe: status %d\n%s", status, out)
	}
}

// The page's requirements table, built from the published statements as the run builds
// it: the template executes with it, the first adapter misses REQ-004 in the lost answer
// only, the second qualifies, and the second with one byte added has no qualification.
func TestRequirementsTableOverPublishedEvidence(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	verified, reqs, err := verifyDir(filepath.Join("docs", "examples", "adapter"), filepath.Join("examples", "adapter", "contract", "requirements.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := readInputs(runPlan())
	if err != nil {
		t.Fatal(err)
	}
	var data pageData
	if err := requirementsView(&data, reqs, verified, files); err != nil {
		t.Fatal(err)
	}
	if len(data.ReqRows) != len(reqs.Requirements) || data.ReqSHA != reqs.SHA256() {
		t.Fatalf("%d rows for %d requirements, pinned %s", len(data.ReqRows), len(reqs.Requirements), data.ReqSHA)
	}
	req4 := data.ReqRows[3]
	if req4.ID != "REQ-004" || req4.Cells[0].Label != "7 of 8" || req4.Cells[0].Failed != "not held in a lost answer (run 4)" || req4.Cells[1].Label != "8 of 8" || req4.Cells[1].Failed != "" {
		t.Fatalf("REQ-004: %+v", req4)
	}
	if !strings.HasPrefix(data.QualV2, "qualified") || !strings.HasPrefix(data.QualV1, "not qualified: 5 of 8") {
		t.Fatalf("first %q, second %q", data.QualV1, data.QualV2)
	}
	if !strings.Contains(data.ChangedAnswer, "no qualification for adapter digest "+data.ChangedSHA) || !strings.Contains(data.ChangedAnswer, "rerun required") {
		t.Fatalf("one byte added: %q", data.ChangedAnswer)
	}
	tmpl, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		t.Fatal(err)
	}
	var page bytes.Buffer
	if err := tmpl.Execute(&page, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), `<td class="reqid"><code>REQ-004</code></td>`) || !strings.Contains(page.String(), "not held in a lost answer (run 4)") {
		t.Fatal("the executed page lacks the REQ-004 row")
	}
}
