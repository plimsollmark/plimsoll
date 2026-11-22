package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/sbom/cdxutil"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/wslc"
)

// wslcBundle is a bundle of one WSL containers project run, its record stamped as a
// daemon stamps it with the sentence given, signed by a key made for the test.
func wslcBundle(t *testing.T, sentence string) (bundle, pub []byte) {
	t.Helper()
	privPEM, pubPEM, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := attest.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	req := &plimsollv1.RunRequest{Protocol: protocol.Number, MinimumIsolation: "vm", TimeoutMs: 30000,
		Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
			Files: []*plimsollv1.ProjectFile{{Path: "main.js", Content: "console.log(1)"}}, Steps: []string{"node main.js"}}}}
	resp := &plimsollv1.RunResponse{Sandbox: "wslc", Isolation: "vm", Environment: "wslc-image:sha256:" + strings.Repeat("c3", 32),
		IsolationQualification: sentence, DaemonVersion: "v0.28.0",
		Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED,
			Steps: []*plimsollv1.StepResult{{Command: "node main.js", Stdout: []byte("1\n")}}}}}
	started := time.UnixMilli(1790000000000)
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req), Started: started, Ended: started.Add(time.Second)}, resp)
	var buf bytes.Buffer
	h := attest.NewHarness(attest.NewSigner(key), &buf)
	if err := h.Record(req, resp); err != nil {
		t.Fatal(err)
	}
	if err := h.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), pubPEM
}

// A WSL containers run reaches a bill of materials only with Microsoft's statement beside
// its tier (finding cyclonedx-14): a version 5 record that states it is written, with the
// sentence as plimsoll:isolation_qualification on the workflow and in the tier claim, and
// its image named by its image ID, never as a registry pin (cyclonedx-13); -check and the
// browser checker pass it, and fail it once the sentence is taken out. A version 5 record
// without the sentence, and any version 4 WSL record, are refused.
func TestAWSLRunReachesABOMOnlyWithItsQualification(t *testing.T) {
	sentence := wslc.PerRunAcceptedQualification
	bundle, pub := wslcBundle(t, sentence)
	srcs, err := sources(bundle, pub, defaults().Pages)
	if err != nil || len(srcs) != 1 {
		t.Fatalf("sources: %d, %v", len(srcs), err)
	}
	raw, err := buildBOM(srcs[0], defaults())
	if err != nil {
		t.Fatal(err)
	}
	followsTaxonomy(t, readTaxonomy(t), "a WSL run", raw)
	bom := decodeBOM(t, raw)
	w := bom["formulation"].([]any)[0].(map[string]any)["workflows"].([]any)[0].(map[string]any)
	if got := propertyValues(w)["plimsoll:isolation_qualification"]; len(got) != 1 || got[0] != sentence {
		t.Fatalf("plimsoll:isolation_qualification is %v, want the record's sentence once", got)
	}
	claims := bom["declarations"].(map[string]any)["claims"].([]any)
	image, tier := claims[1].(map[string]any)["predicate"].(string), claims[2].(map[string]any)["predicate"].(string)
	if !strings.Contains(image, "image ID is sha256:"+strings.Repeat("c3", 32)) || !strings.Contains(image, "no registry pin is stated") || strings.Contains(image, "manifest digest is") {
		t.Errorf("the image claim does not name the image ID as an image ID: %s", image)
	}
	if !strings.HasSuffix(tier, "Beside that tier the daemon states, signed in the record: "+sentence) {
		t.Errorf("the tier claim does not end with the sentence: %s", tier)
	}
	if _, err := checkBOM(raw, pub, nil, have(srcs[0])); err != nil {
		t.Fatalf("-check: %v", err)
	}
	// The sentence taken out of the workflow: -check and the browser checker refuse it.
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	wf := doc["formulation"].([]any)[0].(map[string]any)["workflows"].([]any)[0].(map[string]any)
	var kept []any
	for _, p := range wf["properties"].([]any) {
		if p.(map[string]any)["name"] != "plimsoll:isolation_qualification" {
			kept = append(kept, p)
		}
	}
	wf["properties"] = kept
	cut, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkBOM(cut, pub, nil, have(srcs[0])); err == nil {
		t.Error("-check passed a WSL BOM without its sentence")
	}
	browser := browserCheck(t, map[string][]byte{"whole": raw, "cut": cut})
	if !browser["whole"]["qualification"] || browser["cut"]["qualification"] {
		t.Errorf("the browser checker's qualification line: whole %v, cut %v; want true, false", browser["whole"], browser["cut"])
	}
	for id, ok := range browser["whole"] {
		if !ok {
			t.Errorf("the browser checker failed %s on the whole WSL BOM", id)
		}
	}

	// No sentence in a version 5 record, and a version 4 WSL record: refused.
	bare, bpub := wslcBundle(t, "")
	if _, err := sources(bare, bpub, defaults().Pages); err == nil || !strings.Contains(err.Error(), "states no isolation qualification") {
		t.Errorf("a version 5 WSL record with no sentence: %v", err)
	}
	old := srcs[0]
	old.Record.Version, old.Record.IsolationQualification, old.Record.DaemonVersion = 4, "", ""
	old.Record.SHA256 = record.Digest(old.Record)
	if _, err := buildBOM(old, defaults()); err == nil || !strings.Contains(err.Error(), "states no isolation qualification") {
		t.Errorf("a version 4 WSL record: %v", err)
	}
	// The record itself is a valid stored version 4 record; only the bill refuses it.
	if err := record.CheckStored(old.Record); err != nil {
		t.Fatalf("the version 4 record does not check as stored evidence: %v", err)
	}
	if err := cdxutil.CheckQualification(old.Record); err == nil {
		t.Error("CheckQualification passed a version 4 WSL record")
	}
}

// browserCheck runs check.js on each BOM, as the page does, and returns each check line's
// result by id.
func browserCheck(t *testing.T, boms map[string][]byte) map[string]map[string]bool {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("Node 22 or later is required, no skip: %v", err)
	}
	dir := scratch(t)
	in := map[string]json.RawMessage{}
	for k, v := range boms {
		in[k] = v
	}
	data, _ := json.Marshal(in)
	path := filepath.Join(dir, "boms.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	script := `const fs = require('node:fs'); const vm = require('node:vm');
globalThis.crypto ??= require('node:crypto').webcrypto;
for (const f of ['tables.gen.js', 'check.js']) vm.runInThisContext(fs.readFileSync(f, 'utf8'));
(async () => { const boms = JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); const out = {};
for (const [k, b] of Object.entries(boms)) { out[k] = {}; for (const c of await globalThis.PlimsollReceipt.check(b)) out[k][c.id] = c.ok; }
process.stdout.write(JSON.stringify(out)); })().catch(e => { console.error(e); process.exit(1); });`
	out, err := exec.Command(node, "-e", script, path).Output()
	if err != nil {
		t.Fatalf("check.js: %v", err)
	}
	var got map[string]map[string]bool
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("check.js answered %s: %v", out, err)
	}
	return got
}
