package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func TestBrowserReceiptCheckerInNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("Node 22 or later is required, no skip: %v", err)
	}
	// Go supplies additional vectors covering non-ASCII path order, arbitrary
	// output bytes, flags, ordered software rules and both request domains.
	var vectors []object
	for _, protocol := range []uint32{1, 2, 3, 4} {
		q := &plimsollv1.RunRequest{Protocol: protocol, MinimumIsolation: "kernel", TimeoutMs: 30000,
			Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
				Files: []*plimsollv1.ProjectFile{{Path: "😀.js", Content: "print('é')"}, {Path: "\ue000.js", Content: "zero\x00\n"}},
				Steps: []string{"first", "second"}, Artifacts: []string{"z", "a"},
			}},
		}
		if protocol >= 2 {
			q.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "approved", Identities: []string{"b", "a"}}
		}
		// The current protocol's vector carries the newest outcome, so a checker whose
		// outcome table lags the protocol fails here (review, 2026-10-24).
		outcome := plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT
		if protocol == 4 {
			outcome = plimsollv1.ProjectOutcome_PROJECT_OUTCOME_RUNNER_FAILED
		}
		a := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "kernel", Environment: "index", SoftwareIdentity: "selected",
			Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{
				Outcome: outcome, OutcomeDetail: "bounded", ArtifactsTruncated: true,
				Steps:     []*plimsollv1.StepResult{{Command: "first", ExitCode: -3, TimedOut: true, Stdout: []byte{0, 255, 254}, Stderr: []byte("é\n"), StdoutTruncated: true, StderrTruncated: true}},
				Artifacts: []*plimsollv1.Artifact{{Path: "z", Content: []byte{128, 0}}},
			}},
		}
		r := sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(q), Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000123)}
		a.Record = record.Stamp(r, a)
		s := source{Request: q, Response: a, Record: record.FromWire(a.Record)}
		x, err := exchangeBytes(s)
		if err != nil {
			t.Fatal(err)
		}
		files, fileHash, err := programFiles(s)
		if err != nil {
			t.Fatal(err)
		}
		vectors = append(vectors, object{"exchange": json.RawMessage(x), "request": record.RunRequestDigest(q), "result": record.ResultDigest(a), "record": record.Digest(s.Record), "files": files, "fileSet": fileHash})
	}
	data, err := json.Marshal(vectors)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(scratch(t), "browser-vectors.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, "check_test.mjs", path).CombinedOutput(); err != nil {
		t.Fatalf("browser receipt checks: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
