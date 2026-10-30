package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/receipt"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/runsclog"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const fixtureLog = "runsclog/testdata/canary.boot.json.gz"

// The canary fixture's pod, as its container specs name it.
const canaryPod = "c84f87fe-f629-416f-8297-516df9c7b30c"

// keys writes an Ed25519 key pair in the PEM forms plimsoll-attest keygen writes.
func keys(t *testing.T, dir, name string) (string, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPath, pubPath := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return keyPath, pubPath, priv
}

// bundle writes a one-line bundle holding a signed run record of a run in instance.
func bundle(t *testing.T, dir string, priv ed25519.PrivateKey, instance string) string {
	t.Helper()
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "require('fixture')"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "agentsandbox", Isolation: "kernel", Instance: instance,
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("ok\n")}}}
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
	var b bytes.Buffer
	if err := attest.NewHarness(attest.NewSigner(priv), &b).Record(req, resp); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle-"+instance[len(instance)-4:]+".jsonl")
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// Signed from the gzip-compressed log and joined to its run; checked from the log as runsc
// wrote it, with the record; refused with another pod's record, another key or another log.
func TestSignAndCheck(t *testing.T) {
	dir := t.TempDir()
	key, pub, priv := keys(t, dir, "harness")
	_, otherPub, _ := keys(t, dir, "other")
	runBundle := bundle(t, dir, priv, sandbox.PodInstance(canaryPod))
	out := filepath.Join(dir, "receipt.intoto.json")
	var stdout bytes.Buffer
	if err := run([]string{"-log", fixtureLog, "-key", key, "-out", out, "-bundle", runBundle, "-line", "1"}, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "sandbox k8s-pod-uid:"+canaryPod) || !strings.Contains(stdout.String(), "joined to run record") {
		t.Errorf("sign said: %s", stdout.String())
	}
	if err := run([]string{"-log", fixtureLog, "-key", key, "-out", out}, io.Discard); err == nil {
		t.Error("sign wrote over an existing receipt")
	}

	plain := filepath.Join(dir, "canary.boot.json")
	f, err := os.Open(fixtureLog)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(z)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := run([]string{"-check", out, "-pub", pub, "-log", plain, "-bundle", runBundle, "-line", "1"}, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "receipt checked: ") || !strings.Contains(stdout.String(), "the signer's word") {
		t.Errorf("check said: %s", stdout.String())
	}

	otherRun := bundle(t, dir, priv, sandbox.PodInstance("00000000-0000-0000-0000-000000000000"))
	for name, args := range map[string][]string{
		"without its record":         {"-check", out, "-pub", pub, "-log", plain},
		"another pod's record":       {"-check", out, "-pub", pub, "-log", plain, "-bundle", otherRun, "-line", "1"},
		"another key":                {"-check", out, "-pub", otherPub, "-log", plain, "-bundle", runBundle, "-line", "1", "-record-pub", pub},
		"another log":                {"-check", out, "-pub", pub, "-log", "runsclog/testdata/quiet.boot.json.gz", "-bundle", runBundle, "-line", "1"},
		"a record under another key": {"-check", out, "-pub", pub, "-log", plain, "-bundle", runBundle, "-line", "1", "-record-pub", otherPub},
		"a line past the bundle":     {"-check", out, "-pub", pub, "-log", plain, "-bundle", runBundle, "-line", "2"},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Errorf("%s: checked", name)
		}
	}
	if err := run([]string{"-log", fixtureLog, "-key", key, "-out", filepath.Join(dir, "x.json"), "-bundle", otherRun, "-line", "1"}, io.Discard); err == nil {
		t.Error("signed a receipt joined to another pod's run")
	}
}

// A guest picks how many destinations its log names, so the one-line summary counts them
// through a set and names only the first summaryDests: a lookup in a growing list made the
// work quadratic in the destinations, about 250,000 of which fit in a 256 MiB log.
func TestSummaryBoundsGuestChosenDestinations(t *testing.T) {
	const n = 50_000
	var p receipt.Predicate
	for i := range n {
		p.Attempted.Network = append(p.Attempted.Network, runsclog.Net{Kind: "connect", Addr: "10.0.0.1", Port: i + 1})
		// Every destination again, as a send that failed: still one destination each.
		p.Undetermined.Network = append(p.Undetermined.Network, runsclog.Net{Kind: "connect", Addr: "10.0.0.1", Port: i + 1})
	}
	got := summary(p)
	if !strings.Contains(got, fmt.Sprintf("network destinations tried: %d distinct, the first %d in order: ", n, summaryDests)) {
		t.Fatalf("summary does not state the distinct count and the bound: %.300s", got)
	}
	if named := strings.Count(got, "connect 10.0.0.1:"); named != summaryDests {
		t.Fatalf("summary names %d destinations, want %d", named, summaryDests)
	}

	p = receipt.Predicate{}
	p.Effected.Network = []runsclog.Net{{Kind: "connect", Addr: "10.0.0.2", Port: 443}, {Kind: "connect", Addr: "10.0.0.2", Port: 443}}
	if got := summary(p); !strings.Contains(got, "network destinations tried: connect 10.0.0.2:443;") {
		t.Fatalf("a short list is no longer named whole: %.300s", got)
	}
}
