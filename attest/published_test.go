package attest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// publishedBundle reads a bundle and its harness key as a release published them
// beside the sessions example (testdata/published, never edited).
func publishedBundle(t *testing.T, dir string) ([]Entry, *Verifier) {
	t.Helper()
	data, err := os.ReadFile("testdata/published/" + dir + "/bundle.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ReadBundle(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	pem, err := os.ReadFile("testdata/published/" + dir + "/harness.pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	return entries, NewVerifier(pub)
}

// The bundle v0.22.0 published still verifies whole, links and all, with records of
// version 2: evidence signed under an older release checks without its binary
// (since 2026-10-23).
func TestTheBundleV0220PublishedStillVerifies(t *testing.T) {
	entries, v := publishedBundle(t, "v0.22.0-sessions")
	if _, err := VerifyBundle(entries, v); err != nil {
		t.Fatalf("the v0.22.0 bundle: %v", err)
	}
	if got := recordVersions(t, entries, v); !got[2] {
		t.Fatalf("record versions %v; the v0.22.0 bundle holds version 2 records", got)
	}
}

// Every record v0.11.1 published, version 1, still verifies against the request and
// response stored beside it. The bundle as a whole does not: links arrived in v0.18.0,
// and accepting a bundle without them would let anyone strip a newer bundle's links to
// drop or reorder its lines unseen, so it would need a guard against that first.
func TestTheRecordsV0111PublishedStillVerify(t *testing.T) {
	data, err := os.ReadFile("testdata/published/v0.11.1-sessions/bundle.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBundle(bytes.NewReader(data)); err == nil {
		t.Fatal("a bundle with no links was read as a bundle")
	}
	var entries []Entry
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	pem, err := os.ReadFile("testdata/published/v0.11.1-sessions/harness.pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	if got := recordVersions(t, entries, NewVerifier(pub)); len(got) != 1 || !got[1] {
		t.Fatalf("record versions %v; the v0.11.1 bundle holds version 1 records only", got)
	}
}

// recordVersions verifies each call line's statement and its record against the
// stored request and response, and returns the record versions seen.
func recordVersions(t *testing.T, entries []Entry, v *Verifier) map[int]bool {
	t.Helper()
	seen := map[int]bool{}
	for i, e := range entries {
		if e.Request == nil {
			continue // a session-close or checkpoint line
		}
		// The shipped path for a line with no link: plimsoll-attest verify-record.
		rec, err := VerifyCall(v, e)
		if err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		seen[rec.Version] = true
	}
	return seen
}
