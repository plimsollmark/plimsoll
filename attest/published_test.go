package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
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

// The bundles v0.27.1 published, copied from that release's tag before the version 5
// change, still verify whole with records of version 4: the sessions example's chained
// session calls, and the agent-sandbox example's records, which state the field version 4
// added, instance (finding cyclonedx-16, 2026-11-16).
func TestTheBundlesV0271PublishedStillVerify(t *testing.T) {
	for _, tc := range []struct {
		dir      string
		session  bool
		instance bool
	}{
		{"v0.27.1-sessions", true, false},
		{"v0.27.1-agentsandbox", false, true},
	} {
		entries, v := publishedBundle(t, tc.dir)
		if _, err := VerifyBundle(entries, v); err != nil {
			t.Fatalf("the %s bundle: %v", tc.dir, err)
		}
		if got := recordVersions(t, entries, v); len(got) != 1 || !got[4] {
			t.Fatalf("%s: record versions %v; v0.27.1 wrote version 4 only", tc.dir, got)
		}
		var session, instance bool
		for _, e := range entries {
			if e.Request == nil {
				continue
			}
			rec, err := VerifyCall(v, e)
			if err != nil {
				t.Fatal(err)
			}
			session = session || rec.Session != ""
			instance = instance || rec.Instance != ""
		}
		if session != tc.session || instance != tc.instance {
			t.Errorf("%s: session calls %v, instance stated %v; want %v, %v", tc.dir, session, instance, tc.session, tc.instance)
		}
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

// A signed version 1 or 2 record that ends before it starts is refused as a retired
// reading, not as a forged statement: daemons v0.10.0 to v0.12.0 stamped both times from
// the wall clock and could write one during a clock step, and reading one was retired by
// the decision of 2026-11-21 (record.ErrRetired; finding t6-core-1). The records are the
// frozen ones of record/testdata/retired/clock-step-v1-v2.json, signed here as the harness
// signed them; the same record at a later version is an invalid statement.
func TestSignedWallClockRecordsThatEndBeforeTheyStartAreRetired(t *testing.T) {
	data, err := os.ReadFile("../record/testdata/retired/clock-step-v1-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Records []struct {
			Name   string          `json:"name"`
			Record json.RawMessage `json:"record"`
			SHA256 string          `json:"sha256"`
		} `json:"records"`
	}
	if err := json.Unmarshal(data, &g); err != nil || len(g.Records) == 0 {
		t.Fatalf("the clock-step records: %v", err)
	}
	signer, verifier := newKeyPair(t)
	sign := func(rec sandbox.RunRecord) Envelope {
		payload, err := json.Marshal(Statement{
			Type:          StatementType,
			Subject:       []Subject{{Name: SubjectName, Digest: map[string]string{"sha256": rec.SHA256}}},
			PredicateType: PredicateType,
			Predicate:     predicateOf(rec),
		})
		if err != nil {
			t.Fatal(err)
		}
		return signer.envelope(payload)
	}
	for _, r := range g.Records {
		m := &plimsollv1.RunRecord{}
		if err := protojson.Unmarshal(r.Record, m); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		rec := record.FromWire(m)
		rec.SHA256 = r.SHA256
		if !rec.Ended.Before(rec.Started) {
			t.Fatalf("%s: does not end before it starts", r.Name)
		}
		if _, err := verifier.Verify(sign(rec)); !errors.Is(err, record.ErrRetired) || errors.Is(err, ErrStatement) ||
			err.Error() != "record: "+record.RetiredEndBeforeStartText {
			t.Errorf("%s: %v; want the retirement's refusal, not an invalid statement", r.Name, err)
		}
		later := rec
		later.Version = record.LastWallClockEndVersion + 2 // version 4: answered calls, no field version 2 lacks
		later.SHA256 = record.Digest(later)
		if _, err := verifier.Verify(sign(later)); !errors.Is(err, ErrStatement) || errors.Is(err, record.ErrRetired) {
			t.Errorf("%s at version %d: %v; want ErrStatement", r.Name, later.Version, err)
		}
	}
}
