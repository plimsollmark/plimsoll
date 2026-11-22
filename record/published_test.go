package record

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Every release's own golden vectors still hold: the requests, results and records it
// published, with the digests it computed. testdata/published holds each file as its
// release shipped it, never edited, so a change to an encoding a release wrote fails
// here (since 2026-10-23). v0.22.0's file covers protocol 1 and 2 requests, and
// records of versions 2 and 3; v0.27.1's, copied from that release's tag before the
// version 5 change, covers version 4.
func TestPublishedVectorsStillHold(t *testing.T) {
	files, err := filepath.Glob("testdata/published/*-golden.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no published vectors: %v", err)
	}
	versions := map[int]bool{}
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var g golden
		if err := json.Unmarshal(b, &g); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, r := range g.Requests {
			var got string
			switch r.Kind {
			case "run":
				m := &plimsollv1.RunRequest{}
				mustDecode(t, path, r.Name, r.Request, m)
				got = RunRequestDigest(m)
			case "session":
				m := &plimsollv1.SessionRunRequest{}
				mustDecode(t, path, r.Name, r.Request, m)
				got = SessionRunRequestDigest(m)
			default:
				t.Fatalf("%s: %s: unknown kind %q", path, r.Name, r.Kind)
			}
			if got != r.SHA256 {
				t.Errorf("%s: %s: request digest %s, the release computed %s", path, r.Name, got, r.SHA256)
			}
		}
		for _, r := range g.Results {
			m := &plimsollv1.RunResponse{}
			mustDecode(t, path, r.Name, r.Response, m)
			if got := ResultDigest(m); got != r.SHA256 {
				t.Errorf("%s: %s: result digest %s, the release computed %s", path, r.Name, got, r.SHA256)
			}
		}
		for _, r := range g.Records {
			m := &plimsollv1.RunRecord{}
			mustDecode(t, path, r.Name, r.Record, m)
			rec := FromWire(m)
			if got := Digest(rec); got != r.SHA256 {
				t.Errorf("%s: %s: record digest %s, the release computed %s", path, r.Name, got, r.SHA256)
			}
			rec.SHA256 = r.SHA256
			if err := CheckStored(rec); err != nil {
				t.Errorf("%s: %s: a stored version %d record is refused: %v", path, r.Name, rec.Version, err)
			}
			versions[rec.Version] = true
		}
	}
	// Every published version below the live one needs a vector a release made: a frozen
	// file here, or for version 1 the record golden.json copies from the bundle v0.11.1
	// signed (attest/testdata/published/v0.11.1-sessions, with the digest that release
	// computed). The live version's vector is frozen at its release (docs/releasing.md), so
	// a literal list no longer decides (review, 2026-10-26).
	for _, r := range loadGolden().Records {
		if rec := FromWire(fixture(r.Name, &plimsollv1.RunRecord{})); rec.Version != Version {
			versions[rec.Version] = true
		}
	}
	for v := range published {
		if v != Version && !versions[v] {
			t.Errorf("no published vector holds a version %d record", v)
		}
	}
}

// Version 4 is frozen from the bytes v0.27.1 shipped (record/testdata/golden.json at
// that tag), not from this tree, so a version 5 change that broke reading version 4
// records would fail here rather than be pinned by whatever the new code computes
// (finding cyclonedx-16, 2026-11-16). TestPublishedVectorsStillHold checks its digests.
func TestTheV0271VectorsHoldVersion4Records(t *testing.T) {
	b, err := os.ReadFile("testdata/published/v0.27.1-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.Records) == 0 {
		t.Fatal("the v0.27.1 vectors hold no record")
	}
	for _, r := range g.Records {
		m := &plimsollv1.RunRecord{}
		mustDecode(t, "v0.27.1", r.Name, r.Record, m)
		if v := FromWire(m).Version; v != 4 {
			t.Errorf("%s: version %d; v0.27.1 wrote version 4", r.Name, v)
		}
	}
}

func mustDecode(t *testing.T, path, name string, raw json.RawMessage, m proto.Message) {
	t.Helper()
	if err := protojson.Unmarshal(raw, m); err != nil {
		t.Fatalf("%s: %s: %v", path, name, err)
	}
}

// A record of a version no release wrote is ErrVersion, which tells the caller to
// upgrade the verifier, never ErrMismatch, which would call the record forged. A live
// answer must carry the current version whatever this package reads in storage.
func TestUnknownVersionsSayUpgradeAndLiveAnswersAreCurrent(t *testing.T) {
	future := goldenRecord()
	future.Version = Version + 1
	future.SHA256 = Digest(future)
	if err := CheckStored(future); !errors.Is(err, ErrVersion) || errors.Is(err, ErrMismatch) {
		t.Fatalf("a future version: %v; want ErrVersion alone", err)
	}
	if _, err := readable(2, true); !errors.Is(err, ErrVersion) {
		t.Fatalf("a live answer at version 2: %v", err)
	}
	if _, err := readable(2, false); err != nil {
		t.Fatalf("a stored version 2 record: %v", err)
	}
}

// A version may state only what its digest covers: a version 1 record naming software,
// or a version 2 record naming an instance, would carry evidence nothing signed.
func TestOlderVersionsCannotStateFieldsTheyDoNotCover(t *testing.T) {
	for _, tc := range []struct {
		version int
		set     func(*sandbox.RunRecord)
		field   string
	}{
		{1, func(r *sandbox.RunRecord) { r.SoftwareIdentity = "oci-manifest:linux/amd64@sha256:aa" }, "software_identity"},
		{2, func(r *sandbox.RunRecord) { r.Instance = "k8s-pod-uid:6f1c3a52-0d1e-4c4b-9a8e-2f7b9c1d0e11" }, "instance"},
		{3, func(r *sandbox.RunRecord) { r.Instance = "k8s-pod-uid:6f1c3a52-0d1e-4c4b-9a8e-2f7b9c1d0e11" }, "instance"},
		{4, func(r *sandbox.RunRecord) { r.IsolationQualification = "Microsoft states." }, "isolation_qualification"},
		{4, func(r *sandbox.RunRecord) { r.Warm = true }, "warm"},
		{4, func(r *sandbox.RunRecord) { r.DaemonVersion = "v0.27.1" }, "daemon_version"},
	} {
		r := goldenRecord()
		r.Version, r.Instance, r.SoftwareIdentity, r.SoftwareRuleID = tc.version, "", "", ""
		r.IsolationQualification, r.Warm, r.DaemonVersion = "", false, ""
		if tc.version == 3 {
			r.ResultSHA256, r.Unanswered = "", "unavailable"
		}
		tc.set(&r)
		r.SHA256 = Digest(r)
		if err := CheckStored(r); !errors.Is(err, ErrMismatch) {
			t.Errorf("a version %d record stating %s: %v; want ErrMismatch", tc.version, tc.field, err)
		}
	}
	// A version 2 record of an unanswered call, or a version 3 record of an answered one,
	// is a kind its version never recorded.
	answered := goldenRecord()
	answered.Version, answered.Instance = 3, ""
	answered.IsolationQualification, answered.DaemonVersion = "", ""
	answered.SHA256 = Digest(answered)
	if err := CheckStored(answered); !errors.Is(err, ErrMismatch) {
		t.Errorf("a version 3 record of an answered call: %v", err)
	}
}

// retiredWhy is the why golden.json's refused records state when a retired reading refuses
// them (record_v5.py copies them from testdata/retired).
const retiredWhy = "retired by the decision of 2026-11-21"

// Daemons v0.10.0 to v0.12.0 stamped both times from the wall clock and could write a
// genuine version 1 or 2 record that ends before it starts; reading one was retired by the
// decision of 2026-11-21 (finding t6-core-1). The frozen records of
// testdata/retired/clock-step-v1-v2.json, each ending 1.3 s before it starts, are refused
// as ErrMismatch and ErrRetired with the retirement's text. The same record at every later
// version is refused with the ordinary text, never as retired; ending as it starts, it
// passes at every version.
func TestRetiredWallClockRecordsAreRefusedAsRetired(t *testing.T) {
	b, err := os.ReadFile("testdata/retired/clock-step-v1-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, r := range g.Records {
		m := &plimsollv1.RunRecord{}
		mustDecode(t, "clock-step", r.Name, r.Record, m)
		rec := FromWire(m)
		rec.SHA256 = r.SHA256
		if !rec.Ended.Before(rec.Started) || rec.Version > LastWallClockEndVersion {
			t.Fatalf("%s: version %d from %v to %v; the file holds wall-clock versions that end before they start", r.Name, rec.Version, rec.Started, rec.Ended)
		}
		if Digest(rec) != r.SHA256 {
			t.Fatalf("%s: digest %s, the file states %s", r.Name, Digest(rec), r.SHA256)
		}
		err := CheckStored(rec)
		if !errors.Is(err, ErrMismatch) || !errors.Is(err, ErrRetired) || err.Error() != "record: "+RetiredEndBeforeStartText {
			t.Errorf("%s: %v; want the retirement's refusal", r.Name, err)
		}
		seen[rec.Version] = true
		for v := rec.Version; v <= Version; v++ {
			at := rec
			at.Version = v
			if v == 3 { // version 3 records unanswered calls only
				at.ResultSHA256, at.Unanswered = "", "unavailable"
			}
			at.SHA256 = Digest(at)
			err := CheckStored(at)
			if v > LastWallClockEndVersion && (!errors.Is(err, ErrMismatch) || errors.Is(err, ErrRetired) || !strings.Contains(fmt.Sprint(err), "ends before it starts")) {
				t.Errorf("%s at version %d: %v; want the ordinary refusal", r.Name, v, err)
			}
			at.Ended = at.Started
			at.SHA256 = Digest(at)
			if err := CheckStored(at); err != nil {
				t.Errorf("%s at version %d, ending as it starts: %v", r.Name, v, err)
			}
		}
	}
	for v := 1; v <= LastWallClockEndVersion; v++ {
		if !seen[v] {
			t.Errorf("no frozen version %d record ends before it starts", v)
		}
	}
}
