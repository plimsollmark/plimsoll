package record

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
// records of versions 2 and 3.
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
	for _, v := range []int{2, 3} {
		if !versions[v] {
			t.Errorf("no published vector holds a version %d record", v)
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
	} {
		r := goldenRecord()
		r.Version, r.Instance, r.SoftwareIdentity, r.SoftwareRuleID = tc.version, "", "", ""
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
	answered.SHA256 = Digest(answered)
	if err := CheckStored(answered); !errors.Is(err, ErrMismatch) {
		t.Errorf("a version 3 record of an answered call: %v", err)
	}
}
