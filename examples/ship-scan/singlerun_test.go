package main

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The clean call is a single run: its record may state no session fields. The stored check (record.CheckExchange,
// which reads every published record version) leaves those fields to its caller, so the page checks them itself,
// and a published record given a session fails the page's verification for that reason alone.
func TestTheCleanCallsRecordIsASingleRun(t *testing.T) {
	if err := singleRun(&sandbox.RunRecord{Version: 4}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []sandbox.RunRecord{{Session: "s"}, {Sequence: 1}, {PreviousSHA256: "p"}} {
		if err := singleRun(&r); !errors.Is(err, record.ErrMismatch) {
			t.Errorf("%+v: %v, want record.ErrMismatch", r, err)
		}
	}
	ev, ex, err := readPublished(published)
	if err != nil {
		t.Fatal(err)
	}
	var resp plimsollv1.RunResponse
	if err := protojson.Unmarshal(ex.response, &resp); err != nil {
		t.Fatal(err)
	}
	resp.Record = withSession(resp.Record)
	if ex.response, err = protojson.Marshal(&resp); err != nil {
		t.Fatal(err)
	}
	if err := checkEvidence(ev, ex); !errors.Is(err, record.ErrMismatch) || !strings.Contains(err.Error(), "a single run's record carries session fields") {
		t.Errorf("the published clean call given a session: %v; want the single-run refusal", err)
	}
}

// withSession is the record m with a session's fingerprint, its own digest recomputed under its version's rules, so
// it is a record any reader of that version accepts on its own.
func withSession(m *plimsollv1.RunRecord) *plimsollv1.RunRecord {
	r := record.FromWire(m)
	r.Session = strings.Repeat("5", 64)
	r.SHA256 = record.Digest(r)
	return record.ToWire(r)
}
