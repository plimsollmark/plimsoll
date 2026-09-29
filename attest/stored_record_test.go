package attest

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestVerifyBundleChecksTheStoredResponsesRecord: a bundle whose stored response
// carries an edited record (its record_sha256 left alone) must not verify, and a
// replay must refuse it before sending anything, since its baseline would come from
// the edited copy (external review of v0.10.0, finding 4, 2026-09-28).
func TestVerifyBundleChecksTheStoredResponsesRecord(t *testing.T) {
	key := newKey(t)
	s := NewSigner(key)
	v := NewVerifier(key.Public().(ed25519.PublicKey))
	req, resp := exchange("console.log(1)", "1\n", sandbox.RunRecord{})
	e, err := s.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	stored := &plimsollv1.RunResponse{}
	if err := proto.Unmarshal(e.Response, stored); err != nil {
		t.Fatal(err)
	}
	forged := strings.Repeat("0", 64)
	stored.Record.ResultSha256 = forged
	if e.Response, err = proto.Marshal(stored); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle([]Entry{e}, v); err == nil {
		t.Error("VerifyBundle accepted a stored response whose record was edited")
	}
	sent := false
	_, err = Replay(context.Background(), []Entry{e}, v, func(context.Context, *plimsollv1.RunRequest) (*plimsollv1.RunResponse, error) {
		sent = true
		return resp, nil
	})
	if err == nil || sent {
		t.Errorf("Replay sent a run from a bundle that does not verify (err %v)", err)
	}
}
