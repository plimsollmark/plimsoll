package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func newKeyPair(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return NewSigner(key), NewVerifier(pub)
}

// A line of a bundle proves itself alone: its record's signature, its stored bytes
// and its link. What it cannot prove alone is the bundle around it.
func TestVerifyEntryChecksOneLineAlone(t *testing.T) {
	s, v := newKeyPair(t)
	lines := seal(t, s, traced(t, s, "one"), traced(t, s, "two"))
	whole, err := VerifyBundle(lines, v)
	if err != nil || whole.Runs != 2 {
		t.Fatalf("the bundle: %v", err)
	}
	for i := range 2 {
		rec, l, err := VerifyEntry(v, lines[i])
		if err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if l.Index != uint64(i+1) || l.Entry != ContentDigest(lines[i]) {
			t.Fatalf("line %d: link %+v", i+1, l)
		}
		if want, _ := v.Verify(lines[i].Envelope); want.SHA256 != rec.SHA256 {
			t.Fatalf("line %d: record %s, want %s", i+1, rec.SHA256, want.SHA256)
		}
	}
	// The checkpoint is a link alone, not a call.
	if _, _, err := VerifyEntry(v, lines[2]); !errors.Is(err, ErrLink) {
		t.Fatalf("checkpoint: %v", err)
	}
	// A line without its link, a line whose stored bytes were changed under its link,
	// and a line carrying another line's link are not lines of the bundle.
	unlinked := lines[0]
	unlinked.Link = nil
	if _, _, err := VerifyEntry(v, unlinked); !errors.Is(err, ErrLink) {
		t.Fatalf("no link: %v", err)
	}
	changed := lines[0]
	changed.Request = append([]byte(nil), lines[0].Request...)
	changed.Request[len(changed.Request)-1] ^= 1
	if _, _, err := VerifyEntry(v, changed); !errors.Is(err, ErrLink) {
		t.Fatalf("changed bytes: %v", err)
	}
	swapped := lines[0]
	swapped.Link = lines[1].Link
	if _, _, err := VerifyEntry(v, swapped); !errors.Is(err, ErrLink) {
		t.Fatalf("another line's link: %v", err)
	}
	// A record forged under another key fails on the record, with the link kept.
	other, _ := newKeyPair(t)
	forged := tracedAs(t, other, tracedCode("one"), "one")
	forged.Link = lines[0].Link
	if _, _, err := VerifyEntry(v, forged); err == nil {
		t.Fatal("another key's record was accepted")
	}
}
