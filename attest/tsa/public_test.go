package tsa_test

import (
	"testing"

	"github.com/plimsollmark/plimsoll/attest/tsa"
)

// The embedded roots are the ones the public authorities are pinned by, and the real
// tokens recorded on 2026-10-21 chain to them.
func TestPublicRootsArePinnedAndWitnessTheRecordedTokens(t *testing.T) {
	roots, err := tsa.ParseRoots(tsa.PublicRootsPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != len(tsa.Public) {
		t.Fatalf("%d roots for %d authorities", len(roots), len(tsa.Public))
	}
	for i, a := range tsa.Public {
		if got := tsa.CertSHA256(roots[i]); got != a.RootSHA256 {
			t.Errorf("%s: embedded root %s, pinned %s", a.Name, got, a.RootSHA256)
		}
	}
	digest, req := fixture(t)
	for i, name := range []string{"digicert", "freetsa"} {
		tok, err := tsa.Verify(read(t, name+".tsr"), digest, req.Nonce, roots)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tok.RootSHA256 != tsa.Public[i].RootSHA256 {
			t.Errorf("%s's token chains to %s, not the pinned root", tsa.Public[i].Name, tok.RootSHA256)
		}
	}
}
