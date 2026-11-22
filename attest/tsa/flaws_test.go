package tsa_test

import (
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/attest/tsa"
	"github.com/plimsollmark/plimsoll/attest/tsa/tsatest"
)

// Each token here is signed over its one defect by an authority whose root is pinned, so
// only the check for that defect refuses it. These are the one tests of five checks no
// other test missed when it was deleted (hunt-quality-29).
func TestFlawedTokensAreRefused(t *testing.T) {
	digest := sha256.Sum256([]byte("flawed"))
	req, err := tsa.NewRequest(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	at := func() time.Time { return time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC) }
	// The ordinary token of the same authority verifies, so each refusal below is its flaw's.
	plain := tsatest.New(t)
	plain.Now = at
	resp, err := plain.Respond(req.DER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tsa.Verify(resp, digest[:], req.Nonce, []*x509.Certificate{plain.Root}); err != nil {
		t.Fatalf("an ordinary token: %v", err)
	}
	for _, c := range []struct {
		name string
		opt  tsatest.Option
		want string
	}{
		// RFC 3161 section 2.3: the time-stamping purpose is a critical extension.
		{"an extended key usage not marked critical", tsatest.WithNonCriticalPurpose(), "not marked critical"},
		// RFC 3161 section 2.4.1: the signing-certificate attribute ties the token to the
		// certificate that signed it.
		{"no signing-certificate attribute", tsatest.WithFlaw(tsatest.NoSigningCertificate), "no signing-certificate attribute"},
		{"a signing-certificate attribute naming another certificate", tsatest.WithFlaw(tsatest.WrongSigningCertificate), "names another certificate"},
		// The decoder would skip an accuracy written after the nonce, so the order is checked.
		{"TSTInfo fields out of order", tsatest.WithFlaw(tsatest.NonceBeforeAccuracy), "unsupported or repeated TSTInfo field"},
		{"a second digest algorithm", tsatest.WithFlaw(tsatest.TwoDigestAlgorithms), "one digest algorithm"},
		{"a signer version that disagrees with its identifier", tsatest.WithFlaw(tsatest.SignerVersionThree), "signer version or identifier"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := tsatest.New(t, c.opt)
			a.Now = at
			resp, err := a.Respond(req.DER)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tsa.Verify(resp, digest[:], req.Nonce, []*x509.Certificate{a.Root}); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want an error naming %q", err, c.want)
			}
		})
	}
}
