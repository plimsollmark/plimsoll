package tsa_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/attest/tsa"
	"github.com/plimsollmark/plimsoll/attest/tsa/tsatest"
)

func TestOfflineVerification(t *testing.T) {
	a := tsatest.New(t)
	digest := sha256.Sum256([]byte("invented signed envelope"))
	req, err := tsa.NewRequest(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	response, err := a.Respond(req.DER)
	if err != nil {
		t.Fatal(err)
	}
	roots := []*x509.Certificate{a.Root}
	if _, err := tsa.Verify(response, digest[:], req.Nonce, roots); err != nil {
		t.Fatal(err)
	}
	other := tsatest.New(t)
	for name, check := range map[string]func() error{
		"wrong digest": func() error { _, err := tsa.Verify(response, make([]byte, 32), req.Nonce, roots); return err },
		"wrong nonce":  func() error { _, err := tsa.Verify(response, digest[:], big.NewInt(-1), roots); return err },
		"wrong root": func() error {
			_, err := tsa.Verify(response, digest[:], req.Nonce, []*x509.Certificate{other.Root})
			return err
		},
		"no root": func() error { _, err := tsa.Verify(response, digest[:], req.Nonce, nil); return err },
		"nil root": func() error {
			_, err := tsa.Verify(response, digest[:], req.Nonce, []*x509.Certificate{nil})
			return err
		},
		"oversized": func() error {
			_, err := tsa.Verify(make([]byte, tsa.MaxResponse+1), digest[:], req.Nonce, roots)
			return err
		},
		"trailing": func() error {
			_, err := tsa.Verify(append(bytes.Clone(response), 0), digest[:], req.Nonce, roots)
			return err
		},
		"tampered": func() error {
			b := bytes.Clone(response)
			b[len(b)-1] ^= 1
			_, err := tsa.Verify(b, digest[:], req.Nonce, roots)
			return err
		},
		"no timestamp purpose": func() error {
			plain := tsatest.New(t, tsatest.WithoutTimeStampingPurpose())
			r, err := plain.Respond(req.DER)
			if err != nil {
				return err
			}
			_, err = tsa.Verify(r, digest[:], req.Nonce, []*x509.Certificate{plain.Root})
			return err
		},
		"certificate outside validity": func() error {
			r, err := a.Issue(digest[:], req.Nonce, big.NewInt(1), time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC))
			if err != nil {
				return err
			}
			_, err = tsa.Verify(r, digest[:], req.Nonce, roots)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatal("accepted invalid token")
			}
		})
	}
}

func FuzzTimestampResponse(f *testing.F) {
	// A rejected response and DER-shaped malformed values exercise the outer parser.
	f.Add([]byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02})
	f.Add([]byte{0x30, 0})
	a := tsatest.New(f)
	digest := sha256.Sum256([]byte("fixture"))
	r, err := a.Issue(digest[:], nil, big.NewInt(1), time.Date(2026, 10, 23, 20, 0, 0, 0, time.UTC))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(r)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = tsa.Verify(raw, digest[:], nil, []*x509.Certificate{a.Root}) })
}
