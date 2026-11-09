package tsa_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/attest/tsa"
	"github.com/plimsollmark/plimsoll/attest/tsa/tsatest"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The fixtures: on 2026-10-21 one request (req.tsq, made by openssl over 32 random bytes)
// went to FreeTSA and to DigiCert; both answered 16:20:11 UTC. The roots are the ones
// each publishes.
func fixture(t *testing.T) (digest []byte, req tsa.Request) {
	t.Helper()
	digest, err := hex.DecodeString(strings.TrimSpace(string(read(t, "message.sha256"))))
	if err != nil {
		t.Fatal(err)
	}
	req, err = tsa.ParseRequest(read(t, "req.tsq"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.Digest, digest) {
		t.Fatal("the recorded request is not over the recorded message")
	}
	return digest, req
}

func TestTheRecordedRealTokensVerify(t *testing.T) {
	digest, req := fixture(t)
	want := time.Date(2026, 10, 21, 16, 20, 11, 0, time.UTC)
	for _, name := range []string{"freetsa", "digicert"} {
		roots, err := tsa.ParseRoots(read(t, name+"-root.pem"))
		if err != nil {
			t.Fatal(err)
		}
		tok, err := tsa.Verify(read(t, name+".tsr"), digest, req.Nonce, roots)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !tok.Time.Equal(want) {
			t.Errorf("%s: time %s, want %s", name, tok.Time, want)
		}
		if tok.RootSHA256 != tsa.CertSHA256(roots[0]) {
			t.Errorf("%s: root %s is not the pinned one", name, tok.RootSHA256)
		}
		if tok.Nonce == nil || tok.Nonce.Cmp(req.Nonce) != 0 {
			t.Errorf("%s: the nonce is not echoed", name)
		}
		t.Logf("%s: %s accuracy %s signer %q policy %v", name, tok.Time.Format(time.RFC3339), tok.Accuracy, tok.Signer.Subject.CommonName, tok.Policy)
	}
}

func TestARealTokenIsRefusedForTheWrongDigestNonceOrRoot(t *testing.T) {
	digest, req := fixture(t)
	freetsa, _ := tsa.ParseRoots(read(t, "freetsa-root.pem"))
	digicert, _ := tsa.ParseRoots(read(t, "digicert-root.pem"))
	token := read(t, "digicert.tsr")
	other := sha256.Sum256([]byte("another message"))
	if _, err := tsa.Verify(token, other[:], req.Nonce, digicert); err == nil || !strings.Contains(err.Error(), "another digest") {
		t.Errorf("wrong digest: %v", err)
	}
	if _, err := tsa.Verify(token, digest, big.NewInt(7), digicert); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Errorf("wrong nonce: %v", err)
	}
	if _, err := tsa.Verify(token, digest, req.Nonce, freetsa); err == nil || !strings.Contains(err.Error(), "pinned root") {
		t.Errorf("wrong root: %v", err)
	}
	if _, err := tsa.Verify(token, digest, nil, digicert); err != nil {
		t.Errorf("no nonce check asked: %v", err)
	}
}

func TestTheTestAuthorityRoundTrips(t *testing.T) {
	a := tsatest.New(t)
	at := time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC)
	a.Now = func() time.Time { return at }
	digest := sha256.Sum256([]byte("terms"))
	req, err := tsa.NewRequest(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := tsa.ParseRequest(req.DER)
	if err != nil || !bytes.Equal(parsed.Digest, digest[:]) || parsed.Nonce.Cmp(req.Nonce) != 0 || !parsed.CertReq {
		t.Fatalf("the request does not read back: %v", err)
	}
	resp, err := a.Respond(req.DER)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := tsa.ParseRoots(a.RootPEM)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tsa.Verify(resp, digest[:], req.Nonce, roots)
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Time.Equal(at) || tok.Accuracy != time.Second || tok.Serial.Int64() != 1 || !tok.Policy.Equal(tsatest.Policy) {
		t.Errorf("token %+v", tok)
	}
	if tok.RootSHA256 != tsa.CertSHA256(a.Root) || tok.Signer.Subject.CommonName != "tsatest time-stamping" {
		t.Errorf("signer %q root %s", tok.Signer.Subject.CommonName, tok.RootSHA256)
	}
}

func TestWitnessOverHTTP(t *testing.T) {
	a := tsatest.New(t)
	s := a.Server(t)
	digest := sha256.Sum256([]byte("receipt"))
	tok, req, resp, err := tsa.Witness(context.Background(), s.Client(), a.Definition(s.URL), digest[:], []*x509.Certificate{a.Root})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tok.Digest, digest[:]) || tok.Nonce.Cmp(req.Nonce) != 0 || len(resp) == 0 {
		t.Error("the witnessed token does not match the request")
	}
	// The pinned root must be the one the token chains to.
	def := a.Definition(s.URL)
	def.RootSHA256 = strings.Repeat("0", 64)
	if _, _, _, err := tsa.Witness(context.Background(), s.Client(), def, digest[:], []*x509.Certificate{a.Root}); err == nil || !strings.Contains(err.Error(), "not the pinned") {
		t.Errorf("another pinned root: %v", err)
	}
}

func TestTamperedTokensAreRefused(t *testing.T) {
	a := tsatest.New(t)
	a.Now = func() time.Time { return time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC) }
	roots := []*x509.Certificate{a.Root}
	digest := sha256.Sum256([]byte("verdict"))
	req, _ := tsa.NewRequest(digest[:])
	resp, err := a.Respond(req.DER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tsa.Verify(resp, digest[:], req.Nonce, roots); err != nil {
		t.Fatal(err)
	}
	t.Run("the time changed inside the token", func(t *testing.T) {
		at := []byte("20261021200000Z")
		i := bytes.Index(resp, at)
		if i < 0 {
			t.Fatal("the time is not in the token")
		}
		bad := bytes.Clone(resp)
		bad[i+13] = '1' // 20:00:00 becomes 20:00:01
		if _, err := tsa.Verify(bad, digest[:], req.Nonce, roots); err == nil || !strings.Contains(err.Error(), "message-digest") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("the signature changed", func(t *testing.T) {
		bad := bytes.Clone(resp)
		bad[len(bad)-1] ^= 1
		if _, err := tsa.Verify(bad, digest[:], req.Nonce, roots); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("another authority's root", func(t *testing.T) {
		other := tsatest.New(t)
		if _, err := tsa.Verify(resp, digest[:], req.Nonce, []*x509.Certificate{other.Root}); err == nil || !strings.Contains(err.Error(), "pinned root") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("a signer without the time-stamping purpose", func(t *testing.T) {
		plain := tsatest.New(t, tsatest.WithoutTimeStampingPurpose())
		resp, err := plain.Respond(req.DER)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tsa.Verify(resp, digest[:], req.Nonce, []*x509.Certificate{plain.Root}); err == nil || !strings.Contains(err.Error(), "extended key usage") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("a token dated before the signer's certificate", func(t *testing.T) {
		early := tsatest.New(t)
		early.Now = func() time.Time { return time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) }
		resp, err := early.Respond(req.DER)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tsa.Verify(resp, digest[:], req.Nonce, []*x509.Certificate{early.Root}); err == nil || !strings.Contains(err.Error(), "at the token's time") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("a refused request", func(t *testing.T) {
		// A response whose status is rejection (2) and no token.
		rejected := []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02}
		if _, err := tsa.Verify(rejected, digest[:], req.Nonce, roots); err == nil || !strings.Contains(err.Error(), "did not grant") {
			t.Errorf("got %v", err)
		}
	})
}

func TestFetchRefusesErrorsAndOversizedAnswers(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	req, _ := tsa.NewRequest(digest[:])
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer failing.Close()
	if _, err := (tsa.Authority{Name: "failing", URL: failing.URL}).Fetch(context.Background(), failing.Client(), req); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("got %v", err)
	}
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, tsa.MaxResponse+1))
	}))
	defer huge.Close()
	if _, err := (tsa.Authority{Name: "huge", URL: huge.URL}).Fetch(context.Background(), huge.Client(), req); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("got %v", err)
	}
}
