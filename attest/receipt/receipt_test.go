package receipt_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/attest/receipt"
	"github.com/plimsollmark/plimsoll/attest/tsa/tsatest"
)

var writeExample = flag.Bool("write-example", false, "replace invented receipt examples; emits public keys only")

type world struct {
	policy    receipt.Policy
	evidence  receipt.Receipt
	authority *tsatest.Authority
	signers   []*attest.Signer
}

func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func newWorld(t *testing.T) world {
	t.Helper()
	a := tsatest.New(t)
	digest := sha256.Sum256([]byte("Imaginary widget v1\n"))
	w := world{
		policy:   receipt.Policy{Version: 1, Subject: attest.Subject{Name: "widget.txt", Digest: map[string]string{"sha256": hex.EncodeToString(digest[:])}}},
		evidence: receipt.Receipt{Version: 1}, authority: a,
	}
	for _, name := range []string{"builder", "reviewer"} {
		privatePEM, publicPEM, err := attest.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		key, err := attest.ParsePrivateKey(privatePEM)
		if err != nil {
			t.Fatal(err)
		}
		signer := attest.NewSigner(key)
		w.signers = append(w.signers, signer)
		role := receipt.Role{
			Name: name, PredicateType: "https://example.org/receipt/" + name + "/v1",
			PublicKeyPEM: string(publicPEM), TimestampRootsPEM: string(a.RootPEM),
		}
		w.policy.Roles = append(w.policy.Roles, role)
		w.evidence.Endorsements = append(w.evidence.Endorsements, receipt.Endorsement{Role: name})
		w.sign(t, len(w.signers)-1, w.policy.Subject, role.PredicateType)
	}
	return w
}

func (w *world) sign(t *testing.T, index int, subject attest.Subject, predicateType string) {
	t.Helper()
	env, err := w.signers[index].SignStatement(predicateType, []attest.Subject{subject}, map[string]any{"result": "pass", "example_only": true})
	if err != nil {
		t.Fatal(err)
	}
	w.evidence.Endorsements[index].Envelope = encoded(t, env)
	w.stamp(t, index, w.evidence.Endorsements[index].Envelope)
}

func (w *world) stamp(t *testing.T, index int, content []byte) {
	t.Helper()
	digest := sha256.Sum256(content)
	token, err := w.authority.Issue(digest[:], nil, big.NewInt(int64(index+1)), time.Date(2026, 10, 23, 20, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	w.evidence.Endorsements[index].Timestamp = token
}

func TestPolicyAndEvidenceBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *world)
		want   string
	}{
		{"valid", func(*testing.T, *world) {}, ""},
		{"wrong artifact", func(t *testing.T, w *world) { w.policy.Subject.Digest["sha256"] = strings.Repeat("0", 64) }, "expected subject"},
		{"wrong name", func(t *testing.T, w *world) { w.policy.Subject.Name = "other.txt" }, "expected subject"},
		{"wrong type", func(t *testing.T, w *world) { w.policy.Roles[0].PredicateType += "/other" }, "predicate type"},
		{"invalid type URI", func(t *testing.T, w *world) { w.policy.Roles[0].PredicateType = "relative-type" }, "assertion type"},
		{"substituted key", func(t *testing.T, w *world) {
			other := newWorld(t)
			w.policy.Roles[0].PublicKeyPEM = other.policy.Roles[0].PublicKeyPEM
		}, "signature"},
		{"substituted root", func(t *testing.T, w *world) { w.policy.Roles[0].TimestampRootsPEM = string(tsatest.New(t).RootPEM) }, "pinned root"},
		{"missing root", func(t *testing.T, w *world) { w.policy.Roles[0].TimestampRootsPEM = "" }, "no certificate"},
		{"missing role", func(t *testing.T, w *world) { w.evidence.Endorsements = w.evidence.Endorsements[:1] }, "exactly one"},
		{"extra role", func(t *testing.T, w *world) {
			w.evidence.Endorsements = append(w.evidence.Endorsements, w.evidence.Endorsements[0])
		}, "exactly one"},
		{"duplicate role", func(t *testing.T, w *world) { w.evidence.Endorsements[1].Role = "builder" }, "repeated endorsement"},
		{"unknown role", func(t *testing.T, w *world) { w.evidence.Endorsements[1].Role = "stranger" }, "missing endorsement"},
		{"duplicate policy role", func(t *testing.T, w *world) { w.policy.Roles[1].Name = "builder" }, "repeated policy role"},
		{"no roles", func(t *testing.T, w *world) {
			w.policy.Roles = []receipt.Role{}
			w.evidence.Endorsements = []receipt.Endorsement{}
		}, "1 to 8"},
		{"wrong version", func(t *testing.T, w *world) { w.evidence.Version = 2 }, "versions must be 1"},
		{"reformatted envelope", func(t *testing.T, w *world) {
			w.evidence.Endorsements[0].Envelope = append(w.evidence.Endorsements[0].Envelope, ' ')
		}, "another digest"},
		{"unsigned payload timestamp", func(t *testing.T, w *world) {
			var env attest.Envelope
			if err := json.Unmarshal(w.evidence.Endorsements[0].Envelope, &env); err != nil {
				t.Fatal(err)
			}
			payload, err := base64.StdEncoding.DecodeString(env.Payload)
			if err != nil {
				t.Fatal(err)
			}
			w.stamp(t, 0, payload)
		}, "another digest"},
		{"signature changed", func(t *testing.T, w *world) {
			var env attest.Envelope
			_ = json.Unmarshal(w.evidence.Endorsements[0].Envelope, &env)
			sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
			if err != nil {
				t.Fatal(err)
			}
			sig[0] ^= 1
			env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
			w.evidence.Endorsements[0].Envelope = encoded(t, env)
			w.stamp(t, 0, w.evidence.Endorsements[0].Envelope)
		}, "signature"},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := newWorld(t)
			test.mutate(t, &w)
			report, err := receipt.Verify(encoded(t, w.evidence), encoded(t, w.policy))
			if test.want == "" {
				if err != nil || len(report.Assertions) != 2 || report.DistinctSigningKeys != 2 {
					t.Fatalf("%+v, %v", report, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.want) || len(report.Assertions) != 0 {
				t.Fatalf("want %q and no partial report, got %+v, %v", test.want, report, err)
			}
		})
	}
}

func TestSameKeyIsOnlyAKeyObservation(t *testing.T) {
	w := newWorld(t)
	w.signers[1] = w.signers[0]
	w.policy.Roles[1].PublicKeyPEM = w.policy.Roles[0].PublicKeyPEM
	w.sign(t, 1, w.policy.Subject, w.policy.Roles[1].PredicateType)
	report, err := receipt.Verify(encoded(t, w.evidence), encoded(t, w.policy))
	if err != nil || report.DistinctSigningKeys != 1 {
		t.Fatalf("%+v, %v", report, err)
	}
}

func TestSignedScalarIsNotAStatementPredicateObject(t *testing.T) {
	w := newWorld(t)
	env, err := w.signers[0].SignStatement(w.policy.Roles[0].PredicateType, []attest.Subject{w.policy.Subject}, true)
	if err != nil {
		t.Fatal(err)
	}
	w.evidence.Endorsements[0].Envelope = encoded(t, env)
	w.stamp(t, 0, w.evidence.Endorsements[0].Envelope)
	if _, err := receipt.Verify(encoded(t, w.evidence), encoded(t, w.policy)); err == nil || !strings.Contains(err.Error(), "JSON object") {
		t.Fatalf("scalar predicate: %v", err)
	}
}

func TestMalformedSchemas(t *testing.T) {
	w := newWorld(t)
	good, policy := encoded(t, w.evidence), encoded(t, w.policy)
	array := make([]int, len(w.evidence.Endorsements[0].Envelope))
	for i, b := range w.evidence.Endorsements[0].Envelope {
		array[i] = int(b)
	}
	arrayJSON := encoded(t, array)
	arrayEnvelope := bytes.Replace(good, []byte(`"envelope": "`+base64.StdEncoding.EncodeToString(w.evidence.Endorsements[0].Envelope)+`"`), append([]byte(`"envelope": `), bytes.TrimSpace(arrayJSON)...), 1)
	for name, bad := range map[string][]byte{
		"array instead of base64": arrayEnvelope,
		"duplicate":               bytes.Replace(good, []byte(`"version": 1`), []byte(`"version": 1, "version": 1`), 1),
		"case alias":              bytes.Replace(good, []byte(`"version"`), []byte(`"Version"`), 1),
		"unknown":                 bytes.Replace(good, []byte(`"version": 1`), []byte(`"version": 1, "trusted_roots": []`), 1),
		"nested duplicate":        bytes.Replace(good, []byte(`"role": "builder"`), []byte(`"role": "builder", "role": "reviewer"`), 1),
		"trailing":                append(bytes.Clone(good), []byte("{}")...),
		"null":                    []byte("null"),
		"huge":                    bytes.Repeat([]byte(" "), receipt.MaxBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := receipt.Verify(bad, policy); err == nil {
				t.Fatal("accepted malformed evidence")
			}
		})
	}
	for name, bad := range map[string][]byte{
		"subject alias":    bytes.Replace(policy, []byte(`"name": "widget.txt"`), []byte(`"Name": "widget.txt"`), 1),
		"role alias":       bytes.Replace(policy, []byte(`"public_key_pem"`), []byte(`"Public_Key_Pem"`), 1),
		"duplicate digest": bytes.Replace(policy, []byte(`"sha256":`), []byte(`"sha256": "`+strings.Repeat("0", 64)+`", "sha256":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := receipt.Verify(good, bad); err == nil {
				t.Fatal("accepted malformed policy")
			}
		})
	}
}

func TestInventedExample(t *testing.T) {
	if *writeExample {
		w := newWorld(t)
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string][]byte{
			"policy.json": encoded(t, w.policy), "valid.json": encoded(t, w.evidence), "widget.txt": []byte("Imaginary widget v1\n"),
		} {
			if err := os.WriteFile(filepath.Join("testdata", name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		w.evidence.Endorsements[0].Envelope = append(w.evidence.Endorsements[0].Envelope, ' ')
		if err := os.WriteFile("testdata/changed-envelope.json", encoded(t, w.evidence), 0o644); err != nil {
			t.Fatal(err)
		}
		w = newWorld(t)
		if err := os.WriteFile("testdata/untrusted-policy.json", encoded(t, w.policy), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	policy, good := read("policy.json"), read("valid.json")
	if _, err := receipt.Verify(good, policy); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ evidence, policy string }{
		{"changed-envelope.json", "policy.json"}, {"valid.json", "untrusted-policy.json"},
	} {
		if _, err := receipt.Verify(read(test.evidence), read(test.policy)); err == nil {
			t.Fatalf("accepted %s with %s", test.evidence, test.policy)
		}
	}
}

func FuzzVerify(f *testing.F) {
	good, err := os.ReadFile("testdata/valid.json")
	if err != nil {
		f.Fatal(err)
	}
	policy, err := os.ReadFile("testdata/policy.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"version":1,"endorsements":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = receipt.Verify(raw, policy) })
}
