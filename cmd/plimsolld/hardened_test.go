package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// hardenedEnv is a compliant docker deployment; tests break one property at a
// time and assert that exact violation (and only that one) is reported.
func hardenedEnv() map[string]string {
	return map[string]string{
		"SANDBOX_REQUIRE_PINNED_IMAGES": "1",
		"SANDBOX_MEMORY_MB":             "256",
		"SANDBOX_CPUS":                  "1",
		"SANDBOX_PIDS":                  "128",
		"SANDBOX_DISK_MB":               "160",
		"SANDBOX_TOTAL_MEMORY_MB":       "2048",
	}
}

func hardenedDockerFacts() hardenedFacts {
	return hardenedFacts{
		Provider:        "docker",
		Isolation:       sandbox.IsolationKernel,
		MultiClientAuth: true,
		TLS:             true,
		Addr:            ":8746",
		RatePerMin:      30,
	}
}

func getenvFrom(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func TestHardenedPolicyAcceptsCompliantDeployments(t *testing.T) {
	if err := enforceHardenedPolicy(getenvFrom(hardenedEnv()), hardenedDockerFacts()); err != nil {
		t.Fatalf("compliant docker deployment rejected: %v", err)
	}
	// E2B: vm isolation, explicit template, no pids/total-memory requirement
	// (runners live off-host and e2b rejects a pids cap).
	e2bEnv := map[string]string{
		"E2B_TEMPLATE":      "plimsoll-toolchain",
		"SANDBOX_MEMORY_MB": "1024",
		"SANDBOX_CPUS":      "2",
		"SANDBOX_DISK_MB":   "2048",
	}
	f := hardenedDockerFacts()
	f.Provider, f.Isolation = "e2b", sandbox.IsolationVM
	if err := enforceHardenedPolicy(getenvFrom(e2bEnv), f); err != nil {
		t.Fatalf("compliant e2b deployment rejected: %v", err)
	}
	// Cleartext is acceptable only on an exact-loopback listener.
	f2 := hardenedDockerFacts()
	f2.TLS, f2.Addr = false, "127.0.0.1:8746"
	if err := enforceHardenedPolicy(getenvFrom(hardenedEnv()), f2); err != nil {
		t.Fatalf("loopback cleartext deployment rejected: %v", err)
	}
}

func TestHardenedPolicyFailsClosedPerViolation(t *testing.T) {
	cases := []struct {
		name    string
		env     func(map[string]string)
		facts   func(*hardenedFacts)
		wantErr string
	}{
		{"runc container tier", nil, func(f *hardenedFacts) { f.Isolation = sandbox.IsolationContainer }, "requires vm"},
		{"process tier", nil, func(f *hardenedFacts) { f.Provider, f.Isolation = "wasm", sandbox.IsolationProcess }, "requires vm"},
		{"disabled provider", nil, func(f *hardenedFacts) { f.Provider, f.Isolation = "disabled", sandbox.IsolationNone }, "requires vm"},
		{"shared-token auth", nil, func(f *hardenedFacts) { f.MultiClientAuth = false }, "multi-client auth"},
		{"insecure override", func(e map[string]string) { e["PLIMSOLL_INSECURE"] = "1" }, nil, "PLIMSOLL_INSECURE"},
		{"cleartext off loopback", nil, func(f *hardenedFacts) { f.TLS = false }, "requires TLS"},
		{"cleartext on all interfaces", nil, func(f *hardenedFacts) { f.TLS, f.Addr = false, ":8746" }, "requires TLS"},
		{"unpinned images", func(e map[string]string) { e["SANDBOX_REQUIRE_PINNED_IMAGES"] = "" }, nil, "SANDBOX_REQUIRE_PINNED_IMAGES"},
		{"malformed pin flag", func(e map[string]string) { e["SANDBOX_REQUIRE_PINNED_IMAGES"] = "yes" }, nil, "SANDBOX_REQUIRE_PINNED_IMAGES"},
		{"seccomp unconfined", func(e map[string]string) { e["SANDBOX_DOCKER_SECCOMP"] = "unconfined" }, nil, "unconfined"},
		{"missing memory budget", func(e map[string]string) { delete(e, "SANDBOX_MEMORY_MB") }, nil, "SANDBOX_MEMORY_MB"},
		{"zero memory budget", func(e map[string]string) { e["SANDBOX_MEMORY_MB"] = "0" }, nil, "SANDBOX_MEMORY_MB must be greater than zero"},
		{"zero cpus", func(e map[string]string) { e["SANDBOX_CPUS"] = "0" }, nil, "SANDBOX_CPUS must be greater than zero"},
		{"non-numeric cpus", func(e map[string]string) { e["SANDBOX_CPUS"] = "lots" }, nil, "SANDBOX_CPUS must be greater than zero"},
		{"missing pids budget", func(e map[string]string) { delete(e, "SANDBOX_PIDS") }, nil, "SANDBOX_PIDS"},
		{"missing aggregate budget", func(e map[string]string) { delete(e, "SANDBOX_TOTAL_MEMORY_MB") }, nil, "SANDBOX_TOTAL_MEMORY_MB"},
		{"rate limiting disabled", nil, func(f *hardenedFacts) { f.RatePerMin = 0 }, "SANDBOX_RATE_PER_MIN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := hardenedEnv()
			if tc.env != nil {
				tc.env(env)
			}
			facts := hardenedDockerFacts()
			if tc.facts != nil {
				tc.facts(&facts)
			}
			err := enforceHardenedPolicy(getenvFrom(env), facts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want a violation mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestHardenedPolicyRequiresExplicitE2BTemplate(t *testing.T) {
	f := hardenedDockerFacts()
	f.Provider, f.Isolation = "e2b", sandbox.IsolationVM
	env := map[string]string{"SANDBOX_MEMORY_MB": "1024", "SANDBOX_CPUS": "2", "SANDBOX_DISK_MB": "2048"}
	err := enforceHardenedPolicy(getenvFrom(env), f)
	if err == nil || !strings.Contains(err.Error(), "E2B_TEMPLATE") {
		t.Fatalf("err = %v, want an explicit-template violation", err)
	}
}

// TestHardenedPolicyDockerCloud: a pinned image is required, and the envelope is
// memory and CPU only, because Build rejects SANDBOX_DISK_MB for dockercloud and a
// policy demanding it could never be satisfied.
func TestHardenedPolicyDockerCloud(t *testing.T) {
	f := hardenedDockerFacts()
	f.Provider, f.Isolation = "dockercloud", sandbox.IsolationVM
	env := map[string]string{"SANDBOX_MEMORY_MB": "1024", "SANDBOX_CPUS": "2", "SANDBOX_REQUIRE_PINNED_IMAGES": "1"}
	if err := enforceHardenedPolicy(getenvFrom(env), f); err != nil {
		t.Fatalf("compliant dockercloud deployment rejected: %v", err)
	}
	delete(env, "SANDBOX_REQUIRE_PINNED_IMAGES")
	err := enforceHardenedPolicy(getenvFrom(env), f)
	if err == nil || !strings.Contains(err.Error(), "SANDBOX_REQUIRE_PINNED_IMAGES") {
		t.Fatalf("err = %v, want a pinned-image violation", err)
	}
}

// TestHardenedPolicyReportsAllViolationsAtOnce verifies the operator gets the
// whole fix list in one startup failure, not one violation per restart.
func TestHardenedPolicyReportsAllViolationsAtOnce(t *testing.T) {
	f := hardenedFacts{Provider: "docker", Isolation: sandbox.IsolationContainer, Addr: ":8746"}
	err := enforceHardenedPolicy(getenvFrom(map[string]string{}), f)
	if err == nil {
		t.Fatal("fully non-compliant deployment passed")
	}
	for _, want := range []string{"requires vm", "multi-client auth", "requires TLS", "SANDBOX_REQUIRE_PINNED_IMAGES", "SANDBOX_MEMORY_MB", "SANDBOX_RATE_PER_MIN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined violations missing %q: %v", want, err)
		}
	}
}

func TestLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8746": true,
		"[::1]:8746":     true,
		"localhost:8746": true,
		":8746":          false,
		"0.0.0.0:8746":   false,
		"10.0.0.5:8746":  false,
		"example.com:1":  false,
		"127.0.0.1":      false, // no port = not a valid listen addr; fail closed
	} {
		if got := loopbackAddr(addr); got != want {
			t.Errorf("loopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestTLSConfigFromEnv(t *testing.T) {
	if conf, err := tlsConfigFromEnv(getenvFrom(nil)); err != nil || conf != nil {
		t.Fatalf("unset pair: conf=%v err=%v, want nil/nil (cleartext)", conf, err)
	}
	if _, err := tlsConfigFromEnv(getenvFrom(map[string]string{"PLIMSOLL_TLS_CERT": "/x.pem"})); err == nil {
		t.Fatal("half-configured pair must be a startup error")
	}
	if _, err := tlsConfigFromEnv(getenvFrom(map[string]string{
		"PLIMSOLL_TLS_CERT": "/nonexistent.pem", "PLIMSOLL_TLS_KEY": "/nonexistent.key",
	})); err == nil {
		t.Fatal("unloadable keypair must be a startup error")
	}
	certPath, keyPath := writeSelfSignedPair(t)
	conf, err := tlsConfigFromEnv(getenvFrom(map[string]string{
		"PLIMSOLL_TLS_CERT": certPath, "PLIMSOLL_TLS_KEY": keyPath,
	}))
	if err != nil || conf == nil || len(conf.Certificates) != 1 {
		t.Fatalf("valid pair: conf=%v err=%v", conf, err)
	}
	if conf.MinVersion < 0x0303 { // tls.VersionTLS12
		t.Fatalf("MinVersion = %x, want >= TLS 1.2", conf.MinVersion)
	}
}

// writeSelfSignedPair generates a throwaway self-signed certificate for TLS
// wiring tests.
func writeSelfSignedPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "plimsolld-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
