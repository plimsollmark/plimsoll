package agentsandbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Each pod's own key, and the channel bound to the pod plimsolld read: what keeps one
// caller's run out of another pod of the deployment.

// A connection meant for pod B that reaches pod A, which holds a valid certificate of its
// own from the same issuer, is refused in the handshake: not dispatched, nothing reached
// either sandboxd, and A's terminator completed no handshake and passed on no byte. This
// is the redirect a party on the pod network who owns pod A could make. On the code that
// served one certificate to every pod (one fixed name, no identity) it ran B's code in A.
func TestARedirectToAnotherPodIsRefusedBeforeAnyByte(t *testing.T) {
	p, api, sd := testProvider(t)
	ctx := context.Background()
	if err := p.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := p.claimSandbox(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Every address but A's now reaches A's terminator, as a rewritten route would.
	p.dialAddr = func(ip string) string { return sd.addr(a.ip) }
	_, err = p.RunJavaScript(ctx, sandbox.Request{Code: "1"})
	if refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "another pod's") {
		t.Fatalf("err %v, want the redirect refused for the environment as another pod's certificate", err)
	}
	front := sd.front(a.ip)
	sd.mu.Lock()
	starts, checks := len(sd.starts), sd.tierChecks
	sd.mu.Unlock()
	if sd.reached.Load() != 0 || starts != 0 || checks != 0 || front.handshakes.Load() != 0 || front.bytes.Load() != 0 {
		t.Fatalf("%d requests reached sandboxd (%d starts, %d tier checks); A's terminator completed %d handshakes and passed %d bytes",
			sd.reached.Load(), starts, checks, front.handshakes.Load(), front.bytes.Load())
	}
	api.mu.Lock()
	made := len(api.created)
	api.mu.Unlock()
	if made != 2 {
		t.Fatalf("%d claims made, want A's and B's", made)
	}
	p.deleteLater(ctx, a)
	drained(t, p)
}

// A pod deleted and made again under the same name has a new UID, and a certificate with
// it; plimsolld, which read the earlier pod's UID, refuses it. The warm pool does refill
// under the same names (measured on kind, 2026-11-24), so a name-only identity would let the
// replacement pass for the pod read.
func TestAReplacementPodUnderTheSameNameIsRefused(t *testing.T) {
	p, api, sd := testProvider(t)
	pki := newTestPKI(t)
	p.pool = x509.NewCertPool()
	p.pool.AddCert(pki.ca)
	sd.certAt = func(ip string) (*tls.Certificate, error) {
		name, _, _ := api.podAt(ip)
		cert := pki.podCert(t, DefaultServerName, podIdentity(fakeTrustDomain, "default", name, "a1b2c3d4-0000-4000-8000-00000000beef"))
		return &cert, nil
	}
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "another pod's") || sd.reached.Load() != 0 {
		t.Fatalf("err %v, %d requests reached sandboxd; want the replacement refused before any", err, sd.reached.Load())
	}
	drained(t, p)
}

// Each claim has a channel of its own, closed at its release: two runs in a row at one
// address (a pod deleted and its address given to the next) each meet the pod they read,
// and the first run's connection is closed when its claim is released. A client shared
// by every claim pools connections by address, and a connection checked at its handshake
// for the first pod would carry the second run's token and code.
func TestAPooledConnectionNeverCarriesALaterClaim(t *testing.T) {
	p, api, sd := testProvider(t)
	api.ipFor = func(int) string { return fakePodIP }
	ctx := context.Background()
	for run := 1; run <= 2; run++ {
		if _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		drained(t, p)
		// The release closes the connection at once; the poll's 5 seconds only bound
		// scheduling, and are far below the transport's 30 second idle timeout, which
		// would close it with no release at all.
		front := sd.front(fakePodIP)
		deadline := time.Now().Add(5 * time.Second)
		for front.open.Load() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if n := front.open.Load(); n != 0 {
			t.Fatalf("run %d: %d connections to the pod still open after its claim was released", run, n)
		}
	}
	sd.mu.Lock()
	served := append([]string(nil), sd.served...)
	sd.mu.Unlock()
	api.mu.Lock()
	first, second := api.created[0].Meta.Name, api.created[1].Meta.Name
	api.mu.Unlock()
	want := []string{
		podIdentity(fakeTrustDomain, "default", "sb-"+first, "pod-uid-"+first), podIdentity(fakeTrustDomain, "default", "sb-"+first, "pod-uid-"+first),
		podIdentity(fakeTrustDomain, "default", "sb-"+second, "pod-uid-"+second), podIdentity(fakeTrustDomain, "default", "sb-"+second, "pod-uid-"+second),
	}
	if strings.Join(served, " ") != strings.Join(want, " ") {
		t.Fatalf("the process starts went over connections whose certificates named %q, want each run's own pod (its tier check and its command): %q", served, want)
	}
}

// The key volume's attributes are a closed list: the measured set, in any order of the
// usages, passes; each attribute that would undo the pod's own key is refused with its
// reason, an unknown one is refused, and each required one must be set to its value.
func TestKeyVolumeAttributesAreClosed(t *testing.T) {
	p, _, _ := testProvider(t)
	check := func(edit func(map[string]string)) error {
		attrs := keyAttributes()
		edit(attrs)
		return p.checkKeyAttributes(keyVolume{Volume: "sandboxd-tls", Driver: keyDriver, Attributes: attrs})
	}
	for name, edit := range map[string]func(map[string]string){
		"as measured":             func(map[string]string) {},
		"no lifetime":             func(a map[string]string) { delete(a, keyAttr+"duration") },
		"usages in another order": func(a map[string]string) { a[keyAttr+"key-usages"] = "digital signature, server auth" },
		"an issuer group":         func(a map[string]string) { a[keyAttr+"issuer-group"] = "awspca.cert-manager.io" },
	} {
		if err := check(edit); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for attr := range refusedKeyAttrs {
		if err := check(func(a map[string]string) { a[keyAttr+attr] = "true" }); err == nil || !strings.Contains(err.Error(), "which is refused") {
			t.Errorf("%s: %v, want it refused with its reason", attr, err)
		}
	}
	for _, attr := range requiredKeyAttrs {
		if err := check(func(a map[string]string) { delete(a, keyAttr+attr) }); err == nil || !strings.Contains(err.Error(), "does not set") {
			t.Errorf("%s unset: %v", attr, err)
		}
	}
	for name, c := range map[string]struct {
		edit func(map[string]string)
		want string
	}{
		"an unknown attribute":       {func(a map[string]string) { a[keyAttr+"renew-before"] = "1h" }, "does not accept"},
		"another driver's attribute": {func(a map[string]string) { a["csi.storage.k8s.io/pod.name"] = "x" }, "outside"},
		"RSA":                        {func(a map[string]string) { a[keyAttr+"key-algorithm"] = "RSA" }, "want"},
		"P-384":                      {func(a map[string]string) { a[keyAttr+"key-size"] = "384" }, "want"},
		"PKCS#1":                     {func(a map[string]string) { a[keyAttr+"key-encoding"] = "PKCS1" }, "want"},
		"no server auth":             {func(a map[string]string) { a[keyAttr+"key-usages"] = "digital signature" }, "want exactly"},
		"a further usage":            {func(a map[string]string) { a[keyAttr+"key-usages"] = "server auth,digital signature,client auth" }, "want exactly"},
		"another DNS name":           {func(a map[string]string) { a[keyAttr+"dns-names"] = "sandboxd.example.test" }, "want"},
		"a varying DNS name":         {func(a map[string]string) { a[keyAttr+"dns-names"] = "${POD_NAME}.plimsoll.invalid" }, "want"},
		"two DNS names":              {func(a map[string]string) { a[keyAttr+"dns-names"] = DefaultServerName + ",other.invalid" }, "want"},
		"an identity with no UID": {func(a map[string]string) {
			a[keyAttr+"uri-sans"] = "spiffe://plimsoll.test/ns/${POD_NAMESPACE}/pod/${POD_NAME}"
		}, "want"},
		"another trust domain":        {func(a map[string]string) { a[keyAttr+"uri-sans"] = identityTemplate("other.test") }, "want"},
		"a second URI":                {func(a map[string]string) { a[keyAttr+"uri-sans"] += ",spiffe://plimsoll.test/x" }, "want"},
		"another issuer kind":         {func(a map[string]string) { a[keyAttr+"issuer-kind"] = "Vault" }, "only a namespaced Issuer"},
		"a cluster issuer":            {func(a map[string]string) { a[keyAttr+"issuer-kind"] = "ClusterIssuer" }, "signs for pods in every namespace"},
		"an issuer that is no name":   {func(a map[string]string) { a[keyAttr+"issuer-name"] = "Plimsoll CA" }, "not a name"},
		"a lifetime that is no time":  {func(a map[string]string) { a[keyAttr+"duration"] = "a month" }, "positive duration"},
		"a lifetime already past due": {func(a map[string]string) { a[keyAttr+"duration"] = "-1h" }, "positive duration"},
	} {
		if err := check(c.edit); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// A template whose key volume asks for a refused attribute fails Preflight, so readiness,
// before any claim; a pod admitted with one is refused before any code.
func TestARefusedKeyAttributeFailsTheTemplateAndThePod(t *testing.T) {
	p, api, sd := testProvider(t)
	api.tmplHook = func(s *podSpec) {
		attrs := keyAttributes()
		attrs[keyAttr+"fs-group"] = "61000"
		s.Volumes[1]["csi"] = keySource(attrs)
	}
	if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "fs-group") {
		t.Fatalf("Preflight: %v, want the fs-group refusal", err)
	}
	api.mu.Lock()
	api.tmplHook = nil
	api.podHook = func(pd *pod) { keyAttrs(pd, func(a map[string]string) { a[keyAttr+"reuse-private-key"] = "true" }) }
	api.mu.Unlock()
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "reuse-private-key") || sd.reached.Load() != 0 {
		t.Fatalf("err %v, %d requests reached sandboxd", err, sd.reached.Load())
	}
	drained(t, p)
}

// The 0440 key the driver writes is safe only while no guest process holds group 0, so
// the smoke test fails a guest that holds it (or any group), as setpriv's --clear-groups
// should leave none.
func TestTheSmokeTestFailsAGuestHoldingGroupZero(t *testing.T) {
	for _, groups := range []string{"0", "0 1 2 3 4 6 10 11 20 26 27", "61000"} {
		p, _, sd := testProvider(t)
		fakeSmoke(t, p, sd, func(r *boundaryReport) { r.Groups = groups })
		if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), "groups") {
			t.Errorf("groups %q: %v, want the smoke test failed", groups, err)
		}
		drained(t, p)
	}
}

// The trust domain is required and a DNS name.
func TestTheTrustDomainIsRequired(t *testing.T) {
	for _, td := range []string{"", "Plimsoll.Test", "10.0.0.1", "a/b", "plimsoll.test/ns"} {
		cfg := Config{APIServer: "https://k8s.test", CAFile: "ca", TokenFile: "t", Namespace: "default", WarmPool: "pool",
			RuntimeClass: "gvisor", Image: fakeImage, SandboxdToken: fakeToken, SandboxdCAFile: "ca", SandboxdTrustDomain: td}
		if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "trust domain") {
			t.Errorf("trust domain %q: %v", td, err)
		}
	}
}
