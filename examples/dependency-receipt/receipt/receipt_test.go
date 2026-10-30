package receipt

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/runsclog"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The pod each fixture ran in, as its container specs name it.
var pods = map[string]string{
	"quiet":   "865e17cd-82c3-426e-ada8-9ba93016cf9d",
	"builds":  "a364a2f0-dcb9-49e1-badb-e0e73b49853c",
	"canary":  "c84f87fe-f629-416f-8297-516df9c7b30c",
	"network": "3bff5771-e5d0-4bfc-8aa4-9573b428b4a4",
	"child":   "7bae59e4-294f-4742-950a-57ac816de652",
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open("../runsclog/testdata/" + name + ".boot.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newSigner(t *testing.T) (*attest.Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return attest.NewSigner(priv), pub
}

func build(t *testing.T, log []byte, rec *sandbox.RunRecord) (Predicate, []attest.Subject) {
	t.Helper()
	p, subs, err := Build(bytes.NewReader(log), rec)
	if err != nil {
		t.Fatal(err)
	}
	return p, subs
}

// Every fixture makes a receipt that checks against its own log and no other, names its
// pod, and splits the calls into effected and attempted by their result.
func TestFixtures(t *testing.T) {
	signer, pub := newSigner(t)
	logs := map[string][]byte{}
	for name := range pods {
		logs[name] = fixture(t, name)
	}
	for name, uid := range pods {
		p, subs := build(t, logs[name], nil)
		if p.Instance != "k8s-pod-uid:"+uid || p.Run != nil || len(subs) != 1 || subs[0].Name != LogSubject {
			t.Errorf("%s: instance %q, run %+v, subjects %+v", name, p.Instance, p.Run, subs)
		}
		if p.Observer.Runsc != "release-20260907.0" || p.Observer.StraceLogSize != 16 || p.Observer.Network != "sandbox" ||
			len(p.Observer.ConfigurationSHA256) != 64 || p.Log.Bytes != int64(len(logs[name])) || len(p.NotObserved) == 0 {
			t.Errorf("%s: observer %+v, log %+v", name, p.Observer, p.Log)
		}
		// Each call sits on the side its result names, and every call is on one side.
		sides := map[int]Calls{effected: {Opened: p.Effected.Opened, Changes: p.Effected.Changes, Network: p.Effected.Network},
			attempted: p.Attempted, undetermined: p.Undetermined}
		calls := 0
		for side, c := range sides {
			for _, o := range c.Opened {
				if outcome(o.Result) != side {
					t.Errorf("%s: open %+v on side %d", name, o, side)
				}
			}
			for _, x := range c.Changes {
				if outcome(x.Result) != side {
					t.Errorf("%s: change %+v on side %d", name, x, side)
				}
			}
			for _, x := range c.Network {
				if outcome(x.Result) != side {
					t.Errorf("%s: network call %+v on side %d", name, x, side)
				}
			}
			calls += len(c.Opened) + len(c.Changes) + len(c.Network)
		}
		tr, err := runsclog.Read(bytes.NewReader(logs[name]))
		if err != nil {
			t.Fatal(err)
		}
		if calls != len(tr.Opened)+len(tr.Changes)+len(tr.Network) || len(p.Effected.Written) != len(tr.Written) {
			t.Errorf("%s: %d calls on the three sides, the log has %d", name, calls, len(tr.Opened)+len(tr.Changes)+len(tr.Network))
		}
		env, err := Sign(signer, p, subs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Check(env, pub, bytes.NewReader(logs[name]), nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		other := "quiet"
		if name == "quiet" {
			other = "child"
		}
		if _, err := Check(env, pub, bytes.NewReader(logs[other]), nil); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s checked against %s's log: %v", name, other, err)
		}
	}
	// All five ran under one runtime handler, so they share the configuration digest.
	a, _ := build(t, logs["quiet"], nil)
	b, _ := build(t, logs["canary"], nil)
	if a.Observer.ConfigurationSHA256 != b.Observer.ConfigurationSHA256 {
		t.Error("two runs under one handler have different configuration digests")
	}
}

// What the fixture packages did shows on the side it belongs to.
func TestFixtureFacts(t *testing.T) {
	canary, _ := build(t, fixture(t, "canary"), nil)
	var written []string
	for _, w := range canary.Effected.Written {
		written = append(written, w.Path)
	}
	if !slices.ContainsFunc(written, func(p string) bool { return strings.HasPrefix(p, "/etc/") }) ||
		!slices.ContainsFunc(written, func(p string) bool { return strings.HasPrefix(p, "/root/") }) {
		t.Errorf("canary: the writes to /etc through a symlink and to /root are not effected: %v", written)
	}
	if len(canary.Attempted.Opened)+len(canary.Attempted.Changes) == 0 {
		t.Error("canary: its refused write is not attempted")
	}
	// The package's non-blocking connect answered EINPROGRESS: started, outcome out of the
	// log's sight, so undetermined, never "attempted" (which would read as "did not happen").
	network, _ := build(t, fixture(t, "network"), nil)
	if !slices.ContainsFunc(network.Undetermined.Network, func(x runsclog.Net) bool {
		return x.Kind == "connect" && x.Addr == "203.0.113.7" && x.Port == 443
	}) {
		t.Errorf("network: the connection to 203.0.113.7:443 is not undetermined: %+v", network.Undetermined.Network)
	}
	if !slices.ContainsFunc(network.Effected.Network, func(x runsclog.Net) bool { return x.Kind == "send" && x.Port == 53 }) {
		t.Errorf("network: the DNS query is not effected: %+v", network.Effected.Network)
	}
	child, _ := build(t, fixture(t, "child"), nil)
	var started []string
	for _, p := range child.Processes {
		for _, g := range p.Programs {
			started = append(started, g.Path)
		}
	}
	for _, want := range []string{"sh", "id", "uname"} {
		if !slices.ContainsFunc(started, func(p string) bool { return strings.HasSuffix(p, "/"+want) }) {
			t.Errorf("child: %s did not start: %v", want, started)
		}
	}
	quiet, _ := build(t, fixture(t, "quiet"), nil)
	for _, x := range slices.Concat(quiet.Effected.Network, quiet.Attempted.Network, quiet.Undetermined.Network) {
		if x.Kind == "connect" || x.Kind == "send" {
			t.Errorf("quiet: a network call: %+v", x)
		}
	}
}

// A receipt that lists less than the log shows fails the check, though its signature is
// good; so does a log changed after signing, even where the change alters no event.
func TestCheckRebuilds(t *testing.T) {
	signer, pub := newSigner(t)
	log := fixture(t, "network")
	p, subs := build(t, log, nil)
	// Drop the connection attempt, wherever its result put it.
	hidden := p
	isConnect := func(x runsclog.Net) bool { return x.Kind == "connect" }
	hidden.Effected.Network = slices.DeleteFunc(slices.Clone(p.Effected.Network), isConnect)
	hidden.Attempted.Network = slices.DeleteFunc(slices.Clone(p.Attempted.Network), isConnect)
	hidden.Undetermined.Network = slices.DeleteFunc(slices.Clone(p.Undetermined.Network), isConnect)
	if len(slices.Concat(hidden.Effected.Network, hidden.Attempted.Network, hidden.Undetermined.Network)) ==
		len(slices.Concat(p.Effected.Network, p.Attempted.Network, p.Undetermined.Network)) {
		t.Fatal("the network fixture has no connection attempt to hide")
	}
	env, err := Sign(signer, hidden, subs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(env, pub, bytes.NewReader(log), nil); !errors.Is(err, ErrMismatch) {
		t.Errorf("a receipt hiding a network call: %v", err)
	}
	env, err = Sign(signer, p, subs)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(slices.Clone(log), '\n')
	if _, err := Check(env, pub, bytes.NewReader(edited), nil); !errors.Is(err, ErrMismatch) {
		t.Errorf("a log with a byte added after signing: %v", err)
	}
	_, otherPub := newSigner(t)
	if _, err := Check(env, otherPub, bytes.NewReader(log), nil); err == nil {
		t.Error("a receipt checked under another key")
	}
}

// replaceOnce replaces the n-th (from 1) occurrence of old in b.
func replaceNth(t *testing.T, b []byte, old, new string, n int) []byte {
	t.Helper()
	at := -1
	for i := 0; i < n; i++ {
		j := bytes.Index(b[at+1:], []byte(old))
		if j < 0 {
			t.Fatalf("%q occurs fewer than %d times", old, n)
		}
		at += 1 + j
	}
	out := slices.Clone(b[:at])
	out = append(out, new...)
	return append(out, b[at+len(old):]...)
}

// A log that cannot support a receipt's claim makes none.
func TestRefusals(t *testing.T) {
	log := fixture(t, "quiet")
	uid := pods["quiet"]
	traced := "(--strace-syscalls): " + strings.Join(runsclog.Syscalls(), ",")
	for _, c := range []struct {
		name     string
		old, new string
		nth      int
		want     string // in the refusal
	}{
		{"strace off", "Config.Strace (--strace): true", "Config.Strace (--strace): false", 1, "Strace setting"},
		{"debug off", "Config.Debug (--debug): true", "Config.Debug (--debug): false", 1, "Debug setting"},
		{"text format stated", "Config.DebugLogFormat (--debug-log-format): json", "Config.DebugLogFormat (--debug-log-format): text", 1, "DebugLogFormat setting"},
		{"io_uring on", "Config.IOUring (--iouring): false", "Config.IOUring (--iouring): true", 1, "IOUring setting"},
		{"connect not traced", "(--strace-syscalls): bind,chdir,clone,clone3,close,close_range,connect,", "(--strace-syscalls): bind,chdir,clone,clone3,close,close_range,", 1, "did not trace connect"},
		{"every call traced, unchecked", traced, "(--strace-syscalls): (empty)", 1, "did not trace"},
		{"a setting logged twice", "Config.Strace (--strace): true", "Config.Strace (--strace): true\"}\n{\"msg\":\"config.go:581] Config.Strace (--strace): true", 1, "twice"},
		{"two pods", `sandbox-uid\": \"` + uid, `sandbox-uid\": \"00000000-0000-0000-0000-000000000000`, 2, "two pods"},
		{"a spec naming no pod", `io.kubernetes.cri.sandbox-uid\": \"` + uid, `io.kubernetes.cri.sandbox-uix\": \"` + uid, 2, "names no pod"},
		{"no spec", "specutils.go:134] Spec:", "specutils.go:134] Spek:", 2, "no container spec"},
	} {
		bad := replaceNth(t, log, c.old, c.new, 1)
		if c.nth == 2 {
			bad = replaceNth(t, log, c.old, c.new, 2)
		}
		if c.name == "no spec" { // both specs
			bad = replaceNth(t, bad, c.old, c.new, 1)
		}
		if _, _, err := Build(bytes.NewReader(bad), nil); !errors.Is(err, ErrRefused) || !strings.Contains(fmt.Sprint(err), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A log cut short is refused by the reader, and so here.
	if _, _, err := Build(bytes.NewReader(log[:len(log)/2]), nil); !errors.Is(err, ErrRefused) {
		t.Errorf("a cut log: %v", err)
	}
	// So is a log larger than the reader takes: here, one entry past the limit in a valid log.
	at := bytes.Index(log, []byte("\n")) + 1
	huge := slices.Concat(log[:at], []byte(`{"msg":"`), bytes.Repeat([]byte("A"), runsclog.MaxEntryBytes), []byte("\"}\n"), log[at:])
	if _, _, err := Build(bytes.NewReader(huge), nil); !errors.Is(err, ErrRefused) || !errors.Is(err, runsclog.ErrTooLarge) {
		t.Errorf("an entry over the limit: %v", err)
	}
}

// signedRecord makes a run record for a project run in instance, signed into a bundle line,
// and returns it as attest.VerifyCall reads it back.
func signedRecord(t *testing.T, signer *attest.Signer, pub ed25519.PublicKey, instance string) sandbox.RunRecord {
	t.Helper()
	req := &plimsollv1.RunRequest{Protocol: 1, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "require('fixture')"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "agentsandbox", Isolation: "kernel", Instance: instance,
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{Stdout: []byte("ok\n")}}}
	resp.Record = record.Stamp(sandbox.RunRecord{RequestSHA256: record.RunRequestDigest(req)}, resp)
	e, err := signer.Call(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := attest.VerifyCall(attest.NewVerifier(pub), e)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// A receipt joined to a run names its record, checks only with that record, and is refused
// for a record of another sandbox.
func TestRecordJoin(t *testing.T) {
	signer, pub := newSigner(t)
	log := fixture(t, "canary")
	rec := signedRecord(t, signer, pub, sandbox.PodInstance(pods["canary"]))
	p, subs := build(t, log, &rec)
	if p.Run == nil || p.Run.Record != rec.SHA256 || p.Run.Isolation != "kernel" || p.Run.Version != rec.Version ||
		len(subs) != 2 || subs[1].Name != RecordSubject || subs[1].Digest["sha256"] != rec.SHA256 {
		t.Fatalf("run %+v, subjects %+v", p.Run, subs)
	}
	env, err := Sign(signer, p, subs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(env, pub, bytes.NewReader(log), &rec); err != nil {
		t.Error(err)
	}
	if _, err := Check(env, pub, bytes.NewReader(log), nil); !errors.Is(err, ErrMismatch) {
		t.Errorf("checked without its record: %v", err)
	}
	other := signedRecord(t, signer, pub, sandbox.PodInstance(pods["quiet"]))
	if _, _, err := Build(bytes.NewReader(log), &other); !errors.Is(err, ErrRefused) {
		t.Errorf("a record of another pod: %v", err)
	}
	if _, err := Check(env, pub, bytes.NewReader(log), &other); !errors.Is(err, ErrMismatch) {
		t.Errorf("checked with another pod's record: %v", err)
	}
	none := signedRecord(t, signer, pub, "")
	if _, _, err := Build(bytes.NewReader(log), &none); !errors.Is(err, ErrRefused) {
		t.Errorf("a record that names no instance: %v", err)
	}
	// A receipt without a run does not check with one.
	bare, bareSubs := build(t, log, nil)
	env, err = Sign(signer, bare, bareSubs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(env, pub, bytes.NewReader(log), &rec); !errors.Is(err, ErrMismatch) {
		t.Errorf("a receipt with no run checked with a record: %v", err)
	}
}
