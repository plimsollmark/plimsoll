package sandbox_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/sessiontest"
)

// TestLiveE2BSessions is the live proof of E2B sessions: the provider's startup smoke
// test, the session smoke test and the conformance suite against the real service,
// then what only the service can show (who the guest runs as, whether a paused
// session is found by the listing ReconcileOrphans reads). It spends: every case opens
// a microVM, about 2 cents a pass at the template's size. So it runs only with
// E2B_SESSION_LIVE=1 and E2B_API_KEY (make e2b-session-live), never in the ordinary
// gate or the E2B suite. E2B_TEMPLATE picks the template (default base). It ends by
// draining the provider, as plimsolld does at shutdown, and fails if any sandbox
// stamped with its instance is still listed: a close only starts a delete.
func TestLiveE2BSessions(t *testing.T) {
	if os.Getenv("E2B_SESSION_LIVE") != "1" {
		t.Skip("set E2B_SESSION_LIVE=1 (make e2b-session-live): this spends E2B credits")
	}
	key := os.Getenv("E2B_API_KEY")
	if key == "" {
		t.Fatal("E2B_SESSION_LIVE=1 but E2B_API_KEY is not set")
	}
	e := &sandbox.E2B{APIKey: key, Template: os.Getenv("E2B_TEMPLATE"), DefaultTimeout: 60 * time.Second, MaxTimeout: 90 * time.Second}
	t.Cleanup(func() { requireNothingLeft(t, e) })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := e.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	langs := e.SessionEnvironments().Project.Languages
	t.Logf("languages the template runs: %v", langs)
	t.Run("SessionSmoke", func(t *testing.T) {
		if err := sandbox.SessionSmokeTest(ctx, e, sandbox.SessionOptions{Lifetime: 10 * time.Minute, DiskBytes: 64 << 20}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Conformance", func(t *testing.T) {
		sessiontest.Run(t, e, sessiontest.Config{
			Lifetime: 10 * time.Minute, ShortLifetime: 45 * time.Second, Languages: langs,
			ExecsWalledOff: true, Teardown: sandbox.E2BTeardown,
		})
	})
	t.Run("GuestCannotBecomeRoot", func(t *testing.T) {
		start := time.Now()
		s := openE2B(t, e)
		opened := time.Since(start)
		start = time.Now()
		_ = e2bSnippet(t, s, `1`)
		first := time.Since(start)
		start = time.Now()
		_ = e2bSnippet(t, s, `1`)
		t.Logf("an open took %v; its first call %v, the next %v", opened, first, time.Since(start))
		// As the guest: the uid, no-new-privs, and the template's three ways back to root.
		res := e2bSnippet(t, s, `const cp = require("child_process"), fs = require("fs");
const st = fs.readFileSync("/proc/self/status", "latin1");
const f = (n) => (new RegExp("^" + n + ":[ \\t]*(.*)$", "m").exec(st) || [])[1];
const tryRun = (argv) => { const r = cp.spawnSync(argv[0], argv.slice(1), { encoding: "utf8", timeout: 10000, stdio: ["ignore", "pipe", "pipe"] });
  return r.error ? r.error.code : r.status; };
console.log(JSON.stringify({ uid: f("Uid"), nnp: f("NoNewPrivs"),
  sudo: tryRun(["sudo", "-n", "true"]), su: tryRun(["su", "-c", "true", "root"]),
  ssh: tryRun(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3", "root@127.0.0.1", "true"]) }))`)
		var got struct {
			UID, NNP      string
			Sudo, Su, SSH any
		}
		if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
			t.Fatalf("probe output %q: %v (stderr %q)", res.Stdout, err, res.Stderr)
		}
		t.Logf("guest probe: %+v", got)
		if got.UID != "61000\t61000\t61000\t61000" || got.NNP != "1" {
			t.Fatalf("the guest runs as %q, no-new-privs %q", got.UID, got.NNP)
		}
		for name, v := range map[string]any{"sudo": got.Sudo, "su": got.Su, "ssh": got.SSH} {
			if n, ok := v.(float64); ok && n == 0 {
				t.Errorf("%s succeeded for the guest", name)
			}
		}
	})
	t.Run("PausedSessionIsListed", func(t *testing.T) {
		other := &sandbox.E2B{APIKey: key, Template: os.Getenv("E2B_TEMPLATE")}
		s := openE2B(t, e)
		_ = e2bSnippet(t, s, `1`)
		if _, err := s.Suspend(ctx); err != nil {
			t.Fatalf("Suspend: %v", err)
		}
		// The listing ReconcileOrphans reads finds it, paused, and another instance's
		// reconcile spares it: it is not past its declared expiry.
		listed, err := sandbox.E2BSessionSandboxes(ctx, other)
		if err != nil {
			t.Fatal(err)
		}
		if id := sandbox.E2BSessionSandbox(s); listed[id] != "paused" {
			t.Fatalf("the listing has the paused session's sandbox %s as %q (listed: %v)", id, listed[id], listed)
		}
		if n, err := other.ReconcileOrphans(ctx); err != nil || n != 0 {
			t.Fatalf("another instance's reconcile with a live paused session: killed %d, err %v", n, err)
		}
		res := e2bSnippet(t, s, `console.log("resumed")`)
		if strings.TrimSpace(res.Stdout) != "resumed" {
			t.Fatalf("after the resume: %+v", res)
		}
	})
}

// requireNothingLeft drains e and fails if a sandbox stamped with its instance is still
// listed. E2B can list a sandbox for a moment after its delete returns, so it looks a
// few times before failing.
func requireNothingLeft(t *testing.T, e *sandbox.E2B) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := e.Drain(ctx); err != nil {
		t.Errorf("Drain: %v", err)
	}
	var left map[string]string
	for range 10 {
		var err error
		if left, err = sandbox.E2BOwnSandboxes(ctx, e); err != nil {
			t.Errorf("listing what the run left: %v", err)
			return
		}
		if len(left) == 0 {
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Errorf("the run left sandboxes behind, still billing until their own timeout: %v", left)
}
