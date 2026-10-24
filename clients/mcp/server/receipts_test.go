package server_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

// withReceipts adds a fresh key and receipts directory to cfg, returning the public key.
func withReceipts(t *testing.T, cfg server.Config) (server.Config, []byte, string) {
	t.Helper()
	priv, pub, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.SigningKeyFile = filepath.Join(dir, "harness.key")
	if err := os.WriteFile(cfg.SigningKeyFile, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.ReceiptsDir = filepath.Join(dir, "receipts")
	return cfg, pub, cfg.ReceiptsDir
}

func readEntries(t *testing.T, path string) []attest.Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, err := attest.ReadBundle(f)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func receiptOf(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	r, _ := out["receipt"].(map[string]any)
	if r == nil {
		t.Fatalf("no receipt in %v", out)
	}
	return r
}

// Every run and sandbox call is signed into the receipts directory: each line checks
// on its own at once, a run segment is whole after every run, and a session's file is
// whole once its close is signed.
func TestReceiptsAreSignedAndVerify(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, pubPEM, dir := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	v := attest.NewVerifier(pub)
	checkLine := func(r map[string]any) attest.Entry {
		t.Helper()
		entries := readEntries(t, filepath.Join(dir, r["file"].(string)))
		e := entries[int(r["line"].(float64))-1]
		if _, _, err := attest.VerifyEntry(v, e); err != nil {
			t.Fatalf("line %v of %v: %v", r["line"], r["file"], err)
		}
		if attest.LineDigest(e) != r["lineSha256"] || r["keyId"] != attest.KeyID(pub) || r["scope"] != "entry" {
			t.Fatalf("receipt %v does not name the line it points at", r)
		}
		return e
	}

	var runs string
	for i, code := range []string{"print(1)", "print(2)"} {
		r := receiptOf(t, c.ok("run_code", map[string]any{"code": code}))
		if r["status"] != "stored" || r["session"] != "none" || r["line"] != float64(2*i+1) {
			t.Fatalf("run %d: %v", i, r)
		}
		checkLine(r)
		runs = r["file"].(string)
	}
	if _, err := attest.VerifyBundle(readEntries(t, filepath.Join(dir, runs)), v); err != nil {
		t.Errorf("the run segment after two runs: %v", err)
	}

	h := c.ok("open_sandbox", nil)["sandbox"]
	first := receiptOf(t, c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h}))
	out := c.ok("run_code", map[string]any{"code": "x", "sandbox": h})
	second := receiptOf(t, out)
	if first["session"] != "open" || second["line"] != float64(2) || !strings.HasPrefix(second["file"].(string), "session-") {
		t.Fatalf("sandbox receipts: %v, %v", first, second)
	}
	checkLine(second)
	session := filepath.Join(dir, second["file"].(string))
	if _, err := attest.VerifyBundle(readEntries(t, session), v); err == nil {
		t.Error("an open session's file verified whole")
	}
	c.ok("close_sandbox", map[string]any{"sandbox": h})
	rec := c.ok("get_record", map[string]any{"recordSha256": out["recordSha256"]})
	if r := receiptOf(t, rec); r["session"] != "closed" || !strings.Contains(rec["summary"].(string), "verify-entry") {
		t.Errorf("get_record after the close: %v", rec)
	}
	if _, err := attest.VerifyBundle(readEntries(t, session), v); err != nil {
		t.Errorf("the closed session's file: %v", err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("the receipts directory is %v", st.Mode().Perm())
	}
}

// A receipt that cannot be written leaves its result whole, and the run segment ends
// there: the next run starts another, and both verify.
func TestAFailedReceiptWriteEndsItsSegment(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg, pubPEM, dir := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	pub, _ := attest.ParsePublicKey(pubPEM)
	first := receiptOf(t, c.ok("run_code", map[string]any{"code": "print(1)"}))
	server.FailNextReceiptWrite(c.s)
	failed := c.ok("run_code", map[string]any{"code": "exit 4"})
	if failed["exitCode"] != float64(4) || receiptOf(t, failed)["status"] != "failed" {
		t.Fatalf("the run whose receipt failed: %v", failed)
	}
	next := receiptOf(t, c.ok("run_code", map[string]any{"code": "print(3)"}))
	if next["status"] != "stored" || next["file"] == first["file"] || next["line"] != float64(1) {
		t.Fatalf("the run after: %v (first %v)", next, first)
	}
	for _, f := range []any{first["file"], next["file"]} {
		if _, err := attest.VerifyBundle(readEntries(t, filepath.Join(dir, f.(string))), attest.NewVerifier(pub)); err != nil {
			t.Errorf("%v: %v", f, err)
		}
	}
}

// A sandbox this server lets go without a signed close (here the daemon is gone) has
// its receipts marked incomplete, never closed.
func TestASessionWithoutASignedCloseIsIncomplete(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	out := c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	d.Stop()
	c.ok("close_sandbox", map[string]any{"sandbox": h})
	eventually(t, "the session's receipts are marked incomplete", func() bool {
		r := receiptOf(t, c.ok("get_record", map[string]any{"recordSha256": out["recordSha256"]}))
		return r["session"] == "incomplete"
	})
}

// Past its limit the receipts directory refuses new work before anything runs.
func TestAFullReceiptsDirectoryRefusesWork(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	cfg.ReceiptsMaxBytes = 1
	c := connect(t, cfg)
	c.ok("run_code", map[string]any{"code": "print(1)"})
	if f := c.fail("run_code", map[string]any{"code": "print(2)"}); f.Ran != "no" || f.Refusal != "capacity" || !strings.Contains(f.Summary, "PLIMSOLL_RECEIPTS_MAX_MB") {
		t.Errorf("run_code past the limit: %+v", f)
	}
	if f := c.fail("open_sandbox", nil); f.Ran != "no" || f.Refusal != "capacity" {
		t.Errorf("open_sandbox past the limit: %+v", f)
	}
}

// Receipts hold the code and its output, so a directory or key others can read is refused.
func TestReceiptsRefuseSharedFiles(t *testing.T) {
	cfg, _, dir := withReceipts(t, local("http://127.0.0.1:1"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := server.New(cfg); err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Errorf("a shared directory: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.SigningKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := server.New(cfg); err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Errorf("a shared key: %v", err)
	}
	env := map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_RECEIPTS_DIR": dir}
	if _, err := server.FromEnv(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "set both, or neither") {
		t.Errorf("a directory without a key: %v", err)
	}
}

// A call that may have run is a failure whatever its receipt did; a receipt that
// failed for it does not turn it into a result.
func TestAnUnansweredCallWhoseReceiptFailsStaysAFailure(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	server.FailNextReceiptWrite(c.s)
	res := c.call("run_code", map[string]any{"code": fakedaemon.Breaks, "sandbox": h})
	if !res.IsError || !strings.Contains(text(res), `"ran":"maybe"`) || !strings.Contains(text(res), `"recordSha256":"`) || !strings.Contains(text(res), `"status":"failed"`) {
		t.Errorf("an unanswered call whose receipt failed: %s", text(res))
	}
}

// A session whose first receipt could not be stored never becomes closed: no file
// may hold its later calls or a close that counts calls it does not hold.
func TestASessionMissingItsFirstReceiptIsNeverClosed(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, dir := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	server.FailNextReceiptCreate(c.s)
	first := receiptOf(t, c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h}))
	second := c.ok("run_code", map[string]any{"code": "x", "sandbox": h})
	if first["status"] != "failed" || receiptOf(t, second)["status"] != "failed" {
		t.Errorf("receipts after a failed first file: %v, %v", first, second["receipt"])
	}
	if out := c.ok("close_sandbox", map[string]any{"sandbox": h}); out["deleted"] != true {
		t.Errorf("the close: the daemon deleted the sandbox whatever its receipt: %v", out)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "session-*"))
	if len(files) != 0 {
		t.Errorf("a session file was made for a session missing its first call: %v", files)
	}
	if n := server.SessionsHeld(c.s); n != 0 {
		t.Errorf("the store still holds %d sessions", n)
	}
}

// A close whose summary checked but whose receipt could not be written deleted the
// sandbox: deleted is true, and the session's receipts are incomplete.
func TestAFailedCloseReceiptStillConfirmsDeletion(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	out := c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	server.FailNextReceiptWrite(c.s)
	if closed := c.ok("close_sandbox", map[string]any{"sandbox": h}); closed["deleted"] != true || d.OpenSessions() != 0 {
		t.Errorf("close_sandbox: %v, %d open", closed, d.OpenSessions())
	}
	if r := receiptOf(t, c.ok("get_record", map[string]any{"recordSha256": out["recordSha256"]})); r["session"] != "incomplete" || !strings.Contains(fmt.Sprint(r["reason"]), "receipt write failed") {
		t.Errorf("the session's receipts, and why they are incomplete: %v", r)
	}
}

// A rollback that could not be made is reported, and marked on the file's earlier receipts.
func TestAFailedRollbackIsMarkedOnTheFile(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	first := c.ok("run_code", map[string]any{"code": "print(1)"})
	server.FailNextReceiptWrite(c.s)
	server.FailNextRollback(c.s)
	if r := receiptOf(t, c.ok("run_code", map[string]any{"code": "print(2)"})); r["status"] != "failed" || !strings.Contains(r["reason"].(string), "could not be cut back") && !strings.Contains(r["reason"].(string), "cutting") {
		t.Errorf("the run whose write and rollback failed: %v", r)
	}
	if r := receiptOf(t, c.ok("get_record", map[string]any{"recordSha256": first["recordSha256"]})); r["status"] != "stored" || !strings.Contains(r["reason"].(string), "check the file") {
		t.Errorf("the earlier receipt in that file: %v", r)
	}
}

// The quota measures the directory itself: another writer's files count once the last
// measurement is old enough, and moving them away admits work at the next check, since
// every check at the limit measures again.
func TestTheQuotaMeasuresTheDirectory(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg, _, dir := withReceipts(t, local(d.URL))
	cfg.ReceiptsMaxBytes = 1 << 20
	c := connect(t, cfg)
	c.ok("run_code", map[string]any{"code": "print(1)"})
	other := filepath.Join(dir, "runs-another-process-0001.jsonl")
	if err := os.WriteFile(other, make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	c.ok("run_code", map[string]any{"code": "print(2)"}) // unseen while the measurement is fresh
	server.AdvanceReceiptsClock(c.s, time.Hour)
	if f := c.fail("run_code", map[string]any{"code": "print(3)"}); f.Refusal != "capacity" {
		t.Errorf("past the limit with another writer's file: %+v", f)
	}
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	c.ok("run_code", map[string]any{"code": "print(4)"})
}

// This process's own writes are counted exactly as they land, a line cut back after a
// failed write and a partial line left by a failed cut back included.
func TestTheQuotaCountsThisProcesssWritesExactly(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": "print(1)"})
	c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	server.FailNextReceiptWrite(c.s)
	c.ok("run_code", map[string]any{"code": "print(2)"})
	server.FailNextReceiptWrite(c.s)
	server.FailNextRollback(c.s)
	c.ok("run_code", map[string]any{"code": "print(3)"})
	c.ok("close_sandbox", map[string]any{"sandbox": h})
	if counted, measured := server.ReceiptsCounted(c.s); counted != measured || measured == 0 {
		t.Errorf("counted %d bytes, the directory holds %d", counted, measured)
	}
}

// A directory that cannot be measured refuses work, nothing run, rather than letting it
// in on a measurement that failed.
func TestAnUnmeasurableDirectoryRefusesWork(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg, _, dir := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	server.AdvanceReceiptsClock(c.s, time.Hour)
	if f := c.fail("run_code", map[string]any{"code": "print(1)"}); f.Ran != "no" || f.Refusal != "capacity" || !strings.Contains(f.Summary, "measuring the receipts directory") {
		t.Errorf("a directory that cannot be measured: %+v", f)
	}
}

// Repeated failed sessions leave no file open and no session held.
func TestFailedSessionsAreNotHeld(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 8})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	fds := func() int { e, _ := os.ReadDir("/proc/self/fd"); return len(e) }
	before := fds()
	for range 5 {
		h := c.ok("open_sandbox", nil)["sandbox"]
		c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
		server.FailNextReceiptWrite(c.s)
		c.ok("run_code", map[string]any{"code": "x", "sandbox": h})
		c.ok("close_sandbox", map[string]any{"sandbox": h})
	}
	if n := server.SessionsHeld(c.s); n != 0 {
		t.Errorf("the store holds %d sessions", n)
	}
	if after := fds(); after > before+4 {
		t.Errorf("open descriptors grew from %d to %d", before, after)
	}
}

// A receipts directory whose parents do not exist is created, each level owner-only;
// a start whose parent sync failed is repaired by the next start, which syncs it.
func TestTheReceiptsDirectoryIsCreatedAndItsNameMadeDurable(t *testing.T) {
	cfg, _, dir := withReceipts(t, local("http://127.0.0.1:1"))
	cfg.ReceiptsDir = filepath.Join(dir, "state", "plimsoll", "receipts")
	parent := filepath.Dir(cfg.ReceiptsDir)
	synced, reset := server.FailSyncDirOnce(parent)
	defer reset()
	if _, err := server.New(cfg); err == nil || !strings.Contains(err.Error(), "sync") {
		t.Fatalf("a start whose sync of the directory's parent failed: %v", err)
	}
	if _, err := server.New(cfg); err != nil {
		t.Fatalf("the next start: %v", err)
	}
	if synced() < 2 {
		t.Error("the next start, finding the directory made, did not sync its parent")
	}
	for _, d := range []string{filepath.Join(dir, "state"), filepath.Join(dir, "state", "plimsoll"), cfg.ReceiptsDir} {
		if st, err := os.Stat(d); err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, err, st)
		}
	}
}

// The limit is measured at every admission and dispatch: a call right after the write
// that crossed it is refused, and so is one that waited while the directory filled.
func TestTheQuotaIsMeasuredAtAdmissionAndDispatch(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, dir := withReceipts(t, local(d.URL))
	cfg.ReceiptsMaxBytes = 1
	c := connect(t, cfg)
	c.ok("run_code", map[string]any{"code": "print(1)"})
	if f := c.fail("run_code", map[string]any{"code": "print(2)"}); f.Refusal != "capacity" {
		t.Errorf("the call right after the limit was crossed: %+v", f)
	}

	cfg2, _, dir2 := withReceipts(t, local(d.URL))
	cfg2.ReceiptsMaxBytes = 1 << 20
	c2 := connect(t, cfg2)
	h := c2.ok("open_sandbox", nil)["sandbox"]
	blocked := d.Provider.Blocked()
	first := make(chan map[string]any)
	go func() { first <- c2.ok("run_code", map[string]any{"code": fakedaemon.Block, "sandbox": h}) }()
	<-blocked
	queued := make(chan failure)
	go func() { queued <- c2.fail("run_code", map[string]any{"code": "after", "sandbox": h}) }()
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(dir2, "another-writer.jsonl"), make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	server.AdvanceReceiptsClock(c2.s, time.Hour) // the measurement is old by dispatch
	d.Provider.Release()
	<-first
	if f := <-queued; f.Ran != "no" || f.Refusal != "capacity" {
		t.Errorf("the call that waited while the directory filled: %+v", f)
	}
	_ = dir
}

// A close reports the deletion and, separately, whether the sandbox's receipts are
// whole, with the reason when they are not, for a sandbox that ran calls and one that
// ran none.
func TestCloseReportsReceiptsApartFromDeletion(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	ran := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": ran})
	if out := c.ok("close_sandbox", map[string]any{"sandbox": ran}); out["deleted"] != true || out["receipts"] != "closed" {
		t.Errorf("a close whose signed close was stored: %v", out)
	}
	for _, calls := range []int{1, 0} {
		h := c.ok("open_sandbox", nil)["sandbox"]
		if calls == 1 {
			c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
		}
		server.FailNextReceiptWrite(c.s)
		out := c.ok("close_sandbox", map[string]any{"sandbox": h})
		if out["deleted"] != true || out["receipts"] != "incomplete" || !strings.Contains(out["receiptsReason"].(string), "receipt write failed") {
			t.Errorf("%d calls, a close whose signed close could not be stored: %v", calls, out)
		}
	}
}

// After shutdown begins, no tool call is admitted, a close included, and the shutdown
// still closes the sandbox.
func TestShutdownAdmitsNothingAndStillCloses(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.s.Shutdown()
	if f := c.fail("close_sandbox", map[string]any{"sandbox": h}); f.Ran != "no" || !strings.Contains(f.Summary, "shutting down") {
		t.Errorf("a close after shutdown began: %+v", f)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if n := d.OpenSessions(); n != 0 {
		t.Errorf("%d sessions open after Close", n)
	}
}

// A receipt write that blocks does not stop shutdown from deleting an idle sandbox, and
// when it ends the cleanup finishes by itself, though Close's wait ran out first.
func TestShutdownGoesOnPastABlockedReceiptWrite(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	c.ok("open_sandbox", nil)
	blocked, release := server.BlockNextReceiptWrite(c.s)
	go c.call("run_code", map[string]any{"code": "print(1)"})
	waitFor(t, "the fresh run's receipt write to block", blocked)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.s.Close(ctx); err == nil {
		t.Fatal("Close returned before a blocked receipt write ended")
	}
	eventually(t, "the idle sandbox is deleted while the write is blocked", func() bool { return d.OpenSessions() == 0 })
	release()
	eventually(t, "the cleanup ends the receipt store by itself", func() bool { return server.ReceiptsEnded(c.s) })
}

// A sync that failed at any level of the receipts directory's path is repaired by the
// next start, which syncs the whole chain, existing directories included.
func TestAFailedAncestorSyncIsRepairedOnTheNextStart(t *testing.T) {
	cfg, _, base := withReceipts(t, local("http://127.0.0.1:1"))
	cfg.ReceiptsDir = filepath.Join(base, "state", "plimsoll", "receipts")
	synced, reset := server.FailSyncDirOnce(base) // the sync recording "state" in base
	defer reset()
	if _, err := server.New(cfg); err == nil {
		t.Fatal("a start whose sync of base failed")
	}
	if _, err := server.New(cfg); err != nil {
		t.Fatalf("the next start: %v", err)
	}
	if synced() < 2 {
		t.Error("the next start did not sync base, whose entry for state was never made durable")
	}
}

// A parent this user may write but not open could hold an entry it made, which cannot
// be synced, so every start refuses it; one it may neither open nor write ends the walk.
func TestAnUnopenableParentRefusesOnlyIfWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens any directory")
	}
	cfg, _, base := withReceipts(t, local("http://127.0.0.1:1"))
	parent := filepath.Join(filepath.Dir(base), "parent")
	cfg.ReceiptsDir = filepath.Join(parent, "receipts")
	if err := os.Mkdir(parent, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	for _, start := range []string{"the start that made the directory", "the next start"} {
		if _, err := server.New(cfg); err == nil || !strings.Contains(err.Error(), "sync") {
			t.Fatalf("%s, under a parent it may write but not open: %v", start, err)
		}
	}
	if err := os.Chmod(parent, 0o100); err != nil {
		t.Fatal(err)
	}
	if _, err := server.New(cfg); err != nil {
		t.Fatalf("a start under a parent it may neither open nor write: %v", err)
	}
}

// A close whose answer is due while a call still holds the sandbox answers that it goes
// on, and it does: once the call ends the sandbox is deleted and its receipts closed, and
// shutdown, waiting on the same close, ends cleanly.
func TestACloseWhoseAnswerWasDueGoesOn(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	blocked, release := server.BlockNextReceiptWrite(c.s)
	ran := make(chan map[string]any, 1)
	go func() { ran <- c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h}) }()
	waitFor(t, "the call's receipt write to block, its sandbox held", blocked)
	server.CallTimeout(c.s, 300*time.Millisecond)
	if out := c.ok("close_sandbox", map[string]any{"sandbox": h}); out["deleted"] != false || !strings.Contains(fmt.Sprint(out["summary"]), "goes on in the background") {
		t.Errorf("a close whose answer was due first: %v", out)
	}
	release()
	out := <-ran
	eventually(t, "the sandbox is deleted once the call ends", func() bool { return d.OpenSessions() == 0 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.s.Close(ctx); err != nil {
		t.Fatalf("shutdown, waiting on the same close: %v", err)
	}
	if r := receiptOf(t, out); r["status"] != "stored" {
		t.Errorf("the call's receipt: %v", r)
	}
}

// Shutdown never ends the store under a close still writing its signed close: an ended
// sandbox's close, stuck in that write, ends first, so the session's receipts are whole.
func TestShutdownWaitsForAnEndedSandboxsClose(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, pub, dir := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	blocked, release := server.BlockReceiptWriteAfter(c.s, 1) // the call's line passes, its close's waits
	out := c.ok("run_code", map[string]any{"code": fakedaemon.EndsSession, "sandbox": h})
	waitFor(t, "the ended sandbox's close to block writing its signed close", blocked)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := c.s.Close(ctx); err == nil {
		t.Fatal("Close returned while an ended sandbox's close was still writing")
	}
	release()
	eventually(t, "the store ends", func() bool { return server.ReceiptsEnded(c.s) })
	r := receiptOf(t, out)
	entries := readEntries(t, filepath.Join(dir, fmt.Sprint(r["file"])))
	key, _ := attest.ParsePublicKey(pub)
	if _, err := attest.VerifyBundle(entries, attest.NewVerifier(key)); err != nil {
		t.Errorf("the ended sandbox's receipts: %v", err)
	}
}

// A close whose deletion was confirmed as the answer's deadline came says it was deleted,
// and how its receipts ended, rather than that it goes on.
func TestACloseThatFinishedAsTheDeadlineCameSaysSo(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	server.CallTimeout(c.s, 200*time.Millisecond)
	defer server.SetAwait(func(ctx context.Context, ch <-chan struct{}) { <-ch; <-ctx.Done() })()
	if out := c.ok("close_sandbox", map[string]any{"sandbox": h}); out["deleted"] != true || out["receipts"] != "closed" {
		t.Errorf("a close confirmed as its deadline came: %v", out)
	}
}

// A known failure published as the answer's deadline ends is reported, not unknown.
func TestAFailureThatMeetsTheDeadlineIsReported(t *testing.T) {
	s, err := server.New(local("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if state, reason := server.ReceiptsOfWhenAFailureMeetsTheDeadline(s); state != "incomplete" || reason != "the write failed" {
		t.Errorf("a failure and the deadline at once: %s (%s)", state, reason)
	}
}

// Checks that arrive while the directory is being measured take that walk's answer:
// at the limit, eight checks at once walk the directory once, and all refuse.
func TestChecksAtOnceShareOneWalk(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg, _, _ := withReceipts(t, local(d.URL))
	cfg.ReceiptsMaxBytes = 1
	c := connect(t, cfg)
	c.ok("run_code", map[string]any{"code": "print(1)"})
	walks, errs := server.ChecksAtOnce(c.s, 8)
	if walks != 1 {
		t.Errorf("eight checks at once walked the directory %d times", walks)
	}
	for _, err := range errs {
		if err == nil || !strings.Contains(err.Error(), "PLIMSOLL_RECEIPTS_MAX_MB") {
			t.Errorf("a check at the limit: %v", err)
		}
	}
}

// A measurement's age counts from when its walk began, not when it ended: a file the
// walk read early may have grown while it went on.
func TestAMeasurementsAgeCountsFromItsStart(t *testing.T) {
	cfg, _, _ := withReceipts(t, local("http://127.0.0.1:1"))
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first, at := server.MeasureWithTickingClock(s, 10*time.Second); !at.Equal(first) {
		t.Errorf("measured at %v, its walk began at %v", at, first)
	}
}

// A file whose size cannot be read refuses work rather than counting as empty.
func TestAnUnreadableSizeRefusesWork(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg, _, dir := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	sealed := filepath.Join(dir, "sealed")
	if err := os.Mkdir(sealed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sealed, "big.jsonl"), make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sealed, 0o400); err != nil { // its names can be listed, not looked up
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sealed, 0o700) })
	server.AdvanceReceiptsClock(c.s, time.Hour)
	if f := c.fail("run_code", map[string]any{"code": "print(1)"}); f.Refusal != "capacity" || !strings.Contains(f.Summary, "measuring the receipts directory") {
		t.Errorf("a file whose size cannot be read: %+v", f)
	}
}

// A deletion the daemon has not confirmed within the close's budget is tried once more
// in the same close: the answer says so, the retry collects the deletion and the signed
// close, and shutdown takes the retry's result as the close's.
func TestAnUnconfirmedDeletionIsTriedOnceMore(t *testing.T) {
	defer server.RetireBudget(200 * time.Millisecond)()
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, CloseDelay: 300 * time.Millisecond})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	ran := c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	if out := c.ok("close_sandbox", map[string]any{"sandbox": h}); out["deleted"] != false || !strings.Contains(fmt.Sprint(out["summary"]), "tried once more") {
		t.Errorf("a close the daemon did not confirm in time: %v", out)
	}
	eventually(t, "the retry deletes the sandbox and completes its receipts", func() bool {
		r := receiptOf(t, c.ok("get_record", map[string]any{"recordSha256": ran["recordSha256"]}))
		return d.OpenSessions() == 0 && r["session"] == "closed"
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.s.Close(ctx); err != nil {
		t.Errorf("shutdown, after a close whose retry succeeded: %v", err)
	}
}

// waitFor waits for ch to close.
func waitFor(t *testing.T, what string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("never: %s", what)
	}
}

// lockedBuffer is a log the server's goroutines may write while a test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Every session whose receipts end incomplete is logged where they settle, whatever
// answer also says so: for a close at shutdown, the log is the only record.
func TestIncompleteReceiptsAreLogged(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	var log lockedBuffer
	cfg.Logger = slog.New(slog.NewTextHandler(&log, nil))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	server.FailNextReceiptWrite(c.s)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := log.String(); !strings.Contains(got, "receipts are incomplete") || !strings.Contains(got, "receipt write failed") {
		t.Errorf("nothing logged of the sandbox closed at shutdown: %q", got)
	}
}

// A close's known incomplete receipts are reported at once, though an earlier sandbox
// of the handle is still being closed when the answer is due; without one, unknown.
func TestAKnownIncompleteCloseIsNotHiddenByAPendingOne(t *testing.T) {
	s, err := server.New(local("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if state, reason := server.ReceiptsOfAfterPendingClose(s, "incomplete", "the write failed"); state != "incomplete" || reason != "the write failed" {
		t.Errorf("a failed last close, an earlier one pending: %s (%s)", state, reason)
	}
	if state, _ := server.ReceiptsOfAfterPendingClose(s, "closed", ""); state != "unknown" {
		t.Errorf("a clean last close, an earlier one pending: %s", state)
	}
}

// A handle whose earlier sandbox ended with incomplete receipts is reported
// incomplete at its close, though its last sandbox closed cleanly.
func TestCloseCountsAnEndedSandboxsReceipts(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	server.FailNextReceiptWrite(c.s)
	c.ok("run_code", map[string]any{"code": fakedaemon.EndsSession, "sandbox": h})
	c.ok("run_code", map[string]any{"code": "y = 2", "sandbox": h}) // a new sandbox, whose receipts are whole
	out := c.ok("close_sandbox", map[string]any{"sandbox": h})
	if out["deleted"] != true || out["receipts"] != "incomplete" || !strings.Contains(out["receiptsReason"].(string), "could not be stored") {
		t.Errorf("close_sandbox: %v", out)
	}
}

// Shutdown waits for a call stuck in a receipt write however long it takes, and then
// deletes its sandbox and ends the store; it never gives up on a busy sandbox. The
// write is held past both waits for the turn an earlier shutdown made, each of the
// call budget plus the close budget, shortened here to 0.5 s and 0.1 s.
func TestShutdownWaitsForAStuckCallThenDeletesItsSandbox(t *testing.T) {
	defer server.RetireBudget(100 * time.Millisecond)()
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	server.CallTimeout(c.s, 500*time.Millisecond)
	blocked, release := server.BlockNextReceiptWrite(c.s)
	go c.call("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	waitFor(t, "the call's receipt write to block, its sandbox held", blocked)
	go func() { _ = c.s.Close(context.Background()) }()
	eventually(t, "the cleanup takes the sandboxes", func() bool { return server.SandboxesHeld(c.s) == 0 })
	time.Sleep(2 * time.Second) // past 2 × (0.5 s + 0.1 s)
	release()
	eventually(t, "the busy sandbox is deleted once its call ends", func() bool { return d.OpenSessions() == 0 })
	eventually(t, "the store ends", func() bool { return server.ReceiptsEnded(c.s) })
}

// A run's trace (a coding session's ID, say) is signed into its receipt with the request;
// one the daemon would drop is refused before anything runs, so a run meant to be tagged
// never goes out untagged.
func TestATraceIsSignedIntoTheReceipt(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg, _, dir := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	r := receiptOf(t, c.ok("run_code", map[string]any{"code": "print(1)", "trace": "session-1f2e.3d:4c"}))
	e := readEntries(t, filepath.Join(dir, r["file"].(string)))[int(r["line"].(float64))-1]
	var req plimsollv1.RunRequest
	if err := proto.Unmarshal(e.Request, &req); err != nil {
		t.Fatal(err)
	}
	if req.GetTraceId() != "session-1f2e.3d:4c" {
		t.Errorf("the signed request carries trace %q", req.GetTraceId())
	}
	for _, bad := range []string{"has space", strings.Repeat("a", 65), "slash/path"} {
		if f := c.fail("run_code", map[string]any{"code": "print(2)", "trace": bad}); f.Ran != "no" || !strings.Contains(f.Summary, "trace") {
			t.Errorf("trace %q: %+v", bad, f)
		}
	}
}

// A close the daemon answered with a count this server did not see (a call ran whose
// answer was lost: here every SessionRun answer loses the request ID's echo, so the
// client believes none) still deleted the sandbox: it is reported deleted, not retried
// as unconfirmed, and its receipts end incomplete (review B6, 2026-10-23).
func TestACloseWithAChainThisServerDidNotSeeStillDeleted(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, StripRequestID: true})
	cfg, _, _ := withReceipts(t, local(d.URL))
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.fail("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	closed := c.ok("close_sandbox", map[string]any{"sandbox": h})
	if closed["deleted"] != true || d.OpenSessions() != 0 {
		t.Fatalf("close_sandbox: %v, %d open", closed, d.OpenSessions())
	}
	// The one call's answer was lost, so no receipt file exists; the receipts still end
	// incomplete rather than complete.
	if closed["receipts"] != "incomplete" || !strings.Contains(closed["receiptsReason"].(string), "never saw answered") {
		t.Fatalf("close_sandbox reports receipts %q (%v), want incomplete", closed["receipts"], closed["receiptsReason"])
	}
}
