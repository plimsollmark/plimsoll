package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestOpenShellDaemonSessionLive runs sessions end to end on a live gateway: the
// daemon with sessions enabled and a short idle timeout, the official client with
// the attest harness as its recorder, a session whose file outlives an idle
// suspend, a project reading it, the close, and the signed bundle verified. A
// second session is left open at shutdown, which the drain must end, leaving no
// sandbox behind. (That the session ID never reaches a log line is
// internal/rpc's TestSessionAuditLinesCarryTheFingerprintNeverTheID.)
func TestOpenShellDaemonSessionLive(t *testing.T) {
	if os.Getenv("OPENSHELL_LIVE") != "1" {
		t.Skip("the live OpenShell suite runs with OPENSHELL_LIVE=1 and a gateway")
	}
	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	env := []string{"SANDBOX_PROVIDER=openshell", "PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=off", "PLIMSOLL_TOKEN=" + token,
		"SANDBOX_MAX_SESSIONS=2", "SANDBOX_SESSION_IDLE=2s", "SANDBOX_SESSION_LIFETIME=5m", "SANDBOX_SESSION_DISK_MB=64"}
	for _, name := range openshellVars {
		if os.Getenv(name) == "" {
			t.Fatalf("OPENSHELL_LIVE=1 but %s is not set", name)
		}
		env = append(env, name+"="+os.Getenv(name))
	}
	gw := liveGatewayClient(t)
	before := runSandboxes(t, gw)
	d := startDaemon(t, env, 2*time.Minute)

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var bundle bytes.Buffer
	remote, err := client.New("http://"+d.addr, client.WithToken(token), client.WithRecorder(attest.NewHarness(attest.NewSigner(key), &bundle)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	info, err := remote.Describe(ctx)
	if err != nil || !info.SupportsSessions || info.SessionIdleTimeout != 2*time.Second {
		t.Fatalf("Describe = %+v, %v", info, err)
	}
	s, err := remote.OpenSession(ctx, client.SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.RunJavaScript(ctx, sandbox.Request{Code: `require("fs").writeFileSync("/tmp/kept.txt","across calls");console.log("wrote")`})
	if err != nil || strings.TrimSpace(res.Stdout) != "wrote" {
		t.Fatalf("first call: %+v, %v", res, err)
	}
	// Let the idle timeout suspend the sandbox; the next call resumes it.
	time.Sleep(4 * time.Second)
	if !strings.Contains(d.logText(), "session suspended") {
		t.Fatalf("the idle session was not suspended:\n%s", d.logText())
	}
	start := time.Now()
	pres, err := s.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"cat /tmp/kept.txt"}})
	if err != nil || pres.Outcome != sandbox.ProjectOutcomeCompleted || pres.Steps[0].Stdout != "across calls" {
		t.Fatalf("the call after the idle suspend: %+v, %v", pres, err)
	}
	t.Logf("the call after an idle suspend took %v, resume included", time.Since(start).Round(time.Millisecond))
	sum, err := s.Close(ctx)
	if err != nil || sum.Calls != 2 || sum.End != sandbox.SessionClosed {
		t.Fatalf("close: %+v, %v", sum, err)
	}
	entries, err := attest.ReadBundle(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(key.Public().(ed25519.PublicKey)))
	if err != nil || len(rep.Sessions) != 1 || rep.Sessions[0].Calls != 2 {
		t.Fatalf("the signed bundle: %+v, %v", rep, err)
	}
	t.Logf("bundle: %d entries verified, one session of %d calls, chain closed", len(entries), rep.Sessions[0].Calls)

	// A session still open at shutdown is ended by the drain.
	left, err := remote.OpenSession(ctx, client.SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := left.RunJavaScript(ctx, sandbox.Request{Code: `console.log(1)`}); err != nil {
		t.Fatal(err)
	}
	d.stop(t, 2*time.Minute)
	logText := d.logText()
	if !strings.Contains(logText, left.Fingerprint()) {
		t.Errorf("the open session's fingerprint is not in the log")
	}
	after := runSandboxes(t, gw)
	for name := range after {
		if !before[name] {
			t.Errorf("sandbox %s left after the daemon drained", name)
		}
	}
}
