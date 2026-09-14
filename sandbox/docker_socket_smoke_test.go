package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The socket probe exists because whether a guest may connect to a host Unix
// socket is a property of the OCI runtime (runsc: --host-uds), and the grant path
// is exactly one such socket. These tests pin that the probe is only in the script
// when asked, and that an unreachable socket fails readiness with the fix named.

func TestSmokeProbeScriptConnectsOnlyWhenAsked(t *testing.T) {
	with, without := smokeProbeScript(false, true), smokeProbeScript(false, false)
	if !strings.Contains(with, `require("net").connect("`+containerSocketPath+`")`) {
		t.Fatal("socket script does not connect to the broker socket path")
	}
	if strings.Contains(without, `require("net")`) || !strings.Contains(without, "finish(null);") {
		t.Fatal("a probe built without the socket check still connects, or never emits")
	}
}

func TestStartSmokeSocketAnswersPong(t *testing.T) {
	path, closeFn, err := startSmokeSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode = %v, %v; want 0666 so the uid-1000 guest can connect", info, err)
	}
	c, err := dialUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil || strings.TrimSpace(string(buf[:n])) != "pong" {
		t.Fatalf("reply = %q, %v; want pong", buf[:n], err)
	}
}

// TestDockerSmokeSocketProbeFailsClosed mounts a plain file where the broker
// socket would be: the connect must fail, and the probe must turn that into a
// readiness error that names the runtime fix, under whichever runtime is
// configured.
func TestDockerSmokeSocketProbeFailsClosed(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	state, err := d.executionState()
	if err != nil {
		t.Fatal(err)
	}
	notASocket := filepath.Join(t.TempDir(), "host-api.sock")
	if err := os.WriteFile(notASocket, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	err = d.smokeProbe(ctx, state, state.imageID, false, false, notASocket)
	if err == nil || !strings.Contains(err.Error(), "--host-uds=open") || !strings.Contains(err.Error(), containerSocketPath) {
		t.Fatalf("probe against a non-socket returned %v; want a readiness error naming the socket path and the runsc fix", err)
	}
}
