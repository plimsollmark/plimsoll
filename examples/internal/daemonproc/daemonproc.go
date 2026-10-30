// Package daemonproc builds plimsolld from source and runs it on a loopback port for
// the example programs, so an example exercises the real daemon, not a copy of its
// wiring. Run the examples from the repository root: the build is ./cmd/plimsolld.
package daemonproc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// drainGrace is how long a daemon whose context ends gets to drain (delete its
// sandboxes) after its SIGTERM before it is killed, as long as the examples give Stop.
const drainGrace = 2 * time.Minute

// passedEnv are the only variables of this process's environment a daemon gets besides
// Options.Env: where to find programs, a home, a temporary directory and the docker
// daemon. A SANDBOX_ or PLIMSOLL_ setting an example does not make itself (a runtime,
// a seccomp file, hardened mode, a token) never configures the daemon from the shell
// that ran it, so a published page describes the daemon its program started (release
// review, 2026-10-29).
var passedEnv = []string{"PATH", "HOME", "TMPDIR", "DOCKER_HOST"}

// Build compiles plimsolld into dir and returns the binary's path.
func Build(ctx context.Context, dir string) (string, error) {
	binary := filepath.Join(dir, "plimsolld")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/plimsolld")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build plimsolld (run this from the repository root): %w", err)
	}
	return binary, nil
}

// Daemon is a running plimsolld.
type Daemon struct {
	BaseURL string
	// MetricsURL is the daemon's GET /metrics on a loopback port of its own when
	// Options.Metrics asked for it, else "".
	MetricsURL string
	cmd        *exec.Cmd
	exited     chan error
	termOnce   sync.Once
	termErr    error
}

// Options are what Start runs the daemon with besides its binary.
type Options struct {
	Env   []string      // the daemon's settings; of this process's environment it gets passedEnv only
	Ready time.Duration // how long to wait for /readyz
	// Log receives the daemon's structured log (its audit lines included); nil is this
	// process's stderr. An example that reads the audit lines back passes its own.
	Log io.Writer
	// Metrics serves the daemon's /metrics on a free loopback port (Daemon.MetricsURL)
	// instead of turning it off, for an example that reads the host-call series back.
	Metrics bool
}

// Start runs binary with o.Env and passedEnv as its environment, on a free loopback
// port with the metrics listener off (the default port would collide with any other
// daemon on the machine), and waits up to o.Ready for /readyz. A daemon that exits
// first is reported at once, with its exit status: four examples once copied a starter
// of their own that never noticed, so a daemon that died at startup cost the whole wait
// (review B9, 2026-10-23).
func Start(ctx context.Context, binary string, o Options) (*Daemon, error) {
	addr, err := FreeAddr()
	if err != nil {
		return nil, err
	}
	log := o.Log
	if log == nil {
		log = os.Stderr
	}
	metrics, metricsURL := "off", ""
	if o.Metrics {
		if metrics, err = FreeAddr(); err != nil {
			return nil, err
		}
		metricsURL = "http://" + metrics + "/metrics"
	}
	var env []string
	for _, name := range passedEnv {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(append(env, o.Env...), "PLIMSOLL_ADDR="+addr, "PLIMSOLL_METRICS_ADDR="+metrics)
	cmd.Stdout = log
	cmd.Stderr = log
	// A process group of its own, so a terminal's Ctrl-C reaches this process alone,
	// which then stops the daemon with exactly one SIGTERM: plimsolld force-quits its
	// drain on a second signal, and in this process's group it would get the terminal's
	// SIGINT and then that SIGTERM.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	d := &Daemon{BaseURL: "http://" + addr, MetricsURL: metricsURL, cmd: cmd, exited: make(chan error, 1)}
	// When ctx ends (an example's signal.NotifyContext on Ctrl-C), the daemon is stopped
	// as Stop stops it, so it drains and deletes its sandboxes, and killed only after
	// drainGrace. exec's default is SIGKILL, which left every session and pool container
	// and the daemon's socket directories behind (release review,
	// 2026-10-29).
	cmd.Cancel = d.terminate
	cmd.WaitDelay = drainGrace
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plimsolld: %w", err)
	}
	go func() { d.exited <- cmd.Wait() }()
	if err := d.waitReady(ctx, o.Ready); err != nil {
		d.Stop(5 * time.Second)
		return nil, err
	}
	return d, nil
}

func (d *Daemon) waitReady(ctx context.Context, within time.Duration) error {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		select {
		case err := <-d.exited:
			d.exited <- err
			return fmt.Errorf("plimsolld exited before it was ready: %v", err)
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.BaseURL+"/readyz", nil)
		if err != nil {
			return err
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("plimsolld did not become ready within %v", within)
}

// terminate sends the daemon its one SIGTERM, however many times it is asked: by Stop,
// by the context's end, or both.
func (d *Daemon) terminate() error {
	d.termOnce.Do(func() { d.termErr = d.cmd.Process.Signal(syscall.SIGTERM) })
	return d.termErr
}

// Stop asks the daemon to shut down (SIGTERM: it stops taking runs and drains, which
// for a provider with sandboxes means deleting them) and kills it if it has not
// exited within grace.
func (d *Daemon) Stop(grace time.Duration) error {
	if d.cmd.Process == nil {
		return nil
	}
	_ = d.terminate()
	select {
	case err := <-d.exited:
		d.exited <- err
		var exit *exec.ExitError
		// A daemon that drained after its context ended exits 0, which Wait reports as
		// the context's error; a child holding the log open past drainGrace is ErrWaitDelay.
		if err != nil && !errors.As(err, &exit) && !errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, exec.ErrWaitDelay) {
			return err
		}
		return nil
	case <-time.After(grace):
		_ = d.cmd.Process.Kill()
		d.exited <- <-d.exited
		return fmt.Errorf("plimsolld did not exit within %v of SIGTERM and was killed", grace)
	}
}

// ClientsFile writes, in dir, a caller registry (PLIMSOLL_CLIENTS_FILE) naming one
// caller, id, with the code:run scope, and returns a fresh random token for it and the
// file's path. The file holds only the token's SHA-256, as the daemon reads it.
func ClientsFile(dir, id string) (token, path string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	body, err := json.Marshal(map[string]any{"clients": []map[string]any{
		{"id": id, "token_sha256": hex.EncodeToString(sum[:]), "scopes": []string{"code:run"}}}})
	if err != nil {
		return "", "", err
	}
	path = filepath.Join(dir, "clients.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", "", err
	}
	return token, path, nil
}

// FreeAddr returns a loopback address whose port was free a moment ago, for a daemon's
// listener.
func FreeAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().String()
	return addr, l.Close()
}
