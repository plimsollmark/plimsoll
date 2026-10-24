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
	"syscall"
	"time"
)

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
	cmd     *exec.Cmd
	exited  chan error
}

// Options are what Start runs the daemon with besides its binary.
type Options struct {
	Env   []string      // added to this process's environment
	Ready time.Duration // how long to wait for /readyz
	// Log receives the daemon's structured log (its audit lines included); nil is this
	// process's stderr. An example that reads the audit lines back passes its own.
	Log io.Writer
}

// Start runs binary with o.Env added to this process's environment, on a free loopback
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
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(append(os.Environ(), o.Env...), "PLIMSOLL_ADDR="+addr, "PLIMSOLL_METRICS_ADDR=off")
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plimsolld: %w", err)
	}
	d := &Daemon{BaseURL: "http://" + addr, cmd: cmd, exited: make(chan error, 1)}
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

// Stop asks the daemon to shut down (SIGTERM: it stops taking runs and drains, which
// for a provider with sandboxes means deleting them) and kills it if it has not
// exited within grace.
func (d *Daemon) Stop(grace time.Duration) error {
	if d.cmd.Process == nil {
		return nil
	}
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-d.exited:
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			return err
		}
		return nil
	case <-time.After(grace):
		_ = d.cmd.Process.Kill()
		<-d.exited
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
