// Package daemonproc builds plimsolld from source and runs it on a loopback port for
// the example programs, so an example exercises the real daemon, not a copy of its
// wiring. Run the examples from the repository root: the build is ./cmd/plimsolld.
package daemonproc

import (
	"context"
	"errors"
	"fmt"
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

// Start runs binary with env added to this process's environment, on a free
// loopback port with the metrics listener off (the default port would collide with
// any other daemon on the machine), and waits up to ready for /readyz. The daemon's
// structured log goes to this process's stderr.
func Start(ctx context.Context, binary string, env []string, ready time.Duration) (*Daemon, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(append(os.Environ(), env...), "PLIMSOLL_ADDR="+addr, "PLIMSOLL_METRICS_ADDR=off")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plimsolld: %w", err)
	}
	d := &Daemon{BaseURL: "http://" + addr, cmd: cmd, exited: make(chan error, 1)}
	go func() { d.exited <- cmd.Wait() }()
	if err := d.waitReady(ctx, ready); err != nil {
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
