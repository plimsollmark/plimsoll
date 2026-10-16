//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package remotehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

func checkSocket(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o600 || int(owner.Uid) != os.Geteuid() {
		return errors.New("local control path is not an owner-only socket")
	}
	return nil
}

func listenControl(path string) (net.Listener, error) {
	if err := checkSocket(path); err == nil {
		conn, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			_ = conn.Close()
			return nil, errors.New("local control socket is already in use")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
			return nil, dialErr
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func callControl(ctx context.Context, path, command string) (OperatorResult, bool, error) {
	if err := checkSocket(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return OperatorResult{}, false, nil
		}
		return OperatorResult{}, false, err
	}
	dialer := &net.Dialer{Timeout: time.Second}
	// Probe first to distinguish a stale socket from a request which may already
	// have changed state. A failed HTTP exchange is never retried offline.
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrNotExist) {
			return OperatorResult{}, false, nil
		}
		return OperatorResult{}, false, err
	}
	defer conn.Close()
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	b, _ := json.Marshal(map[string]string{"command": command})
	req, err := http.NewRequestWithContext(ctx, "POST", "http://local/", bytes.NewReader(b))
	if err != nil {
		return OperatorResult{}, true, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: transport, Timeout: 7 * time.Second}).Do(req)
	if err != nil {
		return OperatorResult{}, true, errors.New("local operation response was lost; status must be checked before retrying")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return OperatorResult{}, true, errors.New("running server refused local operation")
	}
	var result OperatorResult
	err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result)
	return result, true, err
}
