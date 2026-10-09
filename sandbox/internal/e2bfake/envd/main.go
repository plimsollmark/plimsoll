// Command envd is a stand-in for E2B's envd, the agent inside an E2B sandbox, for the
// e2b provider's session tests: run as root inside a local container, it really
// starts processes, so the session conformance suite can run against the provider
// without E2B. It speaks the part of envd's API the provider uses, as envd does:
//
//   - process.Process/Start (Connect server stream, JSON codec): the command run as
//     /bin/sh -c 'exec "$@"' -- cmd args, so it keeps the PID and envd is its parent;
//     as the user the Authorization: Basic header names, else the default user; a
//     Connect-Timeout-Ms header becomes a deadline that kills the process, and a
//     client that goes away without one leaves it running; stdin a pipe unless the
//     request sets "stdin": false.
//   - process.Process/SendInput (Connect unary, JSON): bytes onto a process's stdin.
//   - /files: a multipart upload (each part's file name its path, or ?path= for one)
//     written as root and then given to ?username=, as envd does; and a download.
//
// Every request needs the X-Access-Token the container was started with. It listens on
// a Unix socket, so the container needs no network.
//
// Invoked as setpriv, it is instead the part of util-linux's setpriv the provider uses
// (--reuid, --regid, --clear-groups, --no-new-privs, --), for an image whose setpriv is
// BusyBox's, which cannot change uid; E2B's Debian templates carry util-linux's.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// setpriv sets the uid, gid, groups and no-new-privs flag and execs the command, so it
// keeps the PID, as util-linux's setpriv does. no-new-privs is a thread's, so the thread
// that sets it is the one that execs.
func setpriv(args []string) {
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "setpriv: "+format+"\n", a...)
		os.Exit(127)
	}
	uid, gid, clear, nnp := -1, -1, false, false
	for len(args) > 0 && args[0] != "--" {
		a := args[0]
		args = args[1:]
		switch {
		case strings.HasPrefix(a, "--reuid="):
			uid, _ = strconv.Atoi(strings.TrimPrefix(a, "--reuid="))
		case strings.HasPrefix(a, "--regid="):
			gid, _ = strconv.Atoi(strings.TrimPrefix(a, "--regid="))
		case a == "--clear-groups":
			clear = true
		case a == "--no-new-privs":
			nnp = true
		default:
			fail("unrecognized option %q", a)
		}
	}
	if len(args) < 2 {
		fail("no command")
	}
	path, err := exec.LookPath(args[1])
	if err != nil {
		fail("%v", err)
	}
	runtime.LockOSThread()
	if clear {
		if err := syscall.Setgroups(nil); err != nil {
			fail("setgroups: %v", err)
		}
	}
	if gid >= 0 {
		if err := syscall.Setresgid(gid, gid, gid); err != nil {
			fail("setresgid: %v", err)
		}
	}
	if uid >= 0 {
		if err := syscall.Setresuid(uid, uid, uid); err != nil {
			fail("setresuid: %v", err)
		}
	}
	if nnp {
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0); errno != 0 {
			fail("prctl: %v", errno)
		}
	}
	fail("exec: %v", syscall.Exec(path, args[1:], os.Environ()))
}

func main() {
	if filepath.Base(os.Args[0]) == "setpriv" {
		setpriv(os.Args[1:])
	}
	socket := flag.String("socket", "/run/envd/envd.sock", "the Unix socket to listen on")
	token := flag.String("token", "", "the access token every request must carry")
	defaultUser := flag.String("default-user", "user", "the user a request that names none runs as")
	flag.Parse()
	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatal(err)
	}
	// The test process connects as another uid.
	if err := os.Chmod(*socket, 0o777); err != nil {
		log.Fatal(err)
	}
	s := &server{token: *token, defaultUser: *defaultUser, procs: map[int]*proc{}}
	log.Fatal(http.Serve(ln, s))
}

type server struct {
	token       string
	defaultUser string
	mu          sync.Mutex
	procs       map[int]*proc
}

type proc struct {
	stdin io.WriteCloser // nil when the process has none
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Access-Token") != s.token {
		http.Error(w, `{"code":"unauthenticated","message":"bad access token"}`, http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/process.Process/Start":
		s.start(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/process.Process/SendInput":
		s.sendInput(w, r)
	case r.URL.Path == "/files" && r.Method == http.MethodPost:
		s.upload(w, r)
	case r.URL.Path == "/files" && r.Method == http.MethodGet:
		s.download(w, r)
	default:
		http.Error(w, `{"code":"unimplemented"}`, http.StatusNotFound)
	}
}

// account is a user as /etc/passwd names it; "user", E2B's default, is uid 1000 here
// when the image has no account by that name.
func account(name string) (uid, gid int, home string, err error) {
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, 0, "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 6 && f[0] == name {
			uid, _ = strconv.Atoi(f[2])
			gid, _ = strconv.Atoi(f[3])
			return uid, gid, f[5], nil
		}
	}
	if name == "user" {
		return 1000, 1000, "/home/user", nil
	}
	return 0, 0, "", fmt.Errorf("invalid username: %q", name)
}

func (s *server) user(r *http.Request) string {
	if name, _, ok := r.BasicAuth(); ok {
		return name
	}
	return s.defaultUser
}

func connectError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": msg})
}

// frame writes one Connect stream frame.
func frame(w io.Writer, flags byte, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	hdr := make([]byte, 5)
	hdr[0] = flags
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(append(hdr, payload...)); err != nil {
		return err
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

func (s *server) start(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil || len(body) < 5 {
		connectError(w, http.StatusBadRequest, "invalid_argument", "no request frame")
		return
	}
	var req struct {
		Process struct {
			Cmd  string            `json:"cmd"`
			Args []string          `json:"args"`
			Envs map[string]string `json:"envs"`
			Cwd  *string           `json:"cwd"`
		} `json:"process"`
		Stdin *bool `json:"stdin"`
	}
	if err := json.Unmarshal(body[5:], &req); err != nil {
		connectError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	uid, gid, home, err := account(s.user(r))
	if err != nil {
		connectError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	cmd := exec.Command("/bin/sh", append([]string{"-c", `exec "$@"`, "--", req.Process.Cmd}, req.Process.Args...)...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + home}
	for k, v := range req.Process.Envs {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = home
	if req.Process.Cwd != nil {
		cmd.Dir = *req.Process.Cwd
	}
	if uid != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	}
	var stdin io.WriteCloser
	if req.Stdin == nil || *req.Stdin {
		if stdin, err = cmd.StdinPipe(); err != nil {
			connectError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		connectError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	pid := cmd.Process.Pid
	s.mu.Lock()
	s.procs[pid] = &proc{stdin: stdin}
	s.mu.Unlock()
	// The process's own lifetime: the header's deadline, not the request's, so a
	// client that goes away leaves it running.
	if ms, err := strconv.ParseInt(r.Header.Get("Connect-Timeout-Ms"), 10, 64); err == nil && ms > 0 {
		t := time.AfterFunc(time.Duration(ms)*time.Millisecond, func() { _ = cmd.Process.Kill() })
		defer t.Stop()
	}
	w.Header().Set("Content-Type", "application/connect+json")
	w.WriteHeader(http.StatusOK)
	// Frames go out from one goroutine at a time; once the client is gone, output is
	// read and dropped, so the process never blocks on a full pipe.
	var wmu sync.Mutex
	gone := false
	send := func(v any) {
		wmu.Lock()
		defer wmu.Unlock()
		if gone {
			return
		}
		if frame(w, 0, v) != nil || r.Context().Err() != nil {
			gone = true
		}
	}
	send(map[string]any{"event": map[string]any{"start": map[string]any{"pid": pid}}})
	var pumps sync.WaitGroup
	pump := func(rd io.Reader, key string) {
		defer pumps.Done()
		buf := make([]byte, 32<<10)
		for {
			n, err := rd.Read(buf)
			if n > 0 {
				send(map[string]any{"event": map[string]any{"data": map[string]any{key: buf[:n]}}})
			}
			if err != nil {
				return
			}
		}
	}
	pumps.Add(2)
	go pump(stdout, "stdout")
	go pump(stderr, "stderr")
	pumps.Wait()
	werr := cmd.Wait()
	s.mu.Lock()
	delete(s.procs, pid)
	s.mu.Unlock()
	state := cmd.ProcessState
	end := map[string]any{"exitCode": state.ExitCode(), "exited": state.Exited(), "status": state.String()}
	if werr != nil && !errors.As(werr, new(*exec.ExitError)) {
		end["error"] = werr.Error()
	}
	send(map[string]any{"event": map[string]any{"end": end}})
	wmu.Lock()
	if !gone {
		_ = frame(w, 2, map[string]any{})
	}
	wmu.Unlock()
}

func (s *server) sendInput(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Process struct {
			PID int `json:"pid"`
		} `json:"process"`
		Input struct {
			Stdin []byte `json:"stdin"`
		} `json:"input"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&req); err != nil {
		connectError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	s.mu.Lock()
	p := s.procs[req.Process.PID]
	s.mu.Unlock()
	if p == nil {
		connectError(w, http.StatusNotFound, "not_found", "process not found")
		return
	}
	if p.stdin == nil {
		connectError(w, http.StatusBadRequest, "failed_precondition", "stdin not enabled or closed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := p.stdin.Write(req.Input.Stdin)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			connectError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	case <-ctx.Done():
		connectError(w, http.StatusGatewayTimeout, "deadline_exceeded", "stdin write blocked")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "{}")
}

func (s *server) upload(w http.ResponseWriter, r *http.Request) {
	uid, gid, _, err := account(r.URL.Query().Get("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	single := r.URL.Query().Get("path")
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The whole file name, which Part.FileName cuts to its last element.
		_, disp, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		dest := disp["filename"]
		if single != "" {
			dest = single
		}
		if !filepath.IsAbs(dest) {
			http.Error(w, "relative path", http.StatusBadRequest)
			return
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, io.LimitReader(part, 64<<20)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// As root, then given to the user: what real envd does, links and all.
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(dest, buf.Bytes(), 0o644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.Chown(dest, uid, gid); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "[]")
}

func (s *server) download(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(r.URL.Query().Get("path"))
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}
