package sandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The E2B session tests below run against a recording stand-in for E2B: one test
// server answering the control plane and envd's process API, which runs nothing and
// keeps every process start it is sent. They prove how each program of plimsoll's in
// an E2B session is started (the working folder, the environment, the program's path,
// the user), which is what decides whether such a program can come to load a file the
// session wrote. The docker-backed stand-in (e2b_session_docker_test.go) runs the same
// starts for real; the live suite runs them on E2B.

// e2bStart is one process.Process/Start as envd receives it.
type e2bStart struct {
	User  string
	Cmd   string
	Args  []string
	Cwd   string
	Envs  map[string]string
	Stdin bool
}

func (s e2bStart) argv() []string { return append([]string{s.Cmd}, s.Args...) }

// e2bRecBins are the paths the stand-in's open reports, as a Debian template's would be.
var e2bRecBins = map[string]string{"node": "/usr/bin/node", "sh": "/bin/sh", "setpriv": "/usr/bin/setpriv", "python3": "/usr/bin/python3"}

// e2bRecEnv is envd's environment for root as /usr/bin/env -0 prints it on the stand-in:
// envd's PATH, HOME, USER, LOGNAME, a template variable, and the reader's own PWD.
const e2bRecEnv = "PATH=/usr/local/bin:/usr/bin:/bin\x00HOME=/root\x00USER=root\x00LOGNAME=root\x00TEMPLATE_SETTING=on\x00PWD=/\x00"

// e2bRecLaunch marks the launcher's script in the starts this file's tests make.
const e2bRecLaunch = "plimsoll-test-launch-script"

type e2bRecorder struct {
	mu      sync.Mutex
	starts  []e2bStart
	md      map[string]string
	network map[string]any
	bins    map[string]string
	// openExit and openStderr, when openExit is set, are how the open ends instead of
	// its report: a node that does not know sessionkit.NodeSignalFlag exits 9.
	openExit   int
	openStderr string
	creates    int
	deletes    int // DELETEs of the stand-in's sandbox
	// stagerEnd, when set, is the stager's end event instead of an exit 0, and
	// stagerOut its stdout; filesFail fails every file write.
	stagerEnd, stagerOut string
	filesFail            bool
}

func (r *e2bRecorder) recorded() []e2bStart {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.starts)
}

// newE2BRecorder is an E2B provider pointed at a recording stand-in.
func newE2BRecorder(t *testing.T) (*E2B, *e2bRecorder) {
	t.Helper()
	r := &e2bRecorder{bins: e2bRecBins}
	srv := httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(srv.Close)
	return &E2B{APIKey: "k", APIBase: srv.URL, EnvdHost: func(string) string { return srv.URL },
		DefaultTimeout: 10 * time.Second, MaxTimeout: 20 * time.Second}, r
}

const e2bRecID = "sb-rec"

func (r *e2bRecorder) serve(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.Method == http.MethodPost && req.URL.Path == "/sandboxes":
		var body struct {
			Metadata map[string]string `json:"metadata"`
			Network  map[string]any    `json:"network"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		r.mu.Lock()
		r.md, r.network = body.Metadata, body.Network
		r.creates++
		r.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"sandboxID":"`+e2bRecID+`","envdAccessToken":"access","trafficAccessToken":"traffic"}`)
	case req.Method == http.MethodGet && req.URL.Path == "/sandboxes/"+e2bRecID:
		r.mu.Lock()
		rec := map[string]any{"sandboxID": e2bRecID, "templateID": "base", "state": "running", "metadata": r.md,
			"network": r.network, "memoryMB": 512, "cpuCount": 2, "diskSizeMB": 1024}
		r.mu.Unlock()
		_ = json.NewEncoder(w).Encode(rec)
	case req.Method == http.MethodDelete:
		r.mu.Lock()
		if req.URL.Path == "/sandboxes/"+e2bRecID {
			r.deletes++
		}
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case req.Method == http.MethodPost && req.URL.Path == "/sandboxes/"+e2bRecID+"/pause":
		w.WriteHeader(http.StatusNoContent)
	case req.Method == http.MethodPost && req.URL.Path == "/v2/sandboxes/"+e2bRecID+"/connect":
		_, _ = io.WriteString(w, `{"sandboxID":"`+e2bRecID+`"}`)
	case req.Method == http.MethodPost && req.URL.Path == "/files":
		r.mu.Lock()
		fail := r.filesFail
		r.mu.Unlock()
		if fail {
			http.Error(w, "the stand-in refuses the write", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `[]`)
	case req.Method == http.MethodPost && req.URL.Path == "/process.Process/SendInput":
		_, _ = io.WriteString(w, `{}`)
	case req.Method == http.MethodPost && req.URL.Path == "/process.Process/Start":
		r.start(w, req)
	default:
		http.Error(w, "unexpected "+req.Method+" "+req.URL.Path, http.StatusNotFound)
	}
}

func (r *e2bRecorder) start(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)
	var body struct {
		Process struct {
			Cmd  string            `json:"cmd"`
			Args []string          `json:"args"`
			Cwd  string            `json:"cwd"`
			Envs map[string]string `json:"envs"`
		} `json:"process"`
		Stdin bool `json:"stdin"`
	}
	if len(raw) < 5 || json.Unmarshal(raw[5:], &body) != nil {
		http.Error(w, "no request frame", http.StatusBadRequest)
		return
	}
	user, _, _ := req.BasicAuth()
	s := e2bStart{User: user, Cmd: body.Process.Cmd, Args: body.Process.Args, Cwd: body.Process.Cwd, Envs: body.Process.Envs, Stdin: body.Stdin}
	r.mu.Lock()
	r.starts = append(r.starts, s)
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/connect+json")
	_, _ = w.Write(frame(0, []byte(`{"event":{"start":{"pid":42}}}`)))
	if s.Stdin {
		// A relay: its stream stays open until the session lets go of it.
		w.(http.Flusher).Flush()
		<-req.Context().Done()
		return
	}
	stdout, stderr, exit := "", "", 0
	switch e2bProgram(s) {
	case "open":
		b, _ := json.Marshal(map[string]any{"envd": 7, "bins": r.bins})
		stdout = string(b)
		r.mu.Lock()
		if r.openExit != 0 {
			stdout, stderr, exit = "", r.openStderr, r.openExit
		}
		r.mu.Unlock()
	case "environment read":
		stdout = e2bRecEnv
	case "lister":
		stdout = `{"ptrace":"1","procs":[{"pid":1,"ppid":0,"state":"S","start":"1","uid":0,"cmd":"init","cmdHex":"696e697400"}]}`
	case "artifact reader":
		stdout = `{"artifacts":[],"truncated":false}`
	case "stager":
		r.mu.Lock()
		stdout = r.stagerOut
		r.mu.Unlock()
	}
	data, _ := json.Marshal(map[string]any{"event": map[string]any{"data": map[string]any{"stdout": base64.StdEncoding.EncodeToString([]byte(stdout))}}})
	_, _ = w.Write(frame(0, data))
	if stderr != "" {
		data, _ = json.Marshal(map[string]any{"event": map[string]any{"data": map[string]any{"stderr": base64.StdEncoding.EncodeToString([]byte(stderr))}}})
		_, _ = w.Write(frame(0, data))
	}
	end := fmt.Sprintf(`{"exitCode":%d,"exited":true}`, exit)
	r.mu.Lock()
	if e2bProgram(s) == "stager" && r.stagerEnd != "" {
		end = r.stagerEnd
	}
	r.mu.Unlock()
	_, _ = w.Write(frame(0, []byte(`{"event":{"end":`+end+`}}`)))
	_, _ = w.Write(frame(0x2, []byte(`{}`)))
}

// e2bProgram names the program of plimsoll's a start is, by what it runs.
// e2bRelayScript is the relay's script as RelayArgv passes it: the argument after -e,
// wherever node's own flags put it.
func e2bRelayScript() string {
	r := sessionkit.RelayArgv("python", e2bSessionWork)
	return r[slices.Index(r, "-e")+1]
}

func e2bProgram(s e2bStart) string {
	argv := s.argv()
	has := func(x string) int { return slices.Index(argv, x) }
	switch {
	case s.Cmd == e2bEnv && slices.Equal(s.Args, []string{"-0"}):
		return "environment read"
	case has(e2bSessionJS) >= 0 && has(e2bSessionJS)+1 < len(argv):
		switch argv[has(e2bSessionJS)+1] {
		case "open":
			return "open"
		case "stage":
			return "stager"
		case "artifacts":
			return "artifact reader"
		}
	case has(sessionkit.ListScript) >= 0:
		return "lister"
	case has(sessionkit.SweepScript) >= 0:
		return "sweep"
	case has(sessionkit.CheckScript) >= 0:
		return "identity check"
	case has(e2bRelayScript()) >= 0:
		return "relay"
	case has(e2bRecLaunch) >= 0:
		return "launcher"
	case has(e2bGuestStart) >= 0:
		return "guest command"
	}
	return "unknown"
}

// controlTail checks that argv starts as sessionkit.ControlArgvClosed starts a program
// (/usr/bin/env -i, the control PATH, the empty OpenSSL settings file), skips the
// variables after them, and returns the variables and the program with its arguments.
func controlTail(argv []string) (vars, rest []string, err error) {
	head := []string{e2bEnv, "-i", "PATH=" + sessionkit.ControlPathClosed, sessionkit.ControlOpenSSL}
	if len(argv) < len(head) || !slices.Equal(argv[:len(head)], head) {
		return nil, nil, fmt.Errorf("starts %q, not %q", argv[:min(len(argv), len(head))], head)
	}
	rest = argv[len(head):]
	for len(rest) > 0 && strings.Contains(rest[0], "=") && !strings.HasPrefix(rest[0], "/") {
		vars, rest = append(vars, rest[0]), rest[1:]
	}
	if len(rest) == 0 {
		return nil, nil, fmt.Errorf("%q names no program", argv)
	}
	return vars, rest, nil
}

// checkE2BStart checks one start of plimsoll's against what this file requires of
// every one: as root, in /, with no variable of the request's, the program it runs
// named by the path the open pinned (the open's own node excepted, found by name before
// any of the session's code), and a guest process handed the guest's environment.
func checkE2BStart(s e2bStart, bins map[string]string) error {
	name := e2bProgram(s)
	if s.User != e2bRootUser {
		return fmt.Errorf("%s starts as %q, not root", name, s.User)
	}
	if s.Cwd != "/" {
		return fmt.Errorf("%s starts in %q, not /", name, s.Cwd)
	}
	if len(s.Envs) != 0 {
		return fmt.Errorf("%s is handed variables through envd: %v", name, s.Envs)
	}
	if s.Stdin != (name == "relay") {
		return fmt.Errorf("%s has stdin %v", name, s.Stdin)
	}
	switch name {
	case "unknown":
		return fmt.Errorf("a start no program of plimsoll's makes: %q", s.argv())
	case "environment read":
		return nil
	}
	vars, rest, err := controlTail(s.argv())
	if err != nil {
		return fmt.Errorf("%s %w", name, err)
	}
	prog := rest[0]
	switch name {
	case "open":
		if prog != "node" {
			return fmt.Errorf("the open runs %q; want node, found by name before any of the session's code", prog)
		}
		return e2bNodeFlag(name, rest)
	case "lister", "sweep", "identity check", "stager", "relay":
		if prog != bins["node"] {
			return fmt.Errorf("%s runs %q, not the pinned node %s", name, prog, bins["node"])
		}
		if err := e2bNodeFlag(name, rest); err != nil {
			return err
		}
		if name == "relay" && !slices.Equal(vars, []string{"PLIMSOLL_RELAY_UID=61000"}) {
			return fmt.Errorf("the relay's variables are %q", vars)
		}
		return nil
	}
	// The rest run as the guest: the pinned setpriv drops to it.
	drop := []string{"--reuid=61000", "--regid=61000", "--clear-groups", "--no-new-privs", "--"}
	if prog != bins["setpriv"] || len(rest) < 1+len(drop) || !slices.Equal(rest[1:1+len(drop)], drop) {
		return fmt.Errorf("%s drops to the guest as %q, not by the pinned setpriv %s", name, rest[:min(len(rest), 1+len(drop))], bins["setpriv"])
	}
	inner := rest[1+len(drop):]
	switch name {
	case "artifact reader", "launcher":
		_, irest, err := controlTail(inner)
		if err != nil {
			return fmt.Errorf("%s, as the guest, %w", name, err)
		}
		want := map[string]string{"artifact reader": bins["node"], "launcher": bins["sh"]}[name]
		if irest[0] != want {
			return fmt.Errorf("%s runs %q, not the pinned %s", name, irest[0], want)
		}
		if name == "artifact reader" {
			return e2bNodeFlag(name, irest)
		}
		return nil
	}
	// A guest command: the pinned sh changes into the work folder as the guest, then
	// /usr/bin/env -i hands the command the guest's environment.
	head := []string{bins["sh"], "-c", e2bGuestStart, "sh", e2bSessionWork, e2bEnv, "-i"}
	if len(inner) < len(head) || !slices.Equal(inner[:len(head)], head) {
		return fmt.Errorf("a guest command starts %q, not %q", inner[:min(len(inner), len(head))], head)
	}
	env := inner[len(head):]
	for _, want := range []string{"PATH=/usr/local/bin:/usr/bin:/bin", "TEMPLATE_SETTING=on", "USER=root", "HOME=" + e2bSessionWork} {
		if !slices.Contains(env, want) {
			return fmt.Errorf("a guest command's environment %q lacks %s", env, want)
		}
	}
	for _, gone := range []string{"HOME=/root", "PWD=/"} {
		if slices.Contains(env, gone) {
			return fmt.Errorf("a guest command's environment %q carries the reader's %s", env, gone)
		}
	}
	// The guest's own node keeps node's ordinary behavior (sessionkit.GuestNode).
	if slices.Contains(env, sessionkit.NodeSignalFlag) {
		return fmt.Errorf("a guest command %q carries %s, which only plimsoll's own node programs take", env, sessionkit.NodeSignalFlag)
	}
	return nil
}

// e2bNodeFlag requires a node program of plimsoll's own, rest from its program on, to
// start with sessionkit.NodeSignalFlag right after the program (sessionkit.NodeArgv).
func e2bNodeFlag(name string, rest []string) error {
	if len(rest) < 2 || rest[1] != sessionkit.NodeSignalFlag {
		return fmt.Errorf("%s starts %q, without %s right after its node", name, rest[:min(len(rest), 2)], sessionkit.NodeSignalFlag)
	}
	return nil
}

// Every program of plimsoll's an E2B session starts is started as checkE2BStart
// requires: the open, the environment read, the lister, the stager, a snippet's and a
// step's commands, the artifact reader, the sweep after each call and after a resume,
// the identity check, the launcher and a relay.
func TestE2BSessionStartsEveryProgramInRootClosed(t *testing.T) {
	e, rec := newE2BRecorder(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := e.OpenSession(ctx, SessionOptions{Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close(context.Background())
	s := sess.(*e2bSession)
	if res, err := s.RunJavaScript(ctx, Request{Code: "1"}); err != nil || res.ExitCode != 0 {
		t.Fatalf("snippet: %+v, %v", res, err)
	}
	if _, err := s.Suspend(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := s.RunProject(ctx, ProjectRequest{Files: []File{{Path: "a.txt", Content: "a"}}, Steps: []string{"true"}, Artifacts: []string{"out.txt"}})
	if err != nil || res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("project: %+v, %v", res, err)
	}
	// The interpreter's programs: what sessionkit hands the launcher, the identity
	// check and the relay, as a cell would.
	in := &s.life.Interps
	if !maps2Equal(in.Bins, map[string]string{"node": e2bRecBins["node"], "python3": e2bRecBins["python3"]}) {
		t.Fatalf("Interps.Bins = %v; want the pinned node and python3", in.Bins)
	}
	wantStart := []string{e2bEnv, "-i", "LOGNAME=root", "PATH=/usr/local/bin:/usr/bin:/bin", "TEMPLATE_SETTING=on", "USER=root", "HOME=" + e2bSessionWork}
	if !slices.Equal(in.Start, wantStart) {
		t.Fatalf("Interps.Start = %q; want %q", in.Start, wantStart)
	}
	launch := append(append([]string{"sh", "-c", e2bRecLaunch, "sh"}, in.Start...), e2bRecBins["python3"], "-I", "-c", "kernel")
	if _, err := s.launch(ctx, launch, map[string]string{"PLIMSOLL_INTERP_DIR": "/tmp/.plimsoll-interp/python", "PLIMSOLL_WORK": e2bSessionWork}, nil, 4096, 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := s.check(ctx, sessionkit.CheckArgv([]string{"interp:42:1:00"}), nil, nil, 4096, 4096); err != nil {
		t.Fatal(err)
	}
	relay := sessionkit.RelayArgv("python", e2bSessionWork)
	relay[0] = e2bRecBins["node"]
	att, err := s.attach(relay, nil)
	if err != nil {
		t.Fatal(err)
	}
	att.Close()

	seen := map[string]int{}
	for _, st := range rec.recorded() {
		seen[e2bProgram(st)]++
		if err := checkE2BStart(st, e2bRecBins); err != nil {
			t.Error(err)
		}
	}
	for _, name := range []string{"open", "environment read", "lister", "stager", "guest command", "artifact reader", "sweep", "identity check", "launcher", "relay"} {
		if seen[name] == 0 {
			t.Errorf("no %s was started (starts: %v)", name, seen)
		}
	}
	// A snippet's node and a step's sh, and the resume's sweep with every call's.
	if seen["guest command"] < 2 || seen["sweep"] < 3 {
		t.Errorf("starts by program: %v; want two guest commands and three sweeps", seen)
	}
}

func maps2Equal(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// An open that pins no node, or a path the guest writes, or a relative one, refuses the
// session: every later start would otherwise name what the open did not check.
func TestE2BSessionOpenRefusesBadPins(t *testing.T) {
	for name, bins := range map[string]map[string]string{
		"no node":         {"sh": "/bin/sh", "setpriv": "/usr/bin/setpriv"},
		"no setpriv":      {"node": "/usr/bin/node", "sh": "/bin/sh"},
		"no sh":           {"node": "/usr/bin/node", "setpriv": "/usr/bin/setpriv"},
		"relative":        {"node": "bin/node", "sh": "/bin/sh", "setpriv": "/usr/bin/setpriv"},
		"unclean":         {"node": "/usr/bin/../../work/node", "sh": "/bin/sh", "setpriv": "/usr/bin/setpriv"},
		"in /work":        {"node": "/work/node", "sh": "/bin/sh", "setpriv": "/usr/bin/setpriv"},
		"in /tmp":         {"node": "/usr/bin/node", "sh": "/tmp/sh", "setpriv": "/usr/bin/setpriv"},
		"in /dev/shm":     {"node": "/usr/bin/node", "sh": "/bin/sh", "setpriv": "/dev/shm/setpriv"},
		"in the stage":    {"node": "/usr/bin/node", "sh": "/bin/sh", "setpriv": e2bSessionStage + "/setpriv"},
		"in a call's dir": {"node": "/usr/bin/node", "sh": "/bin/sh", "setpriv": e2bSessionOwn + "/x/setpriv"},
	} {
		t.Run(name, func(t *testing.T) {
			e, rec := newE2BRecorder(t)
			rec.bins = bins
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if s, err := e.OpenSession(ctx, SessionOptions{Lifetime: time.Minute}); err == nil {
				s.Close(ctx)
				t.Fatalf("a session opened with the pins %v", bins)
			}
			for _, st := range rec.recorded() {
				if p := e2bProgram(st); p != "open" {
					t.Errorf("after a refused open, a %s was started: %q", p, st.argv())
				}
			}
		})
	}
}

// The open's check of a program's path (e2b_session.js untrusted and pin), run by node
// with the test's own uid standing in for the guest's: a path through a folder the guest
// owns or everyone writes is refused, and so is a control PATH with such a folder or a
// relative entry, while a system program is kept.
func TestE2BSessionPinRefusesWhatTheGuestCanChange(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not on PATH")
	}
	if os.Getuid() == 0 {
		t.Skip("as root, the test's uid cannot stand in for the guest's")
	}
	harness := `if (mode === "plimsoll-test-untrusted") {
  const [guest, ...paths] = args; const out = {};
  for (const p of paths) { try { out[p] = untrusted(p, Number(guest), "file"); } catch (e) { out[p] = "error " + e.code; } }
  process.stdout.write(JSON.stringify(out)); process.exit(0);
}
if (mode === "plimsoll-test-pin") { process.stdout.write(JSON.stringify(pin(Number(args[0])))); process.exit(0); }
`
	src := strings.Replace(e2bSessionJS, "switch (mode) {", harness+"switch (mode) {", 1)
	if src == e2bSessionJS {
		t.Fatal("e2b_session.js has no switch (mode) to put the harness before")
	}
	dir := t.TempDir()
	mine := filepath.Join(dir, "node")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "env")
	if err := os.Symlink("/usr/bin/env", link); err != nil {
		t.Fatal(err)
	}
	uid := fmt.Sprint(os.Getuid())
	run := func(path string, args ...string) (string, string, error) {
		cmd := exec.Command(node, append([]string{"-e", src}, args...)...)
		cmd.Env = []string{"PATH=" + path}
		cmd.Dir = "/"
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		return string(out), stderr.String(), err
	}
	// This file, in folders the test's uid owns that no other user can write: refused
	// for its owner alone.
	own, err := filepath.Abs("e2b_session_start_test.go")
	if err != nil {
		t.Fatal(err)
	}
	out, stderr, err := run("/usr/bin:/bin", "plimsoll-test-untrusted", uid, "/usr/bin/env", mine, link, own)
	if err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	var why map[string]string
	if err := json.Unmarshal([]byte(out), &why); err != nil {
		t.Fatalf("%q: %v", out, err)
	}
	if why["/usr/bin/env"] != "" {
		t.Errorf("the system's /usr/bin/env was refused: %s", why["/usr/bin/env"])
	}
	for _, p := range []string{mine, link} {
		if why[p] == "" {
			t.Errorf("%s, in a folder the guest can write, was kept", p)
		}
	}
	if !strings.Contains(why[own], "owned by the guest") {
		t.Errorf("%s, under folders the guest owns, was not refused for its owner: %q", own, why[own])
	}
	for name, path := range map[string]string{"a folder the guest owns": dir + ":/usr/bin:/bin", "a relative entry": "bin:/usr/bin:/bin"} {
		if out, stderr, err := run(path, "plimsoll-test-pin", uid); err == nil || !strings.Contains(stderr, "control PATH") {
			t.Errorf("pin with %s on the control PATH: %q, %q, %v; want a refusal naming the control PATH", name, out, stderr, err)
		}
	}
}

// A session on a template whose node does not accept sessionkit.NodeSignalFlag is refused
// as unsupported and not dispatched, with plimsoll's words for it (the version needed and
// where the template that has it comes from), never the "machine cannot hold a session"
// error, which a caller sees as an internal one (finding rust-native-helper-35). Twice:
// when the open itself exits 9 on the flag, after which the sandbox is deleted, and when
// the startup check has already read a node too old, when no sandbox is made at all.
func TestE2BSessionRefusesANodeTooOldForTheSignalFlag(t *testing.T) {
	t.Parallel()
	check := func(t *testing.T, err error, found string) {
		t.Helper()
		if err == nil {
			t.Fatal("the session opened on a node too old for the signal flag")
		}
		if !errors.Is(err, sessionkit.ErrNodeFlagRefused) || !errors.Is(err, ErrUnsupported) {
			t.Errorf("the refusal %q does not wrap both sessionkit.ErrNodeFlagRefused and ErrUnsupported", err)
		}
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalUnsupported {
			t.Errorf("the refusal is marked %v, %v; want not dispatched, unsupported", reason, ok)
		}
		for _, want := range []string{sessionkit.NodeVersionNeeded, "e2b/README.md", "E2B_TEMPLATE", "Single runs work", found} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal %q does not say %q", err, want)
			}
		}
		if strings.Contains(err.Error(), "cannot hold a session") {
			t.Errorf("the refusal %q is the open's general failure", err)
		}
	}
	t.Run("the open exits 9 on the flag", func(t *testing.T) {
		t.Parallel()
		e, rec := newE2BRecorder(t)
		rec.openExit, rec.openStderr = 9, "node: bad option: "+sessionkit.NodeSignalFlag+" (template stderr)\n"
		_, err := e.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute})
		check(t, err, "exited 9")
		if err != nil && strings.Contains(err.Error(), "template stderr") {
			t.Errorf("the refusal %q repeats the template's own stderr", err)
		}
	})
	t.Run("the startup check read a node too old", func(t *testing.T) {
		t.Parallel()
		e, rec := newE2BRecorder(t)
		e.sessionNode = e2bSessionNode{read: true, version: "v20.9.0"}
		_, err := e.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute})
		check(t, err, "node's version v20.9.0")
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if rec.creates != 0 {
			t.Errorf("the refused open made %d sandboxes; want none", rec.creates)
		}
	})
	// E2B's template build leaves /usr/local writable by every user in the machine, so
	// plimsoll's own programs never look there (sessionkit.ControlPathClosed). On a
	// template whose only node is there, env finds none and exits 127: refused in
	// plimsoll's words, not dispatched, never the general failure (finding
	// rust-native-helper-40).
	t.Run("the open finds no node outside /usr/local", func(t *testing.T) {
		t.Parallel()
		e, rec := newE2BRecorder(t)
		rec.openExit, rec.openStderr = 127, "/usr/bin/env: 'node': No such file or directory (template stderr)\n"
		_, err := e.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute})
		if err == nil {
			t.Fatal("the session opened with no node on the control PATH")
		}
		if !errors.Is(err, ErrE2BNoControlNode) || !errors.Is(err, ErrUnsupported) {
			t.Errorf("the refusal %q does not wrap both ErrE2BNoControlNode and ErrUnsupported", err)
		}
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalUnsupported {
			t.Errorf("the refusal is marked %v, %v; want not dispatched, unsupported", reason, ok)
		}
		for _, want := range []string{"/usr/sbin, /usr/bin, /sbin, /bin", "/usr/local", "writable by every user", "e2b/README.md", "E2B_TEMPLATE", "Single runs work"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal %q does not say %q", err, want)
			}
		}
		for _, not := range []string{"cannot hold a session", "template stderr"} {
			if strings.Contains(err.Error(), not) {
				t.Errorf("the refusal %q says %q", err, not)
			}
		}
	})
	// A shell that cannot find env itself also exits 127; that is the machine's fault in
	// another way and stays the general failure.
	t.Run("an exit 127 that does not name node is the general failure", func(t *testing.T) {
		t.Parallel()
		e, rec := newE2BRecorder(t)
		rec.openExit, rec.openStderr = 127, "/bin/sh: 1: /usr/bin/env: not found\n"
		_, err := e.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute})
		if err == nil || errors.Is(err, ErrE2BNoControlNode) || !strings.Contains(err.Error(), "cannot hold a session") {
			t.Errorf("the open's exit 127 without node in its words gave %v; want the general failure", err)
		}
	})
	t.Run("a node new enough opens", func(t *testing.T) {
		t.Parallel()
		e, _ := newE2BRecorder(t)
		e.sessionNode = e2bSessionNode{read: true, version: "v24.11.1"}
		s, err := e.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute})
		if err != nil {
			t.Fatalf("a session on node v24.11.1: %v", err)
		}
		_ = s.Close(context.Background())
	})
}

// The open's exit when it could not close /usr/local to the session's user
// (e2b_session.js, usrLocalExit) refuses the session as unsupported and not dispatched,
// in words that say why and how the operator gets a template that serves sessions,
// with the open's own account of the path; no later program is started (finding
// hunt-quality-55). The docker-backed stand-in runs the real open to this exit.
func TestE2BSessionRefusesAUsrLocalTheOpenCouldNotClose(t *testing.T) {
	t.Parallel()
	e, rec := newE2BRecorder(t)
	rec.openExit = e2bOpenUsrLocalExit
	rec.openStderr = `the session's user can still write 1 file(s) or folder(s) under /usr/local after the open closed it, "/usr/local/bin/x" first` + "\n"
	_, err := e.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute})
	if err == nil {
		t.Fatal("the session opened after the open's /usr/local refusal")
	}
	if !errors.Is(err, ErrE2BUsrLocalOpen) || !errors.Is(err, ErrUnsupported) {
		t.Errorf("the refusal %q does not wrap both ErrE2BUsrLocalOpen and ErrUnsupported", err)
	}
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalUnsupported {
		t.Errorf("the refusal is marked %v, %v; want not dispatched, unsupported", reason, ok)
	}
	for _, want := range []string{`"/usr/local/bin/x"`, "writable by every user", "before any of the session's code runs", "Single runs work", "e2b/README.md", "E2B_TEMPLATE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "cannot hold a session") {
		t.Errorf("the refusal %q is the open's general failure", err)
	}
	for _, st := range rec.recorded() {
		if p := e2bProgram(st); p != "open" {
			t.Errorf("after the refused open, a %s was started: %q", p, st.argv())
		}
	}
}

// The open's own refusal of its machine (e2b_session.js, refuse, exit 2) refuses the
// session as not dispatched, reason environment, wrapping ErrUnsupported so that over
// RPC it is never an internal error: none of the caller's code has run. Its words are
// the open's refusal line alone, the last line of its standard error, and the sandbox
// is deleted; no later program is started. Each case is a refusal the real open makes.
func TestE2BSessionMarksTheOpensRefusalNotDispatched(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, stderr, want string }{
		{"a guest uid that is an account", "uid/gid 61000 is already an account here: taken\n", "uid/gid 61000 is already an account here: taken"},
		{"no setpriv", "the machine has no setpriv in its system folders (/usr/sbin:/usr/bin:/sbin:/bin)\n", "the machine has no setpriv in its system folders"},
		{"a pinned program the guest could change", "the machine's sh at /bin/sh is not the root's own: writable by others\n", "is not the root's own: writable by others"},
		// Anything before the refusal line (a warning node printed) stays out.
		{"words before the refusal line", "template-own-warning: x\nsetpriv could not start a process as the guest: denied\n", "setpriv could not start a process as the guest: denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, rec := newE2BRecorder(t)
			rec.openExit, rec.openStderr = e2bOpenRefusedExit, tc.stderr
			_, err := e.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute})
			if err == nil {
				t.Fatal("the session opened after the open refused its machine")
			}
			if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment {
				t.Errorf("the refusal %q is marked %v, %v; want not dispatched, environment", err, reason, ok)
			}
			if !errors.Is(err, ErrE2BOpenRefused) || !errors.Is(err, ErrUnsupported) {
				t.Errorf("the refusal %q does not wrap both ErrE2BOpenRefused and ErrUnsupported", err)
			}
			for _, want := range []string{tc.want, "e2b/README.md", "E2B_TEMPLATE"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal %q does not say %q", err, want)
				}
			}
			for _, unwanted := range []string{"template-own-warning", "cannot hold a session"} {
				if strings.Contains(err.Error(), unwanted) {
					t.Errorf("the refusal %q says %q", err, unwanted)
				}
			}
			for _, st := range rec.recorded() {
				if p := e2bProgram(st); p != "open" {
					t.Errorf("after the refused open, a %s was started: %q", p, st.argv())
				}
			}
			rec.mu.Lock()
			deletes := rec.deletes
			rec.mu.Unlock()
			if deletes == 0 {
				t.Error("the refused open did not delete its sandbox")
			}
		})
	}
}

// A session call is marked not dispatched for a failed staging only before the stager
// starts: a file write envd refused leaves the call's bytes in the root-only staging
// directory, so it is marked (reason environment) and the session goes on; a stager that
// started and then ended by a signal or an unknown code is not marked, for a snippet or a
// project alike, since code of the session can read the call's files as the stager writes
// them, kill it and run them (TestE2BSessionDockerCallWhoseStagerWasKilledIsNotMarked does
// it on the docker-backed stand-in).
func TestE2BSessionStagingIsMarkedOnlyBeforeTheStager(t *testing.T) {
	t.Parallel()
	e, rec := newE2BRecorder(t)
	s, err := e.OpenSession(context.Background(), SessionOptions{Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	set := func(files bool, end string) {
		rec.mu.Lock()
		rec.filesFail, rec.stagerEnd = files, end
		rec.mu.Unlock()
	}
	calls := map[string]func() error{
		"snippet": func() error {
			_, err := s.RunJavaScript(context.Background(), Request{Code: "1"})
			return err
		},
		"project": func() error {
			_, err := s.RunProject(context.Background(), ProjectRequest{Files: []File{{Path: "a.txt", Content: "a"}}, Steps: []string{"true"}})
			return err
		},
	}
	for name, call := range calls {
		set(true, "")
		err := call()
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment {
			t.Errorf("%s whose files envd would not write: %v (reason %q, marked %v); want not dispatched, environment", name, err, reason, ok)
		}
		for _, end := range []string{`{"exitCode":-1,"exited":false,"status":"signal: killed"}`, `{"exitCode":1,"exited":true}`} {
			set(false, end)
			err := call()
			if err == nil {
				t.Errorf("%s whose stager ended %s answered as a result", name, end)
			} else if reason, ok := NotDispatchedReason(err); ok {
				t.Errorf("%s whose stager ended %s is marked not dispatched (%s): %v", name, end, reason, err)
			}
		}
	}
	// A stager that reports a work file it could not write (exit 3) has written the call's
	// own files first. A project's answer is its result (setup_failed), as before; a
	// snippet has no work files, so for it the answer means the work directory is gone,
	// and it is an unmarked error, never a run of a snippet at another path.
	set(false, `{"exitCode":3,"exited":true}`)
	rec.mu.Lock()
	rec.stagerOut = `{"file":0,"errno":"EIO"}`
	rec.mu.Unlock()
	if err := calls["snippet"](); err == nil {
		t.Error("a snippet whose stager could not reach the work directory answered as a result")
	} else if reason, ok := NotDispatchedReason(err); ok {
		t.Errorf("a snippet whose stager could not reach the work directory is marked not dispatched (%s): %v", reason, err)
	}
	if res, err := s.RunProject(context.Background(), ProjectRequest{Files: []File{{Path: "a.txt", Content: "a"}}, Steps: []string{"true"}}); err != nil || res.Outcome != ProjectOutcomeSetupFailed {
		t.Errorf("a project whose work file could not be written: %+v, %v; want setup_failed", res, err)
	}
	rec.mu.Lock()
	rec.stagerOut = ""
	rec.mu.Unlock()
	set(false, "")
	if s.Err() != nil {
		t.Fatalf("a failed staging ended the session: %v", s.Err())
	}
	// Nothing of the snippet ran at a path the stager never wrote.
	for _, st := range rec.recorded() {
		if slices.Contains(st.argv(), "/snippet.cjs") {
			t.Fatalf("a snippet ran from /snippet.cjs: %q", st.argv())
		}
	}
}
