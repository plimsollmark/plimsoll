package sandbox_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/sessiontest"
)

// The e2b provider's sessions are tested against a stand-in for E2B: a fake control
// plane in this process whose sandboxes are local containers, each running the envd
// stand-in (sandbox/internal/e2bfake/envd) as root, so every process a session starts
// really runs. A pause is `docker pause` plus cutting every connection into the
// container, as a microVM snapshot cuts them. It proves plimsoll's session logic, not
// E2B's behavior: the live suite does that.

const e2bFakeImage = "plimsoll/sandbox-python:latest"

type e2bFake struct {
	t     *testing.T
	run   string // the label value of this test's containers
	bin   string // the envd stand-in
	dir   string // one socket directory per sandbox
	srv   *httptest.Server
	mu    sync.Mutex
	boxes map[string]*e2bFakeBox
}

type e2bFakeBox struct {
	id, token, traffic string
	sock               string
	state              string // running, paused, or "" once deleted
	template           string
	metadata           map[string]string
	network            map[string]any
	conns              map[net.Conn]struct{}
}

func newE2BFake(t *testing.T) *e2bFake {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping the e2b session docker test in -short mode")
	}
	required := os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1"
	skip := func(why string) {
		t.Helper()
		if required {
			t.Fatalf("docker coverage was required but %s", why)
		}
		t.Skip(why)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("docker is not available")
	}
	if err := exec.Command("docker", "image", "inspect", e2bFakeImage).Run(); err != nil {
		skip(e2bFakeImage + " is not present (run `make docker-images`)")
	}
	f := &e2bFake{t: t, run: hexID(), dir: t.TempDir(), boxes: map[string]*e2bFakeBox{}}
	f.bin = filepath.Join(t.TempDir(), "envd")
	build := exec.Command("go", "build", "-o", f.bin, "./internal/e2bfake/envd")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the envd stand-in: %v\n%s", err, out)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(func() {
		f.srv.Close()
		out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=io.plimsoll.e2bfake="+f.run).Output()
		if ids := strings.Fields(string(out)); len(ids) > 0 {
			_ = exec.Command("docker", append([]string{"rm", "-f"}, ids...)...).Run()
		}
	})
	return f
}

func hexID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// provider is an e2b provider pointed at the fake, sessions on.
func (f *e2bFake) provider() *sandbox.E2B {
	return &sandbox.E2B{
		APIKey:   "fake-key",
		APIBase:  f.srv.URL,
		EnvdHost: func(id string) string { return "http://e2bfake-" + id },
		HTTP:     &http.Client{Transport: &http.Transport{DialContext: f.dial}},
	}
}

// dial reaches a sandbox's envd through its socket, refused while it is paused or
// gone, and tracks the connection so a pause can cut it.
func (f *e2bFake) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	id, ok := strings.CutPrefix(host, "e2bfake-")
	if !ok {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	f.mu.Lock()
	b := f.boxes[id]
	f.mu.Unlock()
	if b == nil || b.state != "running" {
		return nil, &net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", b.sock)
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, f: f, b: b}
	f.mu.Lock()
	b.conns[tc] = struct{}{}
	f.mu.Unlock()
	return tc, nil
}

type trackedConn struct {
	net.Conn
	f    *e2bFake
	b    *e2bFakeBox
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.f.mu.Lock()
		delete(c.b.conns, c)
		c.f.mu.Unlock()
	})
	return c.Conn.Close()
}

func (f *e2bFake) box(id string) *e2bFakeBox {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b := f.boxes[id]; b != nil && b.state != "" {
		return b
	}
	return nil
}

// mutate changes a sandbox's record as someone holding the API key could.
func (f *e2bFake) mutate(id string, fn func(*e2bFakeBox)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.boxes[id])
}

// setNetwork is E2B's network update: the body replaces the egress configuration, and
// public traffic, which is create-only, is kept.
func (f *e2bFake) setNetwork(w http.ResponseWriter, r *http.Request, id string) {
	var network map[string]any
	if err := json.NewDecoder(r.Body).Decode(&network); err != nil {
		http.Error(w, "bad network", http.StatusBadRequest)
		return
	}
	if f.box(id) == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f.mutate(id, func(b *e2bFakeBox) {
		network["allowPublicTraffic"] = b.network["allowPublicTraffic"]
		b.network = network
	})
	w.WriteHeader(http.StatusNoContent)
}

func (f *e2bFake) container(id string) string { return "plimsoll-e2bfake-" + id }

func (f *e2bFake) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != "fake-key" {
		http.Error(w, "no key", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/sandboxes":
		f.create(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v2/sandboxes":
		f.list(w, r)
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "sandboxes":
		b := f.box(parts[1])
		if b == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		f.mu.Lock()
		rec := map[string]any{
			"templateID": b.template, "sandboxID": b.id, "state": b.state, "cpuCount": 2, "memoryMB": 1024,
			"diskSizeMB": 2048, "metadata": b.metadata, "network": b.network, "envdVersion": "fake",
			"lifecycle": map[string]any{"autoResume": false, "onTimeout": "kill"},
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(rec)
	case r.Method == http.MethodPut && len(parts) == 3 && parts[0] == "sandboxes" && parts[2] == "network":
		f.setNetwork(w, r, parts[1])
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "sandboxes" && parts[2] == "pause":
		f.pause(w, parts[1])
	case r.Method == http.MethodPost && len(parts) == 4 && parts[0] == "v2" && parts[3] == "connect":
		f.resume(w, parts[2])
	case r.Method == http.MethodDelete && len(parts) == 2 && parts[0] == "sandboxes":
		b := f.box(parts[1])
		if b == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// Gone from the record first: E2B answers 404 once a kill has begun.
		f.cut(b, "")
		_ = exec.Command("docker", "rm", "-f", f.container(b.id)).Run()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
	}
}

func (f *e2bFake) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TemplateID string            `json:"templateID"`
		Metadata   map[string]string `json:"metadata"`
		Network    map[string]any    `json:"network"`
		Secure     bool              `json:"secure"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Secure {
		http.Error(w, "bad create", http.StatusBadRequest)
		return
	}
	b := &e2bFakeBox{id: "fake" + hexID(), token: hexID(), traffic: hexID(), state: "running", template: req.TemplateID,
		metadata: req.Metadata, network: req.Network, conns: map[net.Conn]struct{}{}}
	sockDir := filepath.Join(f.dir, b.id)
	if err := os.MkdirAll(sockDir, 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b.sock = filepath.Join(sockDir, "envd.sock")
	out, err := exec.Command("docker", "run", "-d", "--init", "--name", f.container(b.id),
		"--label", "io.plimsoll.e2bfake="+f.run, "--network", "none", "--user", "0",
		"-v", f.bin+":/opt/envd/envd:ro", "-v", f.bin+":/usr/local/bin/setpriv:ro", "-v", sockDir+":/run/envd",
		"--entrypoint", "/opt/envd/envd", e2bFakeImage,
		"-socket", "/run/envd/envd.sock", "-token", b.token).CombinedOutput()
	if err != nil {
		http.Error(w, "docker run: "+string(out), http.StatusInternalServerError)
		return
	}
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(b.sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			http.Error(w, "envd did not start", http.StatusInternalServerError)
			return
		}
	}
	f.mu.Lock()
	f.boxes[b.id] = b
	f.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"sandboxID": b.id, "envdAccessToken": b.token, "trafficAccessToken": b.traffic})
}

// cut closes every connection into a sandbox, as a snapshot does, and sets its state.
func (f *e2bFake) cut(b *e2bFakeBox, state string) {
	f.mu.Lock()
	b.state = state
	conns := make([]net.Conn, 0, len(b.conns))
	for c := range b.conns {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (f *e2bFake) pause(w http.ResponseWriter, id string) {
	b := f.box(id)
	if b == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f.mu.Lock()
	paused := b.state == "paused"
	f.mu.Unlock()
	if paused {
		http.Error(w, "already paused", http.StatusConflict)
		return
	}
	f.cut(b, "paused")
	if out, err := exec.Command("docker", "pause", f.container(id)).CombinedOutput(); err != nil {
		http.Error(w, string(out), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *e2bFake) resume(w http.ResponseWriter, id string) {
	b := f.box(id)
	if b == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f.mu.Lock()
	paused := b.state == "paused"
	f.mu.Unlock()
	status := http.StatusOK
	if paused {
		if out, err := exec.Command("docker", "unpause", f.container(id)).CombinedOutput(); err != nil {
			http.Error(w, string(out), http.StatusInternalServerError)
			return
		}
		f.mu.Lock()
		b.state = "running"
		f.mu.Unlock()
		status = http.StatusCreated
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"sandboxID": b.id, "envdAccessToken": b.token, "trafficAccessToken": b.traffic})
}

func (f *e2bFake) list(w http.ResponseWriter, r *http.Request) {
	filter, _ := url.ParseQuery(r.URL.Query().Get("metadata"))
	var out []map[string]any
	f.mu.Lock()
	for _, b := range f.boxes {
		if b.state == "" {
			continue
		}
		match := true
		for k := range filter {
			match = match && b.metadata[k] == filter.Get(k)
		}
		if match {
			out = append(out, map[string]any{"sandboxID": b.id, "state": b.state, "metadata": b.metadata})
		}
	}
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(out)
}

func openE2B(t *testing.T, e *sandbox.E2B) sandbox.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := e.OpenSession(ctx, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	// Close only starts the delete; waiting for Done keeps a test from ending, and its
	// binary from exiting, with the sandbox still alive (a live run once left one
	// billing until its own timeout).
	t.Cleanup(func() {
		_ = s.Close(context.Background())
		select {
		case <-s.Done():
		case <-time.After(2 * time.Minute):
			t.Errorf("the session's sandbox %s was not deleted within 2 minutes of its close", sandbox.E2BSessionSandbox(s))
		}
	})
	return s
}

func e2bSnippet(t *testing.T, s sandbox.Session, code string) sandbox.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := s.RunJavaScript(ctx, sandbox.Request{Code: code, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("snippet: %v", err)
	}
	return res
}

// The shared conformance suite, both languages, against the provider over the fake.
// ExecsWalledOff: a relay is root's from its first instruction and drops to the guest
// non-dumpable, so no cell can open its pipes even as it starts.
func TestE2BSessionDockerConformance(t *testing.T) {
	f := newE2BFake(t)
	sessiontest.Run(t, f.provider(), sessiontest.Config{
		Lifetime: 5 * time.Minute, ShortLifetime: 20 * time.Second,
		Languages:      []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython},
		ExecsWalledOff: true, Teardown: sandbox.E2BTeardown,
	})
}

// The provider's startup smoke test (a run, its egress probe, the languages) and then
// the session smoke test, as plimsolld runs them, over the fake.
func TestE2BSessionDockerSmokeTest(t *testing.T) {
	f := newE2BFake(t)
	e := f.provider()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := e.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	if got := e.SessionEnvironments().Project.Languages; len(got) != 2 {
		t.Fatalf("the smoke test proved languages %v, want javascript and python", got)
	}
	if err := sandbox.SessionSmokeTest(ctx, e, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20}); err != nil {
		t.Fatal(err)
	}
}

// A session's code runs as the guest uid, with no-new-privs and no group, never as
// root or the template's user; plimsoll's programs run as root.
func TestE2BSessionDockerGuestIsUnprivileged(t *testing.T) {
	f := newE2BFake(t)
	s := openE2B(t, f.provider())
	res := e2bSnippet(t, s, `const st = require("fs").readFileSync("/proc/self/status", "latin1");
const f = (n) => (new RegExp("^" + n + ":[ \\t]*(.*)$", "m").exec(st) || [])[1];
console.log(JSON.stringify({uid: f("Uid"), gid: f("Gid"), groups: f("Groups").trim(), nnp: f("NoNewPrivs"), cwd: process.cwd(), home: process.env.HOME}))`)
	var got struct{ UID, GID, Groups, NNP, Cwd, Home string }
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
		t.Fatalf("snippet output %q: %v (stderr %q)", res.Stdout, err, res.Stderr)
	}
	want := "61000\t61000\t61000\t61000"
	if got.UID != want || got.GID != want || got.Groups != "" || got.NNP != "1" {
		t.Fatalf("the guest runs as %+v; want uid and gid 61000, no groups, no-new-privs", got)
	}
	if got.Cwd != "/work" || got.Home != "/work" {
		t.Fatalf("the guest's directory and HOME: %+v, want /work", got)
	}
	// The staging directory is root's: the guest cannot read a call's files there.
	res = e2bSnippet(t, s, `try { require("fs").readdirSync("/var/lib/plimsoll-stage"); console.log("read") } catch (e) { console.log(e.code) }`)
	if strings.TrimSpace(res.Stdout) != "EACCES" {
		t.Fatalf("the guest listing the staging directory: %q, want EACCES", res.Stdout)
	}
}

// A pause cuts the relays' streams and the interpreters are forgotten; the next call
// resumes the sandbox and sweeps them away, and the next cell says its interpreter is
// new. The files stay.
func TestE2BSessionDockerPauseAndResume(t *testing.T) {
	f := newE2BFake(t)
	s := openE2B(t, f.provider())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cell := func(code string) sandbox.CellResult {
		t.Helper()
		res, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguagePython, Code: code, Timeout: 30 * time.Second})
		if err != nil {
			t.Fatalf("cell %q: %v", code, err)
		}
		return res
	}
	if first := cell("x = 41"); !first.InterpreterStarted {
		t.Fatalf("the first cell did not start an interpreter: %+v", first)
	}
	_ = e2bSnippet(t, s, `require("fs").writeFileSync("kept.txt", "yes")`)
	holds, err := s.Suspend(ctx)
	if err != nil || holds {
		t.Fatalf("Suspend: holds memory %v, err %v; want false, nil", holds, err)
	}
	id := e2bSandboxOf(t, f)
	if st := f.boxState(id); st != "paused" {
		t.Fatalf("after Suspend the sandbox is %q, want paused", st)
	}
	after := cell("print(open('kept.txt').read())")
	if !after.InterpreterStarted || strings.TrimSpace(after.Stdout) != "yes" {
		t.Fatalf("the cell after a resume: %+v; want a new interpreter and the file kept", after)
	}
	if st := f.boxState(id); st != "running" {
		t.Fatalf("after the call the sandbox is %q, want running", st)
	}
	procs := e2bSnippet(t, s, `const fs = require("fs"); let n = 0;
for (const d of fs.readdirSync("/proc")) { try { if (fs.readFileSync("/proc/" + d + "/cmdline", "latin1").includes("kernel")) n++ } catch {} }
console.log(n)`)
	// One Python interpreter (the new one) carries its kernel's text; the old one is gone.
	if strings.TrimSpace(procs.Stdout) != "1" {
		t.Fatalf("interpreters alive after the resume and a new cell: %s", procs.Stdout)
	}
}

func (f *e2bFake) boxState(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b := f.boxes[id]; b != nil {
		return b.state
	}
	return ""
}

// e2bSandboxOf is the ID of the fake's one live sandbox.
func e2bSandboxOf(t *testing.T, f *e2bFake) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for id, b := range f.boxes {
		if b.state != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) != 1 {
		t.Fatalf("the fake has %d live sandboxes, want 1", len(ids))
	}
	return ids[0]
}

// Someone with the API key opening the sandbox's egress between calls ends the
// session at the next call's read-back, before anything runs; so does a sandbox
// deleted under the session.
func TestE2BSessionDockerReadBackEndsAChangedSession(t *testing.T) {
	f := newE2BFake(t)
	e := f.provider()
	for _, c := range []struct {
		name   string
		change func(id string)
	}{
		{"egress opened", func(id string) {
			f.mutate(id, func(b *e2bFakeBox) {
				b.network = map[string]any{"allowOut": []string{"example.com"}, "denyOut": []string{"0.0.0.0/0"}, "allowPublicTraffic": false}
			})
		}},
		{"deleted", func(id string) {
			f.mutate(id, func(b *e2bFakeBox) { b.state = "" })
			_ = exec.Command("docker", "rm", "-f", f.container(id)).Run()
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := openE2B(t, e)
			_ = e2bSnippet(t, s, `1`)
			c.change(e2bSandboxOf(t, f))
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			_, err := s.RunJavaScript(ctx, sandbox.Request{Code: `require("fs").writeFileSync("ran", "1")`, Timeout: 10 * time.Second})
			if reason, ok := sandbox.NotDispatchedReason(err); !ok || sandbox.SessionEndReason(err) != sandbox.SessionSandboxChanged {
				t.Fatalf("a call after the change: %v (marked %v, reason %v); want refused, the session ended sandbox_changed", err, ok, reason)
			}
			_ = s.Close(context.Background())
			<-s.Done()
		})
	}
}

// Every session sandbox declares its expiry and is stamped as a session, so any
// instance's reconciliation can delete a paused one a crashed daemon left; while the
// session lives, its own instance never does.
func TestE2BSessionDockerDeclaresItsExpiry(t *testing.T) {
	f := newE2BFake(t)
	e := f.provider()
	s := openE2B(t, e)
	id := e2bSandboxOf(t, f)
	f.mu.Lock()
	md := f.boxes[id].metadata
	f.mu.Unlock()
	if md["session"] != "1" || md["expires"] == "" {
		t.Fatalf("the session sandbox's metadata %v lacks session=1 or expires", md)
	}
	if n, err := e.ReconcileOrphans(context.Background()); err != nil || n != 0 {
		t.Fatalf("reconcile with the session open: killed %d, err %v; want none", n, err)
	}
	if _, err := s.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A crashed daemon's paused session, its expiry long past: another instance reaps it.
	f.mutate(id, func(b *e2bFakeBox) {
		b.metadata = map[string]string{"sdk": "plimsoll", "instance": "crashed", "lease": "gone", "session": "1", "expires": "1000"}
	})
	other := f.provider()
	if n, err := other.ReconcileOrphans(context.Background()); err != nil || n != 1 {
		t.Fatalf("another instance reconciling a paused session past its expiry: killed %d, err %v; want 1", n, err)
	}
	if st := f.boxState(id); st != "" {
		t.Fatalf("the reaped sandbox is %q, want deleted", st)
	}
}

// A granted call is refused before dispatch, unsupported, on a provider with no way to
// reach the guard (no E2B_GUARD_URL or no E2B_SESSION_GRANTS).
func TestE2BSessionDockerRefusesGrants(t *testing.T) {
	f := newE2BFake(t)
	s := openE2B(t, f.provider())
	grant := &sandbox.HostAPIGrant{BaseURL: "https://api.example.com", Allow: []sandbox.HostRoute{{Method: "GET", Path: "/v1/items"}},
		Minter: sandbox.StaticToken("t"), AllowInSessions: true}
	_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `1`, Timeout: 5 * time.Second, Grant: grant})
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalUnsupported || !errors.Is(err, sandbox.ErrUnsupported) {
		t.Fatalf("a granted call that allows sessions: %v (marked %v, reason %v); want refused, unsupported", err, ok, reason)
	}
}

// The stager clears the last call's directory under /tmp/.plimsoll-call; a link the
// session's code put at that path is replaced, never followed into the work directory.
func TestE2BSessionDockerStagerFollowsNoLinkAtItsDirectory(t *testing.T) {
	f := newE2BFake(t)
	s := openE2B(t, f.provider())
	_ = e2bSnippet(t, s, `const fs = require("fs"); fs.writeFileSync("precious.txt", "keep");
fs.rmSync("/tmp/.plimsoll-call", { recursive: true, force: true }); fs.symlinkSync("/work", "/tmp/.plimsoll-call")`)
	res := e2bSnippet(t, s, `console.log(require("fs").readFileSync("precious.txt", "utf8"))`)
	if strings.TrimSpace(res.Stdout) != "keep" {
		t.Fatalf("after a link at the stager's directory, the work file reads %q (stderr %q)", res.Stdout, res.Stderr)
	}
}
