package sandbox_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/plimsollmark/plimsoll/sandbox/projecttest"
	"github.com/plimsollmark/plimsoll/sandbox/sessiontest"
)

// The e2b provider's sessions are tested against a stand-in for E2B: a fake control
// plane in this process whose sandboxes are local containers, each running the envd
// stand-in (sandbox/internal/e2bfake/envd) as root, so every process a session starts
// really runs. A pause is `docker pause` plus cutting every connection into the
// container, as a microVM snapshot cuts them. It proves plimsoll's session logic, not
// E2B's behavior: the live suite does that.

const e2bFakeImage = "plimsoll/sandbox-python:latest"

// e2bNode20Image stands for E2B's base template's node: v20.9.0, which a paid check read
// in base on 2026-11-20, from nodejs.org's own build, pinned by digest. It is the one image
// these tests pull when it is missing (a public image, free to pull).
const e2bNode20Image = "node:20.9.0-bookworm-slim@sha256:d272d96f3ad3a4e5bb2b6c36ea7427b4e83d1b23fb24b9df8b71d01aa59951b1"

type e2bFake struct {
	t     *testing.T
	image string // every sandbox's image, as E2B's template build leaves it (e2bBuilt)
	// fakeSetpriv mounts the envd stand-in as /usr/sbin/setpriv, the first folder of the
	// control PATH, for an image with none of util-linux's; an image built from
	// e2b/e2b.Dockerfile has its own.
	fakeSetpriv bool
	// runArgs are more `docker run` arguments for every sandbox, as a template's own mounts
	// (a test's: none by default).
	runArgs []string
	run     string // the label value of this test's containers
	bin     string // the envd stand-in
	dir     string // one socket directory per sandbox
	srv     *httptest.Server
	mu      sync.Mutex
	boxes   map[string]*e2bFakeBox
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
	return newE2BFakeOn(t, e2bFakeImage, true, true)
}

// e2bOldNodeAlpine is node v20 built for Alpine, as the stand-in's own image is: its
// node, put in /usr/local/bin of the stand-in's image, is a steps' node too old for
// --disable-sigusr1 beside a session's node that has it (the image's own, in /usr/bin).
// Pinned by digest; the test pulls it when it is missing (a public image, free to pull).
const e2bOldNodeAlpine = "node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293"

var e2bBuiltMu sync.Mutex

// e2bBuilt returns the name of image as E2B's template build leaves it: /usr/local and
// everything in it writable by every user in the machine (mode 777, set after the
// recipe's own steps; measured 2026-11-20 on E2B's base template and on a template
// built from e2b/e2b.Dockerfile, private finding rust-native-helper-40). A stand-in
// without this step passed a recipe that E2B then built into a template no session
// could open on. With copyNode it first copies node from /usr/local/bin to /usr/bin,
// as plimsoll's recipe does, for a stand-in image that is not built from the recipe.
// With stepNodeFrom, an image, that image's /usr/local/bin/node then replaces this one's
// there: the node a run's steps find is that one, while a session's own programs keep
// the copy in /usr/bin (two nodes of two versions, hunt-quality-53).
// The result is built once per image and kept under a name of its own.
//
// With copyNode it also moves node's module and header trees out of /usr/local and links
// them back, and makes /usr/local/bin/node a link to the copy: a session's open takes the
// write permission on every file under /usr/local back (e2b_session.js, closeUsrLocal),
// and overlayfs, the storage docker gives each container, copies a file whole into the
// container's own layer, and syncs it to disk, the first time its mode changes, which
// E2B's machine disk does not. On the stand-in's image that is about 4,700 files and
// 200 MB: measured 2026-11-20, 4.5 to 6.2 s per open alone under runc, and over 40 s
// with the suite's sessions opening side by side, which ran the conformance suite's
// sessions out of time. Links are never changed by the open, so what remains under
// /usr/local is a few dozen files. The recipe's test (TestE2BTemplateRecipeOnALocalImage)
// keeps its image's /usr/local whole.
//
// stepNodeFrom, when set, names an image whose node becomes the one a run's steps find
// (/usr/local/bin/node), apart from the session's own node in /usr/bin: the two-node
// shape of hunt-quality-53. The link the copyNode step left there is removed first, so
// the copy cannot write through it onto /usr/bin/node.
func e2bBuilt(image string, copyNode bool, stepNodeFrom string) (string, error) {
	steps := ""
	if copyNode {
		steps += "RUN cp /usr/local/bin/node /usr/bin/node && chmod 755 /usr/bin/node\n" +
			"RUN for d in lib/node_modules include; do if [ -d /usr/local/$d ]; then mv /usr/local/$d /usr/$d-e2bfake && ln -s /usr/$d-e2bfake /usr/local/$d; fi; done && ln -sf /usr/bin/node /usr/local/bin/node\n"
	}
	if stepNodeFrom != "" {
		steps += "RUN rm -f /usr/local/bin/node\n" +
			"COPY --from=" + stepNodeFrom + " /usr/local/bin/node /usr/local/bin/node\n"
	}
	return e2bDerived(image, steps+"RUN chmod -R 777 /usr/local\n")
}

// e2bDerived returns the name of image with steps (Dockerfile lines, run as root) added,
// built once per image and steps and kept under a name of its own.
func e2bDerived(image, steps string) (string, error) {
	e2bBuiltMu.Lock()
	defer e2bBuiltMu.Unlock()
	id, err := exec.Command("docker", "image", "inspect", "-f", "{{.Id}}", image).Output()
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", image, err)
	}
	recipe := "FROM " + image + "\nUSER 0\n" + steps
	sum := sha256.Sum256([]byte(strings.TrimSpace(string(id)) + "\n" + recipe))
	name := "plimsoll-local/e2bfake-built:" + hex.EncodeToString(sum[:8])
	if exec.Command("docker", "image", "inspect", name).Run() == nil {
		return name, nil
	}
	build := exec.Command("docker", "build", "-q", "--label", "io.plimsoll.e2bfake-built=1", "-t", name, "-")
	build.Stdin = strings.NewReader(recipe)
	if out, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build %s as E2B's template build leaves it: %w\n%s", image, err, out)
	}
	return name, nil
}

// newE2BFakeOn is the stand-in with every sandbox a container of image as E2B's
// template build leaves it (e2bBuilt, which says what copyNode is).
func newE2BFakeOn(t *testing.T, image string, fakeSetpriv, copyNode bool) *e2bFake {
	t.Helper()
	return newE2BFakeWithStepNode(t, image, fakeSetpriv, copyNode, "")
}

// newE2BFakeWithStepNode is newE2BFakeOn with the steps' node taken from another image
// (e2bBuilt's stepNodeFrom; "" leaves the image's own).
func newE2BFakeWithStepNode(t *testing.T, image string, fakeSetpriv, copyNode bool, stepNodeFrom string) *e2bFake {
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
	if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil {
		switch image {
		case e2bFakeImage:
			skip(image + " is not present (run `make docker-images`)")
		case e2bNode20Image:
			if out, err := exec.Command("docker", "pull", "--quiet", image).CombinedOutput(); err != nil {
				skip(image + " is not present and could not be pulled: " + strings.TrimSpace(string(out)))
			}
		default:
			skip(image + " is not present")
		}
	}
	if stepNodeFrom != "" && exec.Command("docker", "image", "inspect", stepNodeFrom).Run() != nil {
		if out, err := exec.Command("docker", "pull", "--quiet", stepNodeFrom).CombinedOutput(); err != nil {
			skip(stepNodeFrom + " is not present and could not be pulled: " + strings.TrimSpace(string(out)))
		}
	}
	built, err := e2bBuilt(image, copyNode, stepNodeFrom)
	if err != nil {
		t.Fatal(err)
	}
	f := &e2bFake{t: t, image: built, fakeSetpriv: fakeSetpriv, run: hexID(), dir: t.TempDir(), boxes: map[string]*e2bFakeBox{}}
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
	if b == nil || b.state != "running" {
		f.mu.Unlock()
		return nil, &net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}
	}
	sock := b.sock
	f.mu.Unlock()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, f: f, b: b}
	f.mu.Lock()
	// A pause or deletion may have cut the sandbox while DialContext was in
	// flight. Check and register atomically so cut cannot miss this connection.
	if b.state != "running" {
		f.mu.Unlock()
		_ = c.Close()
		return nil, &net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}
	}
	b.conns[tc] = struct{}{}
	f.mu.Unlock()
	return tc, nil
}

// The fake's HTTP transport may dial while the test changes the sandbox's
// state. Exercise that shared path without Docker so the race pass always covers it.
func TestE2BSessionDockerFakeDialState(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	box := &e2bFakeBox{state: "running", sock: listener.Addr().String(), conns: map[net.Conn]struct{}{}}
	f := &e2bFake{boxes: map[string]*e2bFakeBox{"test": box}}
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for range 4000 {
			f.mutate("test", func(b *e2bFakeBox) { b.state = "running" })
		}
	}()
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 100 {
				c, err := f.dial(context.Background(), "tcp", "e2bfake-test:80")
				if err != nil {
					t.Error(err)
					return
				}
				_ = c.Close()
			}
		}()
	}
	close(start)
	workers.Wait()
	f.mu.Lock()
	remaining := len(box.conns)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d closed connections remain registered", remaining)
	}
	_ = listener.Close()
	<-accepted
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
	// SYS_ADMIN: root in an E2B microVM holds every capability, and a session's open
	// bind-mounts the work folder on itself as root (e2b_session.js, ownMount), which a
	// container's root may do only with it. The guest holds none: setpriv's drop to another
	// uid clears them, and no-new-privs keeps a program from gaining one
	// (TestE2BSessionDockerGuestIsUnprivileged reads CapEff). apparmor=unconfined: on a host
	// that runs AppArmor (GitHub's Ubuntu runners), docker's default profile denies mount
	// whatever the capabilities, so the open's bind mount failed there ("mounting /work on
	// /work failed: Permission denied", the v0.30.0 push's CI) while it passed here, where WSL
	// runs no AppArmor; an E2B microVM's root has no such profile either.
	args := []string{"run", "-d", "--init", "--name", f.container(b.id),
		"--label", "io.plimsoll.e2bfake=" + f.run, "--network", "none", "--user", "0", "--cap-add", "SYS_ADMIN",
		"--security-opt", "apparmor=unconfined",
		"-v", f.bin + ":/opt/envd/envd:ro", "-v", sockDir + ":/run/envd"}
	if f.fakeSetpriv {
		args = append(args, "-v", f.bin+":/usr/sbin/setpriv:ro")
	}
	args = append(args, f.runArgs...)
	// No --runtime: these containers take docker's default runtime (runc on this project's
	// machines) whatever the suite's runtime setting says, so a run of these tests "under
	// gVisor" runs their sandboxes under runc. Tried 2026-11-20 with the variable passed
	// on as --runtime: under gVisor no sandbox starts ("envd did not start", every
	// session test), since the envd stand-in listens on a Unix socket in a folder of the
	// host's, which gVisor run with --host-uds=open may connect to but not create.
	args = append(args, "--entrypoint", "/opt/envd/envd", f.image, "-socket", "/run/envd/envd.sock", "-token", b.token)
	out, err := exec.Command("docker", args...).CombinedOutput()
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
	t.Parallel()
	f := newE2BFake(t)
	// The fake's sessions are local containers that open in under a second, so the
	// lifetime case waits 8 s, not 20, and the cases run side by side.
	sessiontest.Run(t, f.provider(), sessiontest.Config{
		Lifetime: 5 * time.Minute, ShortLifetime: 8 * time.Second,
		Languages:      []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython},
		ExecsWalledOff: true, Teardown: sandbox.E2BTeardown, Parallel: true,
	})
}

// The one-shot project contract (projecttest) over the fake, in a run and in a
// session's calls.
func TestE2BDockerProjectConformance(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	// The two run side by side, each with sandboxes of its own. A hung step's budget is
	// docker's 8 s: the fake's sandbox is a local container, ready in about half a second
	// (at 15 s each hang waited 7 s more for nothing, 2026-10-29).
	t.Run("run", func(t *testing.T) { t.Parallel(); projecttest.Run(t, f.provider(), 8*time.Second) })
	t.Run("session", func(t *testing.T) { t.Parallel(); projecttest.Run(t, openE2B(t, f.provider()), 8*time.Second) })
}

// The provider's startup smoke test (a run, its egress probe, the languages) and then
// the session smoke test, as plimsolld runs them, over the fake.
func TestE2BSessionDockerSmokeTest(t *testing.T) {
	t.Parallel()
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
	// The startup check's read of the session's node (e2bSessionNodeScript) ran in the
	// container and its answer was read: the stand-in's one node, at both places.
	if step, session, read := sandbox.E2BSmokeNodes(e); !read || session == "" || session != step {
		t.Fatalf("the startup check kept the steps' node %q and the session's %q (read %v); want one version, read, for both", step, session, read)
	}
	if err := sandbox.SessionSmokeTest(ctx, e, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20}); err != nil {
		t.Fatal(err)
	}
}

// A session's code runs as the guest uid, with no-new-privs and no group, never as
// root or the template's user; plimsoll's programs run as root.
func TestE2BSessionDockerGuestIsUnprivileged(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	s := openE2B(t, f.provider())
	res := e2bSnippet(t, s, `const st = require("fs").readFileSync("/proc/self/status", "latin1");
const f = (n) => (new RegExp("^" + n + ":[ \\t]*(.*)$", "m").exec(st) || [])[1];
console.log(JSON.stringify({uid: f("Uid"), gid: f("Gid"), groups: f("Groups").trim(), nnp: f("NoNewPrivs"), capEff: f("CapEff"), capPrm: f("CapPrm"), cwd: process.cwd(), home: process.env.HOME}))`)
	var got struct{ UID, GID, Groups, NNP, CapEff, CapPrm, Cwd, Home string }
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
		t.Fatalf("snippet output %q: %v (stderr %q)", res.Stdout, err, res.Stderr)
	}
	want := "61000\t61000\t61000\t61000"
	if got.UID != want || got.GID != want || got.Groups != "" || got.NNP != "1" {
		t.Fatalf("the guest runs as %+v; want uid and gid 61000, no groups, no-new-privs", got)
	}
	if got.CapEff != "0000000000000000" || got.CapPrm != "0000000000000000" {
		t.Fatalf("the guest holds capabilities %+v; want none (the stand-in's root holds SYS_ADMIN)", got)
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	f := newE2BFake(t)
	s := openE2B(t, f.provider())
	_ = e2bSnippet(t, s, `const fs = require("fs"); fs.writeFileSync("precious.txt", "keep");
fs.rmSync("/tmp/.plimsoll-call", { recursive: true, force: true }); fs.symlinkSync("/work", "/tmp/.plimsoll-call")`)
	res := e2bSnippet(t, s, `console.log(require("fs").readFileSync("precious.txt", "utf8"))`)
	if strings.TrimSpace(res.Stdout) != "keep" {
		t.Fatalf("after a link at the stager's directory, the work file reads %q (stderr %q)", res.Stdout, res.Stderr)
	}
}

// The two roads, planted in the stand-in's container (an Alpine image, so musl's search
// file), are taken by the guest's own node and by no control program of plimsoll's
// (e2b_session_roads_test.go).
func TestE2BSessionDockerControlProgramsTakeNoRoad(t *testing.T) {
	f := newE2BFake(t)
	checkE2BRoads(t, openE2B(t, f.provider()))
}

// containers is how many of this stand-in's sandboxes docker still has.
func (f *e2bFake) containers(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("docker", "ps", "-aq", "--filter", "label=io.plimsoll.e2bfake="+f.run).Output()
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	return len(strings.Fields(string(out)))
}

// On a stand-in whose node is E2B's base template's (v20.9.0, which refuses
// --disable-sigusr1, and only under /usr/local, which E2B's build leaves writable by
// every user), the startup check, a snippet and a project are served, since a single
// run starts no node program of plimsoll's, and a session is refused as unsupported,
// not dispatched, in plimsoll's words: by the open itself (a provider whose startup
// check has not run), which finds no node outside /usr/local (finding
// rust-native-helper-40), or, where a template has that old node in /usr/bin, exits 9
// on the option; and, once the startup check has read the version, before any sandbox
// is made (finding rust-native-helper-35).
func TestE2BDockerNode20ServesSingleRunsAndRefusesSessions(t *testing.T) {
	t.Parallel()
	f := newE2BFakeOn(t, e2bNode20Image, true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	unsupported := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("a session opened on node v20.9.0")
		}
		if !errors.Is(err, sandbox.ErrUnsupported) {
			t.Errorf("the refusal %q is not unsupported", err)
		}
		if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalUnsupported {
			t.Errorf("the refusal %q is marked %v, %v; want not dispatched, unsupported", err, reason, ok)
		}
	}
	refused := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("a session opened on node v20.9.0")
		}
		if !errors.Is(err, sandbox.ErrUnsupported) {
			t.Errorf("the refusal %q is not unsupported", err)
		}
		if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalUnsupported {
			t.Errorf("the refusal %q is marked %v, %v; want not dispatched, unsupported", err, reason, ok)
		}
		for _, want := range []string{"--disable-sigusr1", "node v22.14.0 or later in the 22 line, v23.7.0 or later in the 23 line, or any v24 or later", "e2b/README.md"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal %q does not say %q", err, want)
			}
		}
	}

	// The open itself, on a provider whose startup check has not run, looks for node
	// outside /usr/local and finds none.
	_, err := f.provider().OpenSession(ctx, sandbox.SessionOptions{Lifetime: time.Minute, DiskBytes: 64 << 20})
	unsupported(t, err)
	if !errors.Is(err, sandbox.ErrE2BNoControlNode) {
		t.Errorf("the open's refusal %q is not ErrE2BNoControlNode", err)
	}
	for _, want := range []string{"/usr/sbin, /usr/bin, /sbin, /bin", "writable by every user", "e2b/README.md"} {
		if err != nil && !strings.Contains(err.Error(), want) {
			t.Errorf("the open's refusal %q does not say %q", err, want)
		}
	}
	if n := f.containers(t); n != 0 {
		t.Errorf("the refused open left %d sandboxes", n)
	}
	// The same old node where plimsoll's programs do look: the open exits 9 on the option.
	inBin := newE2BFakeOn(t, e2bNode20Image, true, true)
	_, err = inBin.provider().OpenSession(ctx, sandbox.SessionOptions{Lifetime: time.Minute, DiskBytes: 64 << 20})
	refused(t, err)
	if !strings.Contains(err.Error(), "exited 9") {
		t.Errorf("the open's refusal %q does not say the open exited 9", err)
	}
	if n := inBin.containers(t); n != 0 {
		t.Errorf("the refused open left %d sandboxes", n)
	}

	e := f.provider()
	if err := e.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest on node v20.9.0: %v", err)
	}
	res, err := e.RunJavaScript(ctx, sandbox.Request{Code: `console.log(process.version)`, Timeout: 20 * time.Second})
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "v20.9.0" {
		t.Fatalf("a snippet on the stand-in: %q, exit %d, %v (stderr %q); want v20.9.0", res.Stdout, res.ExitCode, err, res.Stderr)
	}
	pres, err := e.RunProject(ctx, sandbox.ProjectRequest{Files: []sandbox.File{{Path: "main.js", Content: `console.log("project " + process.version)`}},
		Steps: []string{"node main.js"}, Artifacts: []string{"main.js"}, Timeout: 20 * time.Second})
	if err != nil || pres.Outcome != sandbox.ProjectOutcomeCompleted || len(pres.Steps) != 1 || strings.TrimSpace(string(pres.Steps[0].Stdout)) != "project v20.9.0" || len(pres.Artifacts) != 1 {
		t.Fatalf("a project on the stand-in: %+v, %v", pres, err)
	}

	// The startup check looked for the node a session's programs use, where they look,
	// and found none (the steps' v20.9.0 is under /usr/local alone): the next open is
	// refused in the open's own words and makes no sandbox at all (hunt-quality-53).
	if step, session, read := sandbox.E2BSmokeNodes(e); step != "v20.9.0" || session != "" || !read {
		t.Errorf("the startup check kept the steps' node %q and the session's %q (read %v); want v20.9.0 and none, read", step, session, read)
	}
	before := f.containers(t)
	_, err = e.OpenSession(ctx, sandbox.SessionOptions{Lifetime: time.Minute, DiskBytes: 64 << 20})
	unsupported(t, err)
	if !errors.Is(err, sandbox.ErrE2BNoControlNode) {
		t.Errorf("the early refusal %q is not ErrE2BNoControlNode", err)
	}
	if n := f.containers(t); n > before {
		t.Errorf("the refused open made a sandbox (%d before, %d after)", before, n)
	}

	// The same old node where a session's programs do look: the startup check reads its
	// version there, and the next open is refused for it before any sandbox is made.
	eBin := inBin.provider()
	if err := eBin.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest on node v20.9.0 in /usr/bin: %v", err)
	}
	if step, session, read := sandbox.E2BSmokeNodes(eBin); step != "v20.9.0" || session != "v20.9.0" || !read {
		t.Errorf("the startup check kept the steps' node %q and the session's %q (read %v); want v20.9.0 for both", step, session, read)
	}
	before = inBin.containers(t)
	_, err = eBin.OpenSession(ctx, sandbox.SessionOptions{Lifetime: time.Minute, DiskBytes: 64 << 20})
	refused(t, err)
	if !strings.Contains(err.Error(), "the startup check read node's version v20.9.0 from the node a session's programs use") {
		t.Errorf("the refusal %q does not name the version the startup check read", err)
	}
	if n := inBin.containers(t); n > before {
		t.Errorf("the refused open made a sandbox (%d before, %d after)", before, n)
	}
}

// The reverse of the test above: a template whose steps find an old node (v20, in
// /usr/local/bin, which refuses --disable-sigusr1) and whose session programs find a new
// one (in /usr/bin) serves the startup check and opens a session. Until 2026-11-20 the
// early refusal read the steps' node, so every session on such a template was refused for
// a node no session uses (hunt-quality-53). An operator gets this template who adds a new
// node to /usr/bin on E2B's base and leaves base's own where it is.
func TestE2BDockerOldStepNodeAndNewSessionNodeOpensASession(t *testing.T) {
	t.Parallel()
	f := newE2BFakeWithStepNode(t, e2bFakeImage, true, true, e2bOldNodeAlpine)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	e := f.provider()
	if err := e.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	step, session, read := sandbox.E2BSmokeNodes(e)
	if !strings.HasPrefix(step, "v20.") || !read || session == "" || strings.HasPrefix(session, "v20.") {
		t.Fatalf("the startup check kept the steps' node %q and the session's %q (read %v); want a v20 and one new enough for sessions", step, session, read)
	}
	res, err := e.RunJavaScript(ctx, sandbox.Request{Code: `console.log(process.version)`, Timeout: 20 * time.Second})
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != step {
		t.Fatalf("a snippet on the stand-in: %q, exit %d, %v (stderr %q); want the steps' node %s", res.Stdout, res.ExitCode, err, res.Stderr, step)
	}
	s := openE2B(t, e)
	if pinned := sandbox.E2BSessionBins(s)["node"]; pinned != "/usr/bin/node" {
		t.Errorf("the open pinned node at %q, want /usr/bin/node, outside the folder E2B's build opens to every user", pinned)
	}
	if out := e2bSnippet(t, s, `console.log(1 + 1)`); out.ExitCode != 0 || strings.TrimSpace(out.Stdout) != "2" {
		t.Errorf("a snippet in the session: %q, exit %d (stderr %q)", out.Stdout, out.ExitCode, out.Stderr)
	}
}

// A stand-in built from plimsoll's E2B template recipe (e2b/e2b.Dockerfile, built locally
// under a name of the tester's own and named by PLIMSOLL_E2B_TEMPLATE_IMAGE) serves the
// startup check and a session, its own setpriv, node and python3 pinned by the open, as
// plimsolld runs them at startup. Nothing here reaches E2B (e2b/README.md, "Check the
// recipe without E2B"). Its name holds none of the words the docker suite selects tests by
// (DOCKER_TESTS in the Makefile), so that suite, which fails on a skipped test, does not
// run it; `make e2b-template-recipe` builds the image and runs it.
func TestE2BTemplateRecipeOnALocalImage(t *testing.T) {
	image := os.Getenv("PLIMSOLL_E2B_TEMPLATE_IMAGE")
	if image == "" {
		t.Skip("PLIMSOLL_E2B_TEMPLATE_IMAGE names no image built from e2b/e2b.Dockerfile")
	}
	f := newE2BFakeOn(t, image, false, false)
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
	s := openE2B(t, e)
	res := e2bSnippet(t, s, `console.log(process.version)`)
	if !strings.HasPrefix(strings.TrimSpace(res.Stdout), "v24.") {
		t.Errorf("the recipe's node is %q, want v24", res.Stdout)
	}
	pinned := sandbox.E2BSessionBins(s)
	for _, name := range []string{"node", "sh", "setpriv", "python3"} {
		if pinned[name] == "" {
			t.Errorf("the open pinned no %s (pinned %v)", name, pinned)
		}
	}
	// E2B's build leaves /usr/local writable by every user (e2bBuilt), so nothing the
	// open pins may be there; the recipe puts its node in /usr/bin for that.
	for name, p := range pinned {
		if strings.HasPrefix(p, "/usr/local/") {
			t.Errorf("the open pinned %s at %s, under the folder E2B's build opens to every user", name, p)
		}
	}
	if pinned["node"] != "/usr/bin/node" {
		t.Errorf("the open pinned node at %q, want the recipe's copy at /usr/bin/node", pinned["node"])
	}
	tsc, err := s.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"tsc --version && tsx --version && eslint --version"}, Timeout: 30 * time.Second})
	if err != nil || tsc.Outcome != sandbox.ProjectOutcomeCompleted {
		t.Errorf("the recipe's toolchain in a session: %+v, %v", tsc, err)
	}
	// The open closed /usr/local, where the recipe's image keeps node and the TypeScript
	// tools, to the session's user, and the step above still ran them from there.
	checkE2BUsrLocalClosed(t, s)
	// The roads check on a glibc machine: the stand-in the docker suite uses is musl, so
	// this is the one free run of the check's glibc half (the cache ldconfig builds).
	checkE2BRoads(t, openE2B(t, e))
}

// e2bUsrLocalGuest is what checkE2BUsrLocalClosed runs as the session's user: each way
// to change /usr/local it tries (creating a file, a link and a folder in it, writing,
// deleting, renaming and changing the mode of one of its programs, renaming a folder
// under it and the folder itself), with the error each gave or "done", and every file
// and folder there the kernel says the user may write (access W_OK), with how many it
// looked at.
const e2bUsrLocalGuest = `const fs = require("fs"), path = require("path");
const tryIt = (f) => { try { f(); return "done"; } catch (e) { return e.code || String(e); } };
const bin = "/usr/local/bin";
const prog = fs.readdirSync(bin).sort().map((n) => path.join(bin, n)).find((p) => p !== "/usr/local/bin/node" && fs.lstatSync(p).isFile());
const dir = fs.readdirSync("/usr/local").sort().map((n) => path.join("/usr/local", n)).find((p) => fs.lstatSync(p).isDirectory());
const tries = {
  "create a file in /usr/local/bin": tryIt(() => fs.writeFileSync(path.join(bin, "plimsoll-planted"), "#!/bin/sh\n", { flag: "wx", mode: 0o755 })),
  "create a link in /usr/local/bin": tryIt(() => fs.symlinkSync("/work/planted", path.join(bin, "plimsoll-planted-link"))),
  "create a folder in /usr/local": tryIt(() => fs.mkdirSync("/usr/local/plimsoll-planted")),
  ["write " + prog]: tryIt(() => fs.closeSync(fs.openSync(prog, "r+"))),
  ["delete " + prog]: tryIt(() => fs.unlinkSync(prog)),
  ["rename " + prog]: tryIt(() => fs.renameSync(prog, prog + ".plimsoll")),
  ["change the mode of " + prog]: tryIt(() => fs.chmodSync(prog, 0o777)),
  "write /usr/local/bin/node": tryIt(() => fs.closeSync(fs.openSync("/usr/local/bin/node", "r+"))),
  "replace /usr/local/bin/node": tryIt(() => { fs.writeFileSync("/work/node-planted", "#!/bin/sh\n"); fs.copyFileSync("/work/node-planted", "/usr/local/bin/node"); }),
  "delete /usr/local/bin/node": tryIt(() => fs.unlinkSync("/usr/local/bin/node")),
  ["rename the folder " + dir]: tryIt(() => fs.renameSync(dir, dir + ".plimsoll")),
  "rename /usr/local": tryIt(() => fs.renameSync("/usr/local", "/usr/local.plimsoll")),
};
const writable = [];
let looked = 0;
for (const stack = ["/usr/local"]; stack.length > 0; ) {
  const p = stack.pop();
  const st = fs.lstatSync(p);
  if (st.isSymbolicLink()) continue;
  looked++;
  try { fs.accessSync(p, fs.constants.W_OK); writable.push(p); } catch {}
  if (st.isDirectory()) { try { for (const n of fs.readdirSync(p)) stack.push(path.join(p, n)); } catch {} }
}
console.log(JSON.stringify({ tries, writable: writable.slice(0, 10), count: writable.length, looked }));`

// checkE2BUsrLocalClosed shows, as the session's user, that the open left nothing under
// /usr/local that user can create, replace, rename or write (finding hunt-quality-55):
// every try fails with a permission error, and the kernel names no file or folder there
// the user may write. Then that the session's own steps still find and run what the
// image put there.
func checkE2BUsrLocalClosed(t *testing.T, s sandbox.Session) {
	t.Helper()
	res := e2bSnippet(t, s, e2bUsrLocalGuest)
	var got struct {
		Tries    map[string]string
		Writable []string
		Count    int
		Looked   int
	}
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
		t.Fatalf("the guest's tries at /usr/local: %q: %v (stderr %q)", res.Stdout, err, res.Stderr)
	}
	t.Logf("the guest's tries at /usr/local: %v; it looked at %d files and folders there", got.Tries, got.Looked)
	if len(got.Tries) != 12 {
		t.Errorf("the guest made %d tries, want 12 (no program besides node in /usr/local/bin, or no folder in /usr/local?)", len(got.Tries))
	}
	for what, code := range got.Tries {
		if code != "EACCES" && code != "EPERM" {
			t.Errorf("the session's user tried to %s after the open: %s, want a permission error", what, code)
		}
	}
	if got.Count != 0 || got.Looked < 3 {
		t.Errorf("after the open the session's user may write %d of the %d files and folders under /usr/local (the first: %v); want none", got.Count, got.Looked, got.Writable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	step, err := s.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{`command -v node && node -e 'process.stdout.write("ran\n")'`}, Timeout: 30 * time.Second})
	if err != nil || step.Outcome != sandbox.ProjectOutcomeCompleted || len(step.Steps) != 1 || !strings.HasSuffix(strings.TrimSpace(string(step.Steps[0].Stdout)), "ran") {
		t.Fatalf("a step running the image's node after the open closed /usr/local: %+v, %v", step, err)
	}
	t.Logf("the step found node at %s", strings.Fields(string(step.Steps[0].Stdout))[0])
}

// An open closes /usr/local, which the stand-in's image has at mode 777 as E2B's build
// leaves it, to the session's code (finding hunt-quality-55).
func TestE2BSessionDockerClosesUsrLocal(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	s := openE2B(t, f.provider())
	checkE2BUsrLocalClosed(t, s)
	u := sandbox.E2BSessionUsrLocal(s)
	t.Logf("the open closed /usr/local: %d files and folders checked, %d changed, in %.1f ms", u.Entries, u.Changed, u.MS)
	if u.Changed == 0 {
		t.Errorf("the open changed nothing under /usr/local, which the stand-in opens to every user")
	}
	// The live test's listing of root's uses of /usr/local finds a process of root's
	// started by the path of a program there, planted for it (on the stand-in that node is a link to /usr/bin/node, so it is found by its command line).
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	got := listE2BRootUsesOfUsrLocal(t, ctx, s, `/usr/local/bin/node -e 'setTimeout(() => {}, 10000)' </dev/null >/dev/null 2>&1 & sleep 1`)
	found := false
	for _, p := range got.Processes {
		found = found || strings.HasPrefix(p.Argv, "/usr/local/bin/node -e setTimeout")
	}
	if !found {
		t.Errorf("the listing of root's uses of /usr/local did not find the planted process: %+v", got)
	}
	logE2BRootUsesOfUsrLocal(t, ctx, s)
}

// A template where the open cannot close /usr/local to the session's user (here a folder
// there owned by the guest's uid, which a mode change leaves the owner's) refuses the
// session: unsupported, not dispatched, in the open's words, and its sandbox deleted.
func TestE2BSessionDockerRefusesAUsrLocalItCannotClose(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	img, err := e2bDerived(f.image, "RUN mkdir -p /usr/local/share/plimsoll-guest-owned && chown 61000:61000 /usr/local/share/plimsoll-guest-owned\n")
	if err != nil {
		t.Fatal(err)
	}
	f.image = img
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := f.provider().OpenSession(ctx, sandbox.SessionOptions{Lifetime: time.Minute, DiskBytes: 64 << 20})
	if err == nil {
		_ = s.Close(context.Background())
		<-s.Done()
		t.Fatal("a session opened on a template with a folder under /usr/local the session's user owns")
	}
	if !errors.Is(err, sandbox.ErrE2BUsrLocalOpen) || !errors.Is(err, sandbox.ErrUnsupported) {
		t.Errorf("the refusal %q does not wrap both ErrE2BUsrLocalOpen and ErrUnsupported", err)
	}
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalUnsupported {
		t.Errorf("the refusal %q is marked %v, %v; want not dispatched, unsupported", err, reason, ok)
	}
	for _, want := range []string{"/usr/local/share/plimsoll-guest-owned", "can still write", "e2b/README.md", "E2B_TEMPLATE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}
	if n := f.containers(t); n != 0 {
		t.Errorf("the refused open left %d sandboxes", n)
	}
}

// A template where the real open refuses its machine (here an account that already has
// the guest's uid, e2b_session.js open, exit 2) refuses the session as not dispatched,
// reason environment, in the open's own words, never an internal error, and its sandbox
// is deleted.
func TestE2BSessionDockerMarksTheOpensRefusalNotDispatched(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	img, err := e2bDerived(f.image, "RUN echo 'plimsoll-taken:x:61000:61000::/nonexistent:/sbin/nologin' >> /etc/passwd\n")
	if err != nil {
		t.Fatal(err)
	}
	f.image = img
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := f.provider().OpenSession(ctx, sandbox.SessionOptions{Lifetime: time.Minute, DiskBytes: 64 << 20})
	if err == nil {
		_ = s.Close(context.Background())
		<-s.Done()
		t.Fatal("a session opened on a template with an account that has the guest's uid")
	}
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalEnvironment {
		t.Errorf("the refusal %q is marked %v, %v; want not dispatched, environment", err, reason, ok)
	}
	if !errors.Is(err, sandbox.ErrE2BOpenRefused) || !errors.Is(err, sandbox.ErrUnsupported) {
		t.Errorf("the refusal %q does not wrap both ErrE2BOpenRefused and ErrUnsupported", err)
	}
	for _, want := range []string{"uid/gid 61000 is already an account here: plimsoll-taken", "e2b/README.md", "E2B_TEMPLATE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "cannot hold a session") {
		t.Errorf("the refusal %q is the open's general failure", err)
	}
	if n := f.containers(t); n != 0 {
		t.Errorf("the refused open left %d sandboxes", n)
	}
}

// e2bRootUsesOfUsrLocal is what logE2BRootUsesOfUsrLocal runs as root: every process
// whose effective uid is root and whose program file, or any argument, is under
// /usr/local (itself left out), and every cron file and systemd unit file owned by root
// whose text names /usr/local, with the lines that do.
const e2bRootUsesOfUsrLocal = `const fs = require("fs"), path = require("path");
const out = { processes: [], files: [] };
for (const d of fs.readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(d) || d === String(process.pid)) continue;
  try {
    const uid = (/^Uid:\s*\d+\s+(\d+)/m.exec(fs.readFileSync("/proc/" + d + "/status", "latin1")) || [])[1];
    if (uid !== "0") continue;
    let exe = "";
    try { exe = fs.readlinkSync("/proc/" + d + "/exe"); } catch {}
    const argv = fs.readFileSync("/proc/" + d + "/cmdline", "latin1").split("\0").filter(Boolean);
    if (exe.startsWith("/usr/local/") || argv.some((a) => a.startsWith("/usr/local/")))
      out.processes.push({ pid: Number(d), exe, argv: argv.join(" ").slice(0, 300) });
  } catch {}
}
const seen = new Set();
const look = (p, kind, depth) => {
  let st, real;
  try { real = fs.realpathSync(p); st = fs.statSync(real); } catch { return; }
  if (seen.has(real)) return;
  seen.add(real);
  if (st.isDirectory()) {
    if (depth > 3) return;
    let names = [];
    try { names = fs.readdirSync(real); } catch {}
    for (const n of names) look(path.join(real, n), kind, depth + 1);
    return;
  }
  if (!st.isFile() || st.uid !== 0 || st.size > 1 << 20) return;
  let text = "";
  try { text = fs.readFileSync(real, "latin1"); } catch { return; }
  const lines = text.split("\n").filter((l) => l.includes("/usr/local")).map((l) => l.trim().slice(0, 200));
  if (lines.length > 0) out.files.push({ kind, path: p, lines: lines.slice(0, 5) });
};
for (const p of ["/etc/crontab", "/etc/anacrontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"]) look(p, "cron", 0);
for (const p of ["/etc/systemd/system", "/run/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]) look(p, "systemd", 0);
process.stdout.write(JSON.stringify(out));`

// logE2BRootUsesOfUsrLocal logs, as a fact for the record, what of root's in a session's
// machine runs from /usr/local or is scheduled to (e2bRootUsesOfUsrLocal): the programs a
// session's code could have replaced to become root, had the open left the folder open.
// It fails only when the listing itself cannot run, never on what it finds.
func logE2BRootUsesOfUsrLocal(t *testing.T, ctx context.Context, s sandbox.Session) {
	t.Helper()
	got := listE2BRootUsesOfUsrLocal(t, ctx, s, "")
	t.Logf("processes of root's running a program under /usr/local: %d", len(got.Processes))
	for _, p := range got.Processes {
		t.Logf("  pid %d, program %s: %s", p.PID, p.Exe, p.Argv)
	}
	t.Logf("cron and systemd files of root's that name /usr/local: %d", len(got.Files))
	for _, f := range got.Files {
		t.Logf("  %s %s: %q", f.Kind, f.Path, f.Lines)
	}
}

type e2bRootUses struct {
	Processes []struct {
		PID       int
		Exe, Argv string
	}
	Files []struct {
		Kind, Path string
		Lines      []string
	}
}

// listE2BRootUsesOfUsrLocal runs e2bRootUsesOfUsrLocal as root by the session's pinned
// node; before, when not empty, a shell command of the test's own, in the same root
// process tree (the stand-in's test plants a process there that the listing must find).
func listE2BRootUsesOfUsrLocal(t *testing.T, ctx context.Context, s sandbox.Session, before string) e2bRootUses {
	t.Helper()
	node := sandbox.E2BSessionBins(s)["node"]
	argv := []string{node, "-e", e2bRootUsesOfUsrLocal}
	if before != "" {
		argv = []string{"/bin/sh", "-c", before + `; exec "$0" -e "$1"`, node, e2bRootUsesOfUsrLocal}
	}
	out, stderr, code, err := sandbox.E2BSessionRoot(ctx, s, argv...)
	if err != nil || code != 0 {
		t.Fatalf("the listing of root's uses of /usr/local: exit %d, %v: %s", code, err, stderr)
	}
	var got e2bRootUses
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("the listing of root's uses of /usr/local: %q: %v", out, err)
	}
	return got
}

// e2bStagerThief is a cell that leaves a thread in the session's kept Python interpreter.
// The thread waits for the next call's stager (the node program whose arguments hold
// "stage"; its last one is the call's own directory), and once the call's snippet is
// written there, by the stager become the guest, it kills the stager, keeps a copy of the
// snippet in the work directory and runs it.
const e2bStagerThief = `import os, signal, subprocess, shutil, threading, time
def thief():
    end = time.time() + 60
    while time.time() < end:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                argv = open("/proc/%s/cmdline" % pid, "rb").read().split(b"\0")
            except OSError:
                continue
            if b"stage" not in argv or len(argv) < 2:
                continue
            path = argv[-2].decode() + "/snippet.cjs"
            while time.time() < end:
                try:
                    if os.path.getsize(path) > 0:
                        os.kill(int(pid), signal.SIGKILL)
                        code = open(path).read()
                        open("/work/stolen.txt", "w").write(code)
                        subprocess.run([shutil.which("node"), "-e", code], cwd="/work", timeout=20)
                        return
                except OSError:
                    pass
                if not os.path.exists("/proc/" + pid):
                    break
threading.Thread(target=thief, daemon=True).start()
print("armed")`

// A call whose stager code of the session killed after reading the call's snippet (which
// that code can then run: the thief does, and the log says whether it finished before the
// sweep after the call) is not marked not dispatched: once the stager has started,
// the call's bytes are where the guest can read them, so the stager's failure cannot show
// that nothing of the call ran. The rule is the docker sessions' (a call is never marked
// from anything the session's code can cause). The thief races the stager, so the test
// tries up to five calls and fails if it never takes one: it would show nothing.
func TestE2BSessionDockerCallWhoseStagerWasKilledIsNotMarked(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	s := openE2B(t, f.provider())
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cell := func(code string) sandbox.CellResult {
		t.Helper()
		res, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguagePython, Code: code, Timeout: 30 * time.Second})
		if err != nil {
			t.Fatalf("cell: %v", err)
		}
		return res
	}
	for attempt := 1; attempt <= 5; attempt++ {
		_ = cell(`import os
for p in ("/work/stolen.txt", "/work/ran.txt"):
    if os.path.exists(p): os.remove(p)`)
		if armed := cell(e2bStagerThief); strings.TrimSpace(armed.Stdout) != "armed" {
			t.Fatalf("the thief's cell: %+v", armed)
		}
		_, callErr := s.RunJavaScript(ctx, sandbox.Request{Code: `require("fs").writeFileSync("/work/ran.txt", "the call's code ran")`, Timeout: 20 * time.Second})
		// What the session's code did, read by a cell (a cell stages nothing). The thief's
		// node runs beside the cell, so its file is read again, at most 20 times.
		var seen string
		for range 20 {
			seen = strings.TrimSpace(cell(`import os; print(os.path.exists("/work/stolen.txt"), open("/work/ran.txt").read() if os.path.exists("/work/ran.txt") else "-")`).Stdout)
			if strings.HasSuffix(seen, "the call's code ran") {
				break
			}
			time.Sleep(250 * time.Millisecond) // fixed-wait: a pause between reads of a file another process writes; the loop bounds it
		}
		reason, marked := sandbox.NotDispatchedReason(callErr)
		t.Logf("attempt %d: the call answered %v (marked %v %s); the session's code saw: %s", attempt, callErr, marked, reason, seen)
		if !strings.HasPrefix(seen, "True") || callErr == nil {
			continue // the stager finished first, or the thief did not see it
		}
		if marked {
			t.Fatalf("a call whose code the session's code read and ran is marked not dispatched (%s): %v", reason, callErr)
		}
		return
	}
	t.Fatal("the session's code never killed a call's stager in five tries, so this test shows nothing")
}
