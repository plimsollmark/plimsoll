package sandbox_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/sessiontest"
)

// sessionDocker is the docker provider the session tests use, under the runtime and
// seccomp profile the docker suite selects, skipping (or failing, when docker
// coverage is required) without docker or its images.
func sessionDocker(t *testing.T) *sandbox.DockerSandbox {
	t.Helper()
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker coverage was required (SANDBOX_TEST_REQUIRE_DOCKER=1) but its infrastructure is missing: "+format, args...)
		}
		t.Skipf(format, args...)
	}
	if testing.Short() {
		skip("skipping docker session test in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("docker not available")
	}
	d := sandbox.DefaultDocker("")
	d.Runtime = os.Getenv("SANDBOX_DOCKER_RUNTIME")
	d.Seccomp = os.Getenv("SANDBOX_DOCKER_SECCOMP")
	for _, img := range []string{d.Image, d.ProjectImage} {
		if err := exec.Command("docker", "image", "inspect", img).Run(); err != nil {
			skip("image %s is not present (run `make docker-images`)", img)
		}
	}
	return d
}

// pythonSessionDocker is sessionDocker with the Python image (the base image plus
// python3) as the project image, so a session runs cells in both languages.
func pythonSessionDocker(t *testing.T) *sandbox.DockerSandbox {
	d := sessionDocker(t)
	const pythonImage = "plimsoll/sandbox-python:latest"
	if err := exec.Command("docker", "image", "inspect", pythonImage).Run(); err != nil {
		if os.Getenv("SANDBOX_TEST_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker coverage was required but %s is not present (run `make docker-images`)", pythonImage)
		}
		t.Skipf("%s is not present (run `make docker-images`)", pythonImage)
	}
	d.ProjectImage = pythonImage
	return d
}

// TestDockerSessionConformance runs the session conformance suite against the
// docker provider: the suite every session provider passes before it states
// sessions. The project image is the Python one (the base image plus python3), so
// the smoke test's language probe finds both languages and the cell cases run for
// each.
func TestDockerSessionConformance(t *testing.T) {
	d := pythonSessionDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	langs := d.SessionEnvironments().Project.Languages
	if !slices.Equal(langs, []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython}) {
		t.Fatalf("the language probe found %v in %s", langs, d.ProjectImage)
	}
	sessiontest.Run(t, d, sessiontest.Config{Lifetime: 5 * time.Minute, ShortLifetime: 20 * time.Second, Languages: langs, Teardown: sandbox.DockerRemoveBudget})
	dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
	defer dcancel()
	if err := d.Drain(dctx); err != nil {
		t.Fatal(err)
	}
}

func openDockerSession(t *testing.T, d *sandbox.DockerSandbox) sandbox.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := d.OpenSession(ctx, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}

func sessionJS(t *testing.T, s sandbox.Session, code string) (sandbox.Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return s.RunJavaScript(ctx, sandbox.Request{Code: code, Timeout: 10 * time.Second})
}

// sessionContainer names the one session container whose files hold marker. The
// sweep after a call runs off the caller's path and kills every process it does not
// keep, a probe exec'd from the host included (exit 137), so a killed probe is retried.
func sessionContainer(t *testing.T, s sandbox.Session, marker string) string {
	t.Helper()
	if _, err := sessionJS(t, s, `require("fs").writeFileSync("/tmp/`+marker+`","1")`); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "ps", "--filter", "label=io.plimsoll.session", "--format", "{{.Names}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range strings.Fields(string(out)) {
		for try := 0; ; try++ {
			err := exec.Command("docker", "exec", name, "test", "-e", "/tmp/"+marker).Run()
			if err == nil {
				return name
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 137 || try == 20 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Fatal("no session container holds the marker")
	return ""
}

// Done closes only once the container is removed (review F9): a session layer gives
// back the session's capacity on Done, and the container holds its memory until then.
func TestDockerSessionDoneWaitsForTheContainerRemoval(t *testing.T) {
	d := sessionDocker(t)
	s := openDockerSession(t, d)
	name := sessionContainer(t, s, "done-after-removal")
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(sandbox.DockerRemoveBudget + 5*time.Second):
		t.Fatal("Done was not closed within the removal budget")
	}
	if exec.Command("docker", "inspect", name).Run() == nil {
		t.Fatalf("Done closed while container %s still exists", name)
	}
}

// A suspend pauses the container and reports its memory as held; the next call
// resumes it.
func TestDockerSessionSuspendPausesAndHoldsMemory(t *testing.T) {
	d := sessionDocker(t)
	s := openDockerSession(t, d)
	name := sessionContainer(t, s, "suspend-marker")
	held, err := s.Suspend(context.Background())
	if err != nil || !held {
		t.Fatalf("Suspend: held %v, err %v; want the memory held", held, err)
	}
	out, _ := exec.Command("docker", "inspect", "--format", "{{.State.Paused}}", name).Output()
	if strings.TrimSpace(string(out)) != "true" {
		t.Fatalf("the container is not paused after Suspend: %q", out)
	}
	res, err := sessionJS(t, s, `console.log(require("fs").existsSync("/tmp/suspend-marker"))`)
	if err != nil || strings.TrimSpace(res.Stdout) != "true" {
		t.Fatalf("after the resume: %+v, %v", res, err)
	}
}

// The startup check plimsolld runs when sessions are enabled passes on this host.
// The session smoke test as the daemon runs it: after the provider's smoke test has
// proved the image's languages, so it runs a cell in each, here the Python image's two.
func TestDockerSessionSmokeTest(t *testing.T) {
	d := pythonSessionDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	if langs := d.SessionEnvironments().Project.Languages; !slices.Equal(langs, []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython}) {
		t.Fatalf("the language probe found %v", langs)
	}
	if err := sandbox.SessionSmokeTest(ctx, d, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20}); err != nil {
		t.Fatal(err)
	}
}

// A suspend or a resume the caller gives up on is not cut short: docker finishes the
// pause or unpause, the session's view of the container stays true, and the session
// goes on. Cut short, a pause docker had taken left the session thinking the
// container ran, and the next call ended it as paused by someone else.
func TestDockerSessionGivingUpOnPauseOrResumeKeepsTheSession(t *testing.T) {
	d := sessionDocker(t)
	s := openDockerSession(t, d)
	if _, err := sessionJS(t, s, `1`); err != nil {
		t.Fatal(err)
	}
	// The docker CLI takes tens of milliseconds to start, so the window in which a
	// cancel lands after docker took the request moves with the host: try every 5 ms.
	for delay := time.Duration(0); delay <= 120*time.Millisecond; delay += 5 * time.Millisecond {
		ctx, cancel := context.WithTimeout(context.Background(), delay)
		_, _ = s.Suspend(ctx)
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), delay)
		_, _ = s.RunJavaScript(ctx, sandbox.Request{Code: "1", Timeout: 10 * time.Second})
		cancel()
		res, err := sessionJS(t, s, `console.log("alive")`)
		if err != nil || strings.TrimSpace(res.Stdout) != "alive" {
			t.Fatalf("after giving up at %v: %+v, %v (session %v)", delay, res, err, s.Err())
		}
	}
}

// Anyone who can reach the docker daemon can connect a running container to a
// network. The read-back before the next call refuses it and ends the session.
func TestDockerSessionRefusesAContainerGivenANetwork(t *testing.T) {
	d := sessionDocker(t)
	s := openDockerSession(t, d)
	name := sessionContainer(t, s, "network-marker")
	if out, err := exec.Command("docker", "network", "connect", "bridge", name).CombinedOutput(); err != nil {
		// Docker itself refuses (measured on Docker 29.1.3, 2026-10-01): the threat cannot
		// happen here, and the read-back stays for a daemon that allows it.
		t.Logf("docker refused to connect a network to a --network none container: %s", out)
		return
	}
	_, err := sessionJS(t, s, `console.log("should not run")`)
	if !errors.Is(err, sandbox.ErrSessionEnded) || sandbox.SessionEndReason(s.Err()) != sandbox.SessionSandboxChanged {
		t.Fatalf("a call after a network was connected: %v (session %v)", err, s.Err())
	}
	if _, ok := sandbox.NotDispatchedReason(err); !ok {
		t.Fatalf("the refusal is not marked as not dispatched: %v", err)
	}
}

// A changed resource limit (docker update) is caught the same way.
func TestDockerSessionRefusesAChangedLimit(t *testing.T) {
	d := sessionDocker(t)
	s := openDockerSession(t, d)
	name := sessionContainer(t, s, "update-marker")
	if out, err := exec.Command("docker", "update", "--pids-limit", "4096", name).CombinedOutput(); err != nil {
		t.Fatalf("docker update: %v: %s", err, out)
	}
	_, err := sessionJS(t, s, `console.log("should not run")`)
	if !errors.Is(err, sandbox.ErrSessionEnded) || sandbox.SessionEndReason(s.Err()) != sandbox.SessionSandboxChanged {
		t.Fatalf("a call after the limit changed: %v (session %v)", err, s.Err())
	}
}

// Code in the session can kill the main process, which stops the container; the
// session ends with that reason rather than reporting docker's error as the call's.
// The killing call may still end as a plain result: its node can exit before the
// container stops, and the sweep after it can run before the stop too (under runsc in
// CI it did, 2026-10-03). Then the next call's read-back ends the session, so once
// docker reports the container stopped, the session has ended or the next call is
// refused with that reason.
func TestDockerSessionMainProcessKilled(t *testing.T) {
	d := sessionDocker(t)
	s := openDockerSession(t, d)
	name := sessionContainer(t, s, "main-process-marker")
	_, err := sessionJS(t, s, `const fs=require("fs");for(const p of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(p))continue;
let c="";try{c=fs.readFileSync("/proc/"+p+"/cmdline","latin1")}catch{continue}
if(c.startsWith("sleep\0"))process.kill(+p,"SIGKILL")}`)
	if err != nil && !errors.Is(err, sandbox.ErrSessionEnded) {
		t.Fatalf("the killing call failed with something other than the session's end: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, ierr := exec.Command("docker", "inspect", "--format", "{{.State.Running}}", name).Output()
		if ierr != nil || strings.TrimSpace(string(out)) == "false" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the container still runs 10 s after its main process was killed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if s.Err() == nil {
		if _, nerr := sessionJS(t, s, `console.log("should not run")`); !errors.Is(nerr, sandbox.ErrSessionEnded) {
			t.Fatalf("a call after the container stopped: %v, want the session's end", nerr)
		}
	}
	if got := sandbox.SessionEndReason(s.Err()); got != sandbox.SessionMainProcessEnded {
		t.Fatalf("the session ended with %v, want main_process_ended (killing call error %v)", got, err)
	}
}

// A session container a crashed daemon left behind is removed once its declared
// lifetime plus the margin has passed; a live one is not.
func TestDockerSessionReconcileOrphans(t *testing.T) {
	d := sessionDocker(t)
	live := openDockerSession(t, d)
	sessionContainer(t, live, "live-marker")
	name := "plsm-orphan-test-" + strings.ReplaceAll(t.Name(), "/", "-")
	_ = exec.Command("docker", "rm", "-f", name).Run()
	if out, err := exec.Command("docker", "run", "-d", "--name", name, "--network", "none",
		"--label", "io.plimsoll.session=1", "--label", "io.plimsoll.expires=1",
		"--entrypoint", "sleep", d.ProjectImage, "600").CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	n, err := d.ReconcileOrphans(context.Background())
	if err != nil || n < 1 {
		t.Fatalf("ReconcileOrphans: %d, %v", n, err)
	}
	if exec.Command("docker", "inspect", name).Run() == nil {
		t.Fatal("the orphan is still there")
	}
	if res, err := sessionJS(t, live, `console.log("alive")`); err != nil || strings.TrimSpace(res.Stdout) != "alive" {
		t.Fatalf("the live session after reconciliation: %+v, %v", res, err)
	}
}

// A call's grant lives for that call: the socket mounted at open serves it during
// the call, injects the credential host-side, and answers 503 to a later call that
// carries no grant, even one that dials the socket directly.
func TestDockerSessionGrantLivesForItsCall(t *testing.T) {
	d := sessionDocker(t)
	var mu sync.Mutex
	var auths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, `{"id":1}`)
	}))
	defer upstream.Close()
	grant := &sandbox.HostAPIGrant{
		BaseURL: upstream.URL,
		Allow:   []sandbox.HostRoute{{Method: "GET", Path: "/items/*"}},
		Minter:  sandbox.StaticToken("session-grant-token"),
		// A session call needs a grant that allows sessions.
		AllowInSessions: true,
	}
	s := openDockerSession(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := s.RunJavaScript(ctx, sandbox.Request{Code: `(async () => { const r = await host.get("/items/1"); console.log(JSON.stringify(r)); })()`, Grant: grant, Timeout: 10 * time.Second})
	if err != nil || res.ExitCode != 0 || !strings.Contains(res.Stdout, `"id":1`) {
		t.Fatalf("the grant call: %+v, %v", res, err)
	}
	if res.CallTrace == nil || len(res.CallTrace.Calls) != 1 {
		t.Fatalf("the grant call's trace: %+v", res.CallTrace)
	}
	mu.Lock()
	if len(auths) != 1 || auths[0] != "Bearer session-grant-token" {
		t.Fatalf("upstream saw %v", auths)
	}
	mu.Unlock()
	res, err = s.RunJavaScript(ctx, sandbox.Request{Code: `const http=require("node:http");
const req=http.request({socketPath:"/run/host-api.sock",path:"/items/1",method:"GET"},(r)=>{r.resume();r.on("end",()=>console.log("status",r.statusCode))});
req.on("error",(e)=>console.log("error",e.code));req.end();`, Timeout: 10 * time.Second})
	if err != nil || !strings.Contains(res.Stdout, "status 503") {
		t.Fatalf("a call without a grant reached the broker: %+v, %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(auths) != 1 {
		t.Fatalf("upstream was called %d times, want once", len(auths))
	}
}

// A pause freezes the interpreter with the rest of the container, so a docker
// session's variables survive an idle suspend (openshell's stop does not keep them;
// its next cell reports a fresh interpreter).
func TestDockerSessionPauseKeepsTheInterpreter(t *testing.T) {
	d := sessionDocker(t)
	s := openDockerSession(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if res, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: "const kept = 'across the pause'"}); err != nil || res.ExitCode != 0 {
		t.Fatalf("define: %+v, %v", res, err)
	}
	if held, err := s.Suspend(ctx); err != nil || !held {
		t.Fatalf("Suspend: %v, %v", held, err)
	}
	res, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: "kept"})
	if err != nil || res.InterpreterStarted || strings.TrimSpace(res.Stdout) != "'across the pause'" {
		t.Fatalf("after the pause: %+v, %v", res, err)
	}
}

// A docker session relays cells through a process it keeps attached beside the
// interpreter. Code that kills only the relay costs a new relay, not the state.
func TestDockerSessionRelayKilledKeepsTheInterpreter(t *testing.T) {
	d := sessionDocker(t)
	s := openDockerSession(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if res, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: "globalThis.kept = 7"}); err != nil || res.ExitCode != 0 {
		t.Fatalf("define: %+v, %v", res, err)
	}
	// The relay's command line names the interpreter's directory as its first
	// argument after the script; the interpreter's names it last. Kill the relay only.
	res, err := sessionJS(t, s, `const fs=require("fs");let n=0;for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d))continue;
let a=[];try{a=fs.readFileSync("/proc/"+d+"/cmdline","latin1").split("\0")}catch{continue}
if(a[0]==="node"&&a[1]==="-e"&&a[3]==="/tmp/.plimsoll-interp/javascript"&&a[4]==="/work"){try{process.kill(+d,"SIGKILL");n++}catch{}}}
console.log(n)`)
	if err != nil || strings.TrimSpace(res.Stdout) != "1" {
		t.Fatalf("killing the relay: %+v, %v", res, err)
	}
	got, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: "kept"})
	if err != nil || got.InterpreterStarted || strings.TrimSpace(got.Stdout) != "7" {
		t.Fatalf("after the relay was killed: %+v, %v", got, err)
	}
}
