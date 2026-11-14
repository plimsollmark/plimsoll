package wslc

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// readyPerRun is a per-run provider on a good fake whose smoke test has passed, with the
// calls so far cleared.
func readyPerRun(t *testing.T, setup func(*fakeSetup), mut ...func(*Config)) (*Provider, *fake) {
	t.Helper()
	s := goodSetup(t)
	if setup != nil {
		setup(&s)
	}
	f := newFake(t, s)
	p := f.provider(append([]func(*Config){perRun}, mut...)...)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatalf("per-run smoke test on a good fake: %v", err)
	}
	p.drain()
	f.clearCalls()
	return p, f
}

// leftovers is every entry under the run root but the template, and every listed session
// with the provider's prefix.
func leftovers(t *testing.T, p *Provider, f *fake) []string {
	t.Helper()
	p.drain()
	var left []string
	entries, err := os.ReadDir(f.runRoot())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != templateDirName {
			left = append(left, "dir "+e.Name())
		}
	}
	for name := range f.state().Sessions {
		if strings.HasPrefix(name, SessionPrefix) {
			left = append(left, "session "+name)
		}
	}
	return left
}

// The per-run smoke test builds its own template, runs the probe in two fresh sessions,
// and states the vm tier with what it read: two boot IDs that differ from each other, from
// the default session's and from this distribution's; the GPU device in the session VM and
// not in the container; the Windows folders the session VM mounts.
func TestPerRunSmokeTestStatesVMAndEvidence(t *testing.T) {
	s := goodSetup(t)
	f := newFake(t, s)
	p := f.provider(perRun)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.IsolationClass() != sandbox.IsolationVM {
		t.Fatalf("the per-run tier is %v", p.IsolationClass())
	}
	ev, ok := p.Evidence()
	if !ok || ev.Mode != ModePerRun || len(ev.RunSessions) != 2 {
		t.Fatalf("evidence: %+v", ev)
	}
	a, b := ev.RunSessions[0], ev.RunSessions[1]
	distro, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	for _, rs := range ev.RunSessions {
		if !sessionNameRE.MatchString(rs.Name) || !bootIDRE.MatchString(rs.BootID) || rs.BootID == fakeBootID || rs.BootID == strings.TrimSpace(string(distro)) {
			t.Fatalf("a smoke session: %+v", rs)
		}
	}
	if a.Name == b.Name || a.BootID == b.BootID {
		t.Fatalf("the two smoke sessions are one: %+v %+v", a, b)
	}
	if ev.DefaultSessionBootID != fakeBootID || ev.GPUInSessionVM != "present: "+fakeGPU || ev.GPUInContainer != "absent" {
		t.Fatalf("evidence: %+v", ev)
	}
	if !slices.Contains(ev.SessionVMWindowsMounts, "virtiofs ro /usr/lib/wsl/drivers") || !slices.Contains(ev.SessionVMWindowsMounts, "virtiofs rw /run/wsl/virtiofs-mounts/drvfs") {
		t.Fatalf("the session VM's Windows mounts: %q", ev.SessionVMWindowsMounts)
	}
	if ev.RunRoot != "C:/Users/fake/AppData/Local/plimsoll-wslc" || ev.TemplateBytes <= 0 {
		t.Fatalf("evidence: %+v", ev)
	}
	if _, err := os.Stat(filepath.Join(f.runRoot(), templateDirName, storageFile)); err != nil {
		t.Fatal(err)
	}
	// The template is built from nothing and the image crosses by ID alone: mkfs.ext4 ran,
	// the image was saved from the default session by ID and loaded into the new store,
	// and nothing ever copied a file of the default session's.
	var mkfs, saved, loaded bool
	for _, c := range f.calls() {
		switch {
		case c.Prog == "mkfs.ext4":
			mkfs = true
		case c.Prog == "wslc.exe" && len(c.Argv) == 4 && c.Argv[0] == "save" && c.Argv[3] == fakeImageID && c.Session == "":
			saved = true
		case c.Prog == "wslc.exe" && len(c.Argv) >= 3 && c.Argv[2] == "load" && sessionNameRE.MatchString(c.Session):
			loaded = true
		case c.Prog == "powershell.exe" && strings.Contains(c.Script, "Copy-Item"):
			if !strings.Contains(c.Script, "-LiteralPath 'C:/Users/fake/AppData/Local/plimsoll-wslc/plimsoll-template/storage.vhdx'") {
				t.Fatalf("a copy from somewhere other than the template: %s", c.Script)
			}
		}
		if strings.Contains(strings.Join(c.Argv, " ")+c.Script, "wslc/sessions") {
			t.Fatalf("a call names the default session's store: %v %s", c.Argv, c.Script)
		}
	}
	if !mkfs || !saved || !loaded {
		t.Fatalf("mkfs %v, saved %v, loaded %v", mkfs, saved, loaded)
	}
	if left := leftovers(t, p, f); len(left) != 0 {
		t.Fatalf("left after the smoke test: %v", left)
	}
}

// The shared mode's problem (one run's processes count against another's --ulimit nproc)
// cannot hold in the per-run mode: concurrent runs land in different sessions, each its own VM, and
// each session runs exactly one container.
func TestPerRunEachRunHasASessionOfItsOwn(t *testing.T) {
	p, f := readyPerRun(t, func(s *fakeSetup) { s.ContainerSleepMs = 300 }, func(c *Config) { c.MaxSessions = 3 })
	var wg sync.WaitGroup
	results := make([]sandbox.Result, 3)
	errs := make([]error, 3)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
		}()
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil || results[i].Isolation != sandbox.IsolationVM || results[i].ExitCode != 0 {
			t.Fatalf("run %d: %+v %v", i, results[i], errs[i])
		}
	}
	p.drain()
	perSession := map[string]int{}
	for _, c := range f.runs() {
		perSession[c.Session]++
	}
	if len(perSession) != 3 {
		t.Fatalf("three concurrent runs ran in %d sessions: %v", len(perSession), perSession)
	}
	for name, n := range perSession {
		if !sessionNameRE.MatchString(name) || n != 1 {
			t.Fatalf("session %q ran %d containers", name, n)
		}
	}
	if left := leftovers(t, p, f); len(left) != 0 {
		t.Fatalf("left after the runs: %v", left)
	}
}

// The holder's input is a root shell in the run's VM, so the only thing
// ever written to it is the fixed exit line, whatever the request holds.
func TestHolderInputIsOnlyTheExitLine(t *testing.T) {
	s := goodSetup(t)
	f := newFake(t, s)
	p := f.provider(perRun)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	canary := "canary-91c2; reboot -f\n exit\n"
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "console.log('" + canary + "')"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RunProject(context.Background(), sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "exit", Content: canary}}, Steps: []string{"cat exit # " + canary}}); err != nil {
		t.Fatal(err)
	}
	p.drain()
	enters := f.enters()
	if len(enters) != 5 { // the template build, the two smoke sessions, the two runs
		t.Fatalf("%d holders recorded, want 5", len(enters))
	}
	for _, c := range enters {
		if c.Stdin != holderExitLine {
			t.Fatalf("holder %v got input %q, want exactly %q", c.Argv, c.Stdin, holderExitLine)
		}
	}
	for _, c := range f.calls() {
		if strings.Contains(strings.Join(c.Argv, " ")+c.Script, "canary-91c2") {
			t.Fatalf("the canary reached the arguments of %s %v", c.Prog, c.Argv)
		}
		isRun := slices.ContainsFunc(f.runs(), func(r fakeCall) bool { return slices.Equal(r.Argv, c.Argv) })
		if !isRun && strings.Contains(c.Stdin, "canary-91c2") {
			t.Fatalf("the canary reached the input of %s %v, which is not a container run", c.Prog, c.Argv)
		}
	}
}

// The holder's input has one writer: only startHolder sets holder.in and only closeInput
// uses it, so no new code path can write a request's bytes into the VM's root shell.
func TestHolderInputHasOneWriter(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "perrun.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	uses := map[string]int{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "in" {
				uses[fn.Name.Name]++
			}
			return true
		})
	}
	for _, name := range []string{"closeInput", "startHolder"} {
		if uses[name] == 0 {
			t.Fatalf("%s does not touch holder.in; the guard is broken: %v", name, uses)
		}
		delete(uses, name)
	}
	if len(uses) != 0 {
		t.Fatalf("holder.in is used outside startHolder and closeInput: %v", uses)
	}
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if name == "perrun.go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), ".in.") || strings.Contains(string(b), ".in)") || strings.Contains(string(b), ".in,") {
			t.Fatalf("%s reaches a holder's input", name)
		}
	}
}

// Beyond SANDBOX_WSLC_MAX_SESSIONS runs at once a run is refused before anything starts,
// marked not dispatched (capacity), so it is safe to retry.
func TestPerRunCapacityRefusal(t *testing.T) {
	p, f := readyPerRun(t, func(s *fakeSetup) { s.ContainerSleepMs = 1500 }, func(c *Config) { c.MaxSessions = 1 })
	done := make(chan error, 1)
	go func() {
		_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.pr.mu.Lock()
		n := p.pr.running
		p.pr.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first run never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	refusal(t, err, sandbox.RefusalCapacity)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	p.drain()
	// A holder is recorded when its input ends: one, the first run's.
	if got := len(f.enters()); got != 1 || len(f.runs()) != 1 {
		t.Fatalf("the refused run started something: %d holders, %d container runs", got, len(f.runs()))
	}
	// Once the first run's session is gone, the next run goes ahead.
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
}

// The startup sweep terminates every listed session with
// the provider's prefix and deletes every directory it made, and touches nothing else.
func TestPerRunStartupSweep(t *testing.T) {
	f := newFake(t, goodSetup(t))
	orphan := SessionPrefix + "00112233445566ff"
	root := f.runRoot()
	for _, d := range []string{orphan, templateDirName, "keep-me"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, orphan+".tar"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	state := map[string]any{"sessions": map[string]any{
		orphan:         map[string]any{"dir": filepath.Join(root, orphan), "bootID": "11111111-2222-4333-8444-555555555555"},
		"someone-else": map[string]any{"dir": "/elsewhere", "bootID": "66666666-2222-4333-8444-555555555555"},
	}}
	b, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(f.dir, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	p := f.provider(perRun)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := f.state()
	if _, ok := st.Sessions[orphan]; ok || !slices.Contains(st.Terminated, orphan) {
		t.Fatalf("the orphan was not terminated: %+v", st)
	}
	if _, ok := st.Sessions["someone-else"]; !ok {
		t.Fatal("the sweep ended a session that is not the provider's")
	}
	for _, gone := range []string{orphan, orphan + ".tar"} {
		if _, err := os.Stat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s is still there: %v", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "keep-me")); err != nil {
		t.Fatalf("the sweep deleted a directory that is not the provider's: %v", err)
	}
	if left := leftovers(t, p, f); !slices.Equal(left, []string{"dir keep-me"}) {
		t.Fatalf("left: %v", left)
	}
}

// The give-up path: a holder that dies under its run (killed, as when the OOM killer takes
// it) leaves its session listed; the run's teardown terminates it and deletes its
// directory. So does a session that stays listed after its holder's polite end.
func TestPerRunGiveUpPathTerminates(t *testing.T) {
	for _, mode := range []string{"die", "stay"} {
		t.Run(mode, func(t *testing.T) {
			// The holder misbehaves from the run on: a template build would refuse its store.
			p, f := readyPerRun(t, nil)
			s := goodSetup(t)
			s.EnterMode = mode
			f.set(s)
			p.teardownTimeout = 100 * time.Millisecond
			res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			if err != nil || res.ExitCode != 0 {
				t.Fatalf("%+v %v", res, err)
			}
			p.drain()
			runs := f.runs()
			if len(runs) != 1 || !slices.Contains(f.state().Terminated, runs[0].Session) {
				t.Fatalf("the run's session was not terminated: %+v", f.state())
			}
			if left := leftovers(t, p, f); len(left) != 0 {
				t.Fatalf("left: %v", left)
			}
		})
	}
}

// A VM whose boot ID was seen before is not fresh: the smoke test refuses it, and leaves
// nothing behind.
func TestPerRunRefusesAReusedVM(t *testing.T) {
	s := goodSetup(t)
	s.SameBootID = true
	f := newFake(t, s)
	p := f.provider(perRun)
	err := p.SmokeTest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "seen before") {
		t.Fatalf("smoke test with every session on the default session's boot ID: %v", err)
	}
	if _, ok := p.Evidence(); ok {
		t.Fatal("evidence after a refused smoke test")
	}
	if left := leftovers(t, p, f); len(left) != 0 {
		t.Fatalf("left: %v", left)
	}
}

// A container that has the GPU device is refused, in both modes.
func TestSmokeTestRefusesTheGPUInTheContainer(t *testing.T) {
	for _, mode := range []Mode{ModeShared, ModePerRun} {
		probe := goodProbe()
		probe["gpu"] = "present"
		b, _ := json.Marshal(probe)
		s := goodSetup(t)
		s.ProbeStdout = string(b)
		f := newFake(t, s)
		p := f.provider(func(c *Config) { c.Mode = mode })
		if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), "/dev/dxg") {
			t.Fatalf("%s: a container with the GPU device: %v", mode, err)
		}
	}
}

// A new store that holds anything but the image is refused, and the build leaves nothing.
func TestTemplateRefusesAStoreThatHoldsMore(t *testing.T) {
	s := goodSetup(t)
	s.StoreExtra = "container"
	f := newFake(t, s)
	p := f.provider(perRun)
	if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), "containers") {
		t.Fatalf("a store with a container: %v", err)
	}
	p.drain()
	entries, _ := os.ReadDir(f.runRoot())
	if len(entries) != 0 {
		t.Fatalf("the failed build left %v", entries)
	}
	if len(f.state().Sessions) != 0 {
		t.Fatalf("the failed build left sessions %v", f.state().Sessions)
	}
}

// A template build whose session did not end at its exit line (its holder was killed, or
// the session stayed listed and was terminated) refuses the store: whether terminate lets
// dockerd write the loaded image out is not measured, and the fake's terminate does not.
// Nothing is left: no session, no directory, no archive, no template.
func TestTemplateRefusesAStoreItsSessionDidNotEnd(t *testing.T) {
	for _, mode := range []string{"die", "stay"} {
		t.Run(mode, func(t *testing.T) {
			s := goodSetup(t)
			s.EnterMode = mode
			f := newFake(t, s)
			p := f.provider(perRun)
			err := p.SmokeTest(context.Background())
			if err == nil || !strings.Contains(err.Error(), "did not end at its exit line") {
				t.Fatalf("a template whose session was terminated: %v", err)
			}
			if _, ok := p.Evidence(); ok {
				t.Fatal("evidence after a refused template")
			}
			p.drain()
			if entries, _ := os.ReadDir(f.runRoot()); len(entries) != 0 {
				t.Fatalf("the refused build left %v", entries)
			}
			if !slices.ContainsFunc(f.state().Terminated, func(n string) bool { return strings.HasPrefix(n, SessionPrefix) }) {
				t.Fatalf("the build's session was not terminated: %+v", f.state())
			}
			if left := leftovers(t, p, f); len(left) != 0 {
				t.Fatalf("left: %v", left)
			}
		})
	}
}

// A save that fails part-way leaves its archive beside the build's directory; the failed
// build deletes it with everything else.
func TestTemplateBuildRemovesTheArchiveOnFailure(t *testing.T) {
	s := goodSetup(t)
	s.SaveFails = true
	f := newFake(t, s)
	p := f.provider(perRun)
	if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), "could not be written") {
		t.Fatalf("a failed save: %v", err)
	}
	p.drain()
	if entries, _ := os.ReadDir(f.runRoot()); len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the failed build left %v", names)
	}
	if len(f.state().Sessions) != 0 {
		t.Fatalf("the failed build left sessions %v", f.state().Sessions)
	}
}

// Before the smoke test has placed the template, reconciling does nothing, even with the
// run root found and an orphan's directory in it: the smoke test sweeps for itself, and
// the template build's directory is no live run's just before its rename.
func TestPerRunReconcileWaitsForTheTemplate(t *testing.T) {
	f := newFake(t, goodSetup(t))
	p := f.provider(perRun)
	if err := p.resolveRoot(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.clearCalls()
	building := filepath.Join(f.runRoot(), SessionPrefix+"0123456789abcdef")
	if err := os.Mkdir(building, 0o755); err != nil {
		t.Fatal(err)
	}
	if n, err := p.ReconcileOrphans(context.Background()); n != 0 || err != nil {
		t.Fatalf("reconcile before the template: %d, %v", n, err)
	}
	if _, err := os.Stat(building); err != nil {
		t.Fatalf("reconcile before the template deleted %s: %v", building, err)
	}
	if len(f.calls()) != 0 {
		t.Fatalf("reconcile before the template called %v", f.calls())
	}
}

// Every failure before the container starts ran nothing: it is marked not dispatched, and
// nothing is left.
func TestPerRunStartFailuresAreNotDispatched(t *testing.T) {
	for name, set := range map[string]func(*fakeSetup){
		"copy fails":   func(s *fakeSetup) { s.CopyFails = true },
		"enter fails":  func(s *fakeSetup) { s.EnterMode = "fail" },
		"never listed": func(s *fakeSetup) { s.EnterMode = "unlisted" },
	} {
		t.Run(name, func(t *testing.T) {
			p, f := readyPerRun(t, nil)
			s := goodSetup(t)
			set(&s)
			f.set(s)
			p.listTimeout = 200 * time.Millisecond
			_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			refusal(t, err, sandbox.RefusalEnvironment)
			if len(f.runs()) != 0 {
				t.Fatal("a container started")
			}
			if left := leftovers(t, p, f); len(left) != 0 {
				t.Fatalf("left: %v", left)
			}
		})
	}
}

// Every argument the per-run path builds passes safeArg, and the caller's text is in none
// of them: not in wslc's, not in powershell.exe's script, not in mkfs.ext4's.
func TestPerRunArgvIsInteropSafe(t *testing.T) {
	s := goodSetup(t)
	f := newFake(t, s)
	p := f.provider(perRun)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	canary := "x\" & echo pwned \\ % $(id) é"
	if _, err := p.RunProject(context.Background(), sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "q.js", Content: canary}}, Steps: []string{"node q.js # " + canary}}); err != nil {
		t.Fatal(err)
	}
	p.drain()
	for _, c := range f.calls() {
		if err := checkArgs(c.Argv); err != nil {
			t.Fatalf("%s %v: %v", c.Prog, c.Argv, err)
		}
		if strings.Contains(strings.Join(c.Argv, " ")+c.Script, "pwned") {
			t.Fatalf("the caller's text reached %s's arguments", c.Prog)
		}
		if len(c.Env) != 1 || !strings.HasPrefix(c.Env[0], "PATH=") {
			t.Fatalf("%s started with environment %q", c.Prog, c.Env)
		}
	}
}

// The floor a request may ask of the per-run mode is vm; of the shared mode, container.
func TestPerRunFloor(t *testing.T) {
	p, _ := readyPerRun(t, nil)
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM}); err != nil {
		t.Fatal(err)
	}
	q, _ := ready(t)
	_, err := q.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM})
	refusal(t, err, sandbox.RefusalIsolation)
}

// The shared mode's smoke test records the session it landed in, the GPU
// device in that session's VM and the VM's Windows mounts.
func TestSharedSmokeRecordsTheSession(t *testing.T) {
	p, _ := ready(t)
	ev, _ := p.Evidence()
	if ev.Mode != ModeShared || ev.Session != "wslc-cli-test" || ev.GPUInSessionVM != "present: "+fakeGPU || ev.GPUInContainer != "absent" {
		t.Fatalf("evidence: %+v", ev)
	}
	if p.IsolationClass() != sandbox.IsolationContainer {
		t.Fatal("the shared tier is not container")
	}
}

func TestModeFromEnv(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{"SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	// An unset mode is per-run, and the shared mode is chosen by setting it.
	for _, set := range [][]string{{}, {"SANDBOX_WSLC_MODE", "per-run"}} {
		prov, err := FromEnv(env(set...))
		if err != nil {
			t.Fatal(err)
		}
		if p := prov.Sandbox.(*Provider); p.Mode() != ModePerRun || p.IsolationClass() != sandbox.IsolationVM || p.cfg.MaxSessions != 2 {
			t.Fatalf("mode %v: %v, %v, %d sessions", set, p.Mode(), p.IsolationClass(), p.cfg.MaxSessions)
		}
	}
	prov, err := FromEnv(env("SANDBOX_WSLC_MODE", "shared"))
	if err != nil {
		t.Fatal(err)
	}
	if p := prov.Sandbox.(*Provider); p.Mode() != ModeShared || p.IsolationClass() != sandbox.IsolationContainer {
		t.Fatalf("shared: %v, %v", p.Mode(), p.IsolationClass())
	}
	for name, c := range map[string]struct {
		env  func(string) string
		want string
	}{
		"unknown mode":     {env("SANDBOX_WSLC_MODE", "vm"), "SANDBOX_WSLC_MODE"},
		"cap in shared":    {env("SANDBOX_WSLC_MODE", "shared", "SANDBOX_WSLC_MAX_SESSIONS", "2"), "per-run only"},
		"root in shared":   {env("SANDBOX_WSLC_MODE", "shared", "SANDBOX_WSLC_RUN_ROOT", "/mnt/c/x"), "per-run only"},
		"cap too high":     {env("SANDBOX_WSLC_MODE", "per-run", "SANDBOX_WSLC_MAX_SESSIONS", "17"), "between 1 and 16"},
		"cap not a number": {env("SANDBOX_WSLC_MODE", "per-run", "SANDBOX_WSLC_MAX_SESSIONS", "two"), "whole number"},
		"relative root":    {env("SANDBOX_WSLC_MODE", "per-run", "SANDBOX_WSLC_RUN_ROOT", "mnt/c/x"), "clean absolute"},
		"unclean root":     {env("SANDBOX_WSLC_MODE", "per-run", "SANDBOX_WSLC_RUN_ROOT", "/mnt/c/x/../y"), "clean absolute"},
	} {
		if _, err := FromEnv(c.env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// A run's session directory exists from the template copy on, before any process of its
// own: a concurrent run's give-up sweep and the daemon's periodic ReconcileOrphans must
// spare it, and still end a session and a directory that nothing live holds (the
// periodic sweep must not delete a run that has only started).
func TestPerRunReconcileSparesAStartingRun(t *testing.T) {
	p, f := readyPerRun(t, nil)
	starting := p.newHolder()
	if err := os.Mkdir(starting.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	orphan := SessionPrefix + "00112233445566ff"
	if err := os.Mkdir(filepath.Join(f.runRoot(), orphan), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(f.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	sessions, _ := st["sessions"].(map[string]any)
	if sessions == nil {
		sessions = map[string]any{}
		st["sessions"] = sessions
	}
	sessions[orphan] = map[string]any{"dir": filepath.Join(f.runRoot(), orphan), "bootID": "11111111-2222-4333-8444-555555555555"}
	raw, _ = json.Marshal(st)
	if err := os.WriteFile(filepath.Join(f.dir, "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := p.ReconcileOrphans(context.Background())
	if _, statErr := os.Stat(starting.dir); statErr != nil {
		t.Fatalf("the sweep deleted the directory of a run that had only started: %v", statErr)
	}
	if err != nil || n != 1 {
		t.Fatalf("reconcile ended %d sessions: %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(f.runRoot(), orphan)); !os.IsNotExist(err) {
		t.Fatalf("the orphan's directory is still there: %v", err)
	}
	if !slices.Contains(f.state().Terminated, orphan) {
		t.Fatalf("the orphan was not terminated: %+v", f.state())
	}
	if err := p.endSession(starting, false, false); err != nil {
		t.Fatal(err)
	}
	if left := leftovers(t, p, f); len(left) != 0 {
		t.Fatalf("left: %v", left)
	}
}

// The daemon calls Drain on shutdown so a teardown that runs after the result is not cut
// off with the process; without it the session waits for the next startup's sweep.
func TestPerRunDrainWaitsForTeardowns(t *testing.T) {
	p, f := readyPerRun(t, nil)
	s := goodSetup(t)
	s.EnterMode = "stay"
	f.set(s)
	p.teardownTimeout = 300 * time.Millisecond
	d, ok := any(p).(sandbox.Drainer)
	if !ok {
		t.Fatal("the provider is not a sandbox.Drainer: shutdown would not wait for its teardowns")
	}
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := d.Drain(short); err == nil {
		t.Fatal("Drain returned nil with a teardown still running")
	}
	if err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	// No p.drain here: Drain alone must have waited.
	var left []string
	for name := range f.state().Sessions {
		if strings.HasPrefix(name, SessionPrefix) {
			left = append(left, name)
		}
	}
	entries, _ := os.ReadDir(f.runRoot())
	for _, e := range entries {
		if e.Name() != templateDirName {
			left = append(left, e.Name())
		}
	}
	if len(left) != 0 {
		t.Fatalf("left after Drain: %v", left)
	}
	if _, ok := any(p).(sandbox.OrphanReconciler); !ok {
		t.Fatal("the provider is not a sandbox.OrphanReconciler")
	}
}
