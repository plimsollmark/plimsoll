package wslc

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
)

// ready is a provider on a good fake whose smoke test has passed, with the calls so far
// cleared.
func ready(t *testing.T, mut ...func(*Config)) (*Provider, *fake) {
	t.Helper()
	var cfg Config
	for _, m := range mut {
		m(&cfg)
	}
	f := newFake(t, goodSetupFor(t, cfg))
	p := f.provider(mut...)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatalf("smoke test on a good fake: %v", err)
	}
	f.clearCalls()
	return p, f
}

func refusal(t *testing.T, err error, want sandbox.Refusal) {
	t.Helper()
	got, marked := sandbox.NotDispatchedReason(err)
	if !marked || got != want {
		t.Fatalf("error %v: marked %v reason %v, want not dispatched (%v)", err, marked, got, want)
	}
}

// The package starts a process only through hostCommand, and nothing else sets a
// command's environment, so the closed environment and the argument check cannot be
// bypassed by a new call site.
func TestProcessesStartOnlyThroughHostCommand(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	starters := map[string][]string{"exec": {"Command", "CommandContext"}, "os": {"StartProcess"}, "syscall": {"Exec", "ForkExec", "StartProcess"}}
	fset := token.NewFileSet()
	checked := 0
	parentLit := map[*ast.SelectorExpr]struct{}{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			inside := fn != nil && fn.Name.Name == "startHost" && name == "exec.go"
			ast.Inspect(decl, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					pkg, ok := n.X.(*ast.Ident)
					if ok && slices.Contains(starters[pkg.Name], n.Sel.Name) {
						checked++
						if !inside {
							t.Errorf("%s: %s.%s outside startHost: start a process only through hostCommand or startHost (exec.go)", fset.Position(n.Pos()), pkg.Name, n.Sel.Name)
						}
					}
					// An exec.Cmd built by hand would skip hostCommand.
					if ok && pkg.Name == "exec" && n.Sel.Name == "Cmd" {
						if _, lit := parentLit[n]; lit {
							t.Errorf("%s: builds an exec.Cmd by hand", fset.Position(n.Pos()))
						}
					}
				case *ast.CompositeLit:
					if sel, ok := n.Type.(*ast.SelectorExpr); ok {
						parentLit[sel] = struct{}{}
					}
				case *ast.AssignStmt:
					for _, lhs := range n.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Env" && !inside {
							t.Errorf("%s: sets a command's Env outside startHost", fset.Position(n.Pos()))
						}
					}
				}
				return true
			})
		}
	}
	if checked != 1 {
		t.Fatalf("found %d process starts in the package, want exactly the one in startHost; the guard is broken", checked)
	}
}

// wslc.exe gets PATH and nothing else: no variable of this process, a canary planted in
// it included, and no WSLENV asking interop to translate one. The planted WSLENV names the
// canary with no flag, a form that crosses into a Windows process ("/u" would not: it is
// "only included when running WSL from Win32", learn.microsoft.com/en-us/windows/wsl/filesystems).
func TestWSLCEnvironmentIsPathAlone(t *testing.T) {
	t.Setenv("PLIMSOLL_TOKEN", "canary-7f3a")
	t.Setenv("WSLENV", "PLIMSOLL_TOKEN")
	t.Setenv("WSL_INTEROP", "/run/WSL/1_interop")
	p, f := ready(t)
	if _, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	if len(calls) == 0 {
		t.Fatal("no call recorded")
	}
	for _, c := range calls {
		if len(c.Env) != 1 || !strings.HasPrefix(c.Env[0], "PATH=") {
			t.Errorf("wslc %v started with environment %q, want PATH alone", c.Argv, c.Env)
		}
		if strings.Contains(strings.Join(c.Env, "\n")+strings.Join(c.Argv, " ")+c.Stdin, "canary-7f3a") {
			t.Errorf("the canary reached wslc %v", c.Argv)
		}
	}
}

// Every argument the run path builds is a fixed flag or a checked ID, so the interop
// command line (each argument quoted only when it holds a space, tab or quote, by WSL's
// FormatCommandLine) is the arguments joined by spaces and splits back into them; and
// nothing a caller sent reaches argv: files, steps and the image's environment travel on
// stdin.
func TestRunArgvIsInteropSafe(t *testing.T) {
	for _, cfg := range []func(*Config){
		func(*Config) {},
		func(c *Config) { c.CPUs, c.MemoryMB, c.DiskMB, c.Nproc = 0.25, 2048, 1024, 4096 },
		func(c *Config) { c.Image = "registry.example:5000/team/sandbox@sha256:" + strings.Repeat("cd", 32) },
	} {
		p, f := ready(t, cfg)
		argv := p.runArgv(containerName(), fakeImageID)
		if err := checkArgs(argv); err != nil {
			t.Fatalf("runArgv: %v (%q)", err, argv)
		}
		if got := strings.Fields(strings.Join(argv, " ")); !slices.Equal(got, argv) {
			t.Fatalf("the joined command line splits into %q, not %q", got, argv)
		}
		canary := "x\" & echo pwned \\ % $(id) é"
		_, err := p.RunProject(context.Background(), sandbox.ProjectRequest{
			Files: []sandbox.File{{Path: "q.js", Content: canary}}, Steps: []string{"node q.js # " + canary}})
		if err != nil {
			t.Fatal(err)
		}
		runs := f.runs()
		if len(runs) != 1 {
			t.Fatalf("%d runs recorded", len(runs))
		}
		if err := checkArgs(runs[0].Argv); err != nil {
			t.Fatalf("the recorded argv: %v", err)
		}
		if strings.Contains(strings.Join(runs[0].Argv, " "), "pwned") || !strings.Contains(runs[0].Stdin, "pwned") {
			t.Fatal("the caller's text is in argv, or missing from the plan on stdin")
		}
		if !strings.Contains(runs[0].Stdin, "NODE_VERSION=22.11.0") {
			t.Fatal("the image's environment is not in the plan the steps get")
		}
	}
}

// The run flags are the whole lockdown WSLC offers, in full, ahead of the image; the image is the
// inspected ID, and the command is the runner under env -i.
func TestRunArgvCarriesTheLockdown(t *testing.T) {
	p, _ := ready(t)
	argv := p.runArgv("plimsoll-wslc-0123", fakeImageID)
	at := slices.Index(argv, fakeImageID)
	if at < 0 {
		t.Fatalf("the image ID is not in %q", argv)
	}
	flags, cmd := strings.Join(argv[:at], " "), argv[at+1:]
	for _, want := range []string{"container run", "--rm", "--interactive", "--name plimsoll-wslc-0123", "--pull never", "--network none",
		"--cap-drop ALL", "--user 61000:61000", "--memory 536870912", "--cpus 1", "--ulimit nproc=256:256", "--ulimit nofile=4096:4096",
		"--ulimit core=0:0", "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777", "--tmpfs /var/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
		"--tmpfs /dev/shm:rw,noexec,nosuid,nodev,size=16m,mode=1777", "--tmpfs /work:rw,noexec,nosuid,nodev,size=128m,mode=1777",
		"--no-healthcheck", "--entrypoint /usr/bin/env", "--dns 127.0.0.1", "--dns-search ."} {
		if !strings.Contains(flags, want) {
			t.Errorf("the run flags lack %q", want)
		}
	}
	for _, banned := range []string{"--volume", "-v", "--mount", "--privileged", "--cap-add", "--publish", "--gpus", "--env"} {
		if slices.Contains(argv[:at], banned) {
			t.Errorf("the run flags carry %s", banned)
		}
	}
	// The runner is the native helper, started under a clean environment and nothing else:
	// no guard library (it makes itself non-dumpable) and no node.
	want := append([]string{"-i", "PATH=" + controlPath, "HOME=/"}, nativehelper.RunProject...)
	if !slices.Equal(cmd, want) {
		t.Fatalf("the container command is %q, want %q", cmd, want)
	}
}

// An argument outside the safe set fails before any process exists.
func TestUnsafeArgumentStartsNothing(t *testing.T) {
	f := newFake(t, goodSetup(t))
	p := f.provider()
	for _, bad := range []string{"a b", `a"b`, `a\b`, "a%PATH%", "é", "", "a\nb"} {
		if _, err := p.output(context.Background(), "image", "inspect", bad); !errors.Is(err, errUnsafeArg) {
			t.Errorf("argument %q: %v, want errUnsafeArg", bad, err)
		}
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Fatalf("an unsafe argument started wslc: %v", calls)
	}
}

// Preflight reads only wslc's version, which needs no session VM, and refuses a missing
// wslc.exe in plain words and a release before 3.0.5.
func TestPreflight(t *testing.T) {
	f := newFake(t, goodSetup(t))
	p := f.provider()
	if err := p.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	if len(calls) != 1 || strings.Join(calls[0].Argv, " ") != "version --format json" {
		t.Fatalf("Preflight ran %v, want the version alone", calls)
	}
	for _, v := range []string{"3.0.3.0", "2.6.3.0", "garbage", ""} {
		s := goodSetup(t)
		s.Version = v
		f.set(s)
		if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "3.0.5") {
			t.Errorf("version %q: %v", v, err)
		}
	}
	// A machine with no WSL containers and none of the per-run mode's Windows programs (a
	// Linux CI runner): the answer names the missing wslc.exe, the first thing to fix.
	none := t.TempDir()
	missing := Config{Path: filepath.Join(none, "wslc.exe"), Image: "plimsoll/sandbox:latest",
		PowerShell: filepath.Join(none, "powershell.exe"), Mkfs: filepath.Join(none, "mkfs.ext4")}
	pm, err := New(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err := pm.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "has no WSL containers") {
		t.Fatalf("a missing wslc.exe: %v", err)
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		got  string
		want bool
	}{{"3.0.5", true}, {"3.0.5.0", true}, {"3.0.10.0", true}, {"3.1.0.0", true}, {"4.0.0", true},
		{"3.0.4.9", false}, {"3.0.3.0", false}, {"2.9.13", false}, {"3.0.5-rc", false}, {"", false}} {
		if got := versionAtLeast(c.got, MinVersion); got != c.want {
			t.Errorf("versionAtLeast(%q) = %v", c.got, got)
		}
	}
}

// The smoke test runs the probe through the run path, and Describe's environments name
// the inspected image after it.
func TestSmokeTestPassesAndStatesTheImage(t *testing.T) {
	f := newFake(t, goodSetup(t))
	p := f.provider()
	if env := p.Environments(); env.Project.Identity != "" {
		t.Fatalf("an identity before the smoke test: %+v", env)
	}
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	runs := f.runs()
	if len(runs) != 1 || !strings.Contains(runs[0].Stdin, `"steps":["node probe.js"]`) {
		t.Fatalf("the smoke test's run: %+v", runs)
	}
	if !slices.Equal(runs[0].Argv, p.runArgv(runs[0].Argv[slices.Index(runs[0].Argv, "--name")+1], fakeImageID)) {
		t.Fatal("the smoke test's container was not built by runArgv")
	}
	env := p.Environments()
	if env.Project.Identity != "wslc-image:"+fakeImageID || env.JavaScript.Identity != env.Project.Identity || env.Project.SoftwareIdentity != "" {
		t.Fatalf("environments after the smoke test: %+v", env)
	}
	ev, ok := p.Evidence()
	if !ok || ev.Seccomp != "2" || ev.NoNewPrivs != "0" || ev.PidsMax != "max" || ev.BootID != fakeBootID || ev.Moby == "" || ev.WSLVersion != "3.0.5.0" {
		t.Fatalf("evidence: %+v", ev)
	}
}

// Each way the probe container could be weaker than the one runArgv asks for refuses
// startup, and runs stay refused (not dispatched) after.
func TestSmokeTestRefusesAWeakerContainer(t *testing.T) {
	type probe = map[string]any
	status := func(k, v string) func(probe) {
		return func(r probe) { r["status"].(map[string]string)[k] = v }
	}
	set := func(k string, v any) func(probe) { return func(r probe) { r[k] = v } }
	mount := func(old, repl string) func(probe) {
		return func(r probe) {
			m := slices.Clone(r["mountinfo"].([]string))
			for i, l := range m {
				if strings.Contains(l, old) {
					m[i] = repl
				}
			}
			r["mountinfo"] = m
		}
	}
	cases := map[string]struct {
		mut  func(probe)
		want string
	}{
		"no seccomp filter":       {status("Seccomp", "0"), "not a filter"},
		"a capability left":       {status("CapEff", "00000000a80425fb"), "CapEff"},
		"bounding set left":       {status("CapBnd", "00000000a80425fb"), "CapBnd"},
		"root":                    {status("Uid", "0\t0\t0\t0"), "--user was not applied"},
		"a supplementary group":   {status("Groups", "61000 27"), "supplementary"},
		"a network":               {set("interfaces", []string{"lo", "eth0"}), "loopback alone"},
		"a connection":            {set("connect", map[string]string{"1.1.1.1:443": "connected"}), "reached"},
		"a writable image dir":    {set("writable", []string{"/dev/shm", "/opt/x", "/tmp", "/var/tmp", "/work"}), "accepted a write"},
		"a tmpfs refused writes":  {set("writable", []string{"/dev/shm", "/tmp", "/work"}), "accepted a write"},
		"walk cut short":          {set("walk", map[string]any{"entries": 400001, "truncated": true}), "stopped"},
		"memory not applied":      {set("memoryMax", "max"), "memory.max"},
		"nproc not applied":       {set("limits", map[string]string{"Max processes": "unlimited unlimited", "Max open files": "4096 4096", "Max core file size": "0 0"}), "Max processes"},
		"a search domain":         {set("resolv", "nameserver 127.0.0.1\nsearch corp.example\n"), "search"},
		"an outside nameserver":   {set("resolv", "nameserver 10.255.255.254\n"), "nameserver"},
		"an outside variable":     {set("envNames", []string{"HOME", "PATH", "WSL_INTEROP"}), "WSL_INTEROP"},
		"runner memory readable":  {set("runnerMem", "open"), "not non-dumpable"},
		"no runner":               {set("helper", map[string]any{"error": "ENOENT"}), "no file at /usr/local/libexec/plimsoll-helper"},
		"another runner":          {set("helper", map[string]any{"type": "file", "uid": 0, "mode": 0o755, "sha256": strings.Repeat("0", 64)}), "the native helper this plimsolld carries"},
		"a runner the guest owns": {set("helper", map[string]any{"type": "file", "uid": 61000, "mode": 0o755, "sha256": goodHelper()["sha256"]}), "must be root's"},
		"another kernel":          {set("kernel", "6.6.87.2-microsoft-standard-WSL2"), "kernel"},
		"another boot":            {set("bootID", "ffffffff-0000-0000-0000-000000000000"), "boot ID"},
		"a windows folder":        {mount("/var/tmp", "605 600 0:65 / /mnt/host rw,relatime - 9p drvfs rw,aname=drvfs;path=C:\\"), "Windows folder"},
		"var tmp not tmpfs":       {mount("/var/tmp", "605 600 0:65 / /var/tmp rw,relatime - overlay overlay rw"), "not tmpfs"},
		"tmp may run programs":    {mount(" /tmp ", "604 600 0:64 / /tmp rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=16384k"), "noexec"},
		"work unbounded":          {mount(" /work ", "606 600 0:66 / /work rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=1777"), "size="},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := goodProbe()
			c.mut(r)
			b, _ := json.Marshal(r)
			s := goodSetup(t)
			s.ProbeStdout = string(b)
			f := newFake(t, s)
			p := f.provider()
			err := p.SmokeTest(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("smoke test: %v, want an error naming %q", err, c.want)
			}
			f.clearCalls()
			_, err = p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			refusal(t, err, sandbox.RefusalEnvironment)
			if len(f.runs()) != 0 {
				t.Fatal("a run started after a failed smoke test")
			}
		})
	}
}

// The image is refused before any container starts when a run could not use it safely.
func TestSmokeTestRefusesTheImage(t *testing.T) {
	image := func(fields map[string]any) json.RawMessage {
		img := map[string]any{"Id": fakeImageID, "Os": "linux", "RepoDigests": []string{"plimsoll/sandbox@sha256:" + strings.Repeat("cd", 32)}, "Config": map[string]any{}}
		for k, v := range fields {
			img[k] = v
		}
		b, _ := json.Marshal([]any{img})
		return b
	}
	for name, c := range map[string]struct {
		images json.RawMessage
		cfg    func(*Config)
		want   string
	}{
		"a volume":        {image(map[string]any{"Config": map[string]any{"Volumes": map[string]any{"/data": map[string]any{}}}}), nil, "VOLUME"},
		"a loader var":    {image(map[string]any{"Config": map[string]any{"Env": []string{"LD_PRELOAD=/work/x.so"}}}), nil, "LD_PRELOAD"},
		"a short id":      {image(map[string]any{"Id": "abc"}), nil, "sha256"},
		"windows image":   {image(map[string]any{"Os": "windows"}), nil, "linux"},
		"two images":      {json.RawMessage(`[{},{}]`), nil, "want 1"},
		"pin not matched": {image(nil), func(c *Config) { c.Image = "plimsoll/sandbox@sha256:" + strings.Repeat("ee", 32) }, "do not include"},
	} {
		t.Run(name, func(t *testing.T) {
			s := goodSetup(t)
			s.Images = c.images
			f := newFake(t, s)
			var muts []func(*Config)
			if c.cfg != nil {
				muts = append(muts, c.cfg)
			}
			p := f.provider(muts...)
			if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("smoke test: %v, want %q", err, c.want)
			}
			if len(f.runs()) != 0 {
				t.Fatal("a container started for a refused image")
			}
		})
	}
}

// A project and a snippet run through the runner, and their results are the report's.
func TestRunProjectAndSnippet(t *testing.T) {
	p, f := ready(t)
	res, err := p.RunProject(context.Background(), sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "a.js", Content: "console.log(1)"}}, Steps: []string{"node a.js", "node a.js --again"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 2 || res.Steps[1].Stdout != "ran: node a.js --again\n" ||
		res.Isolation != sandbox.IsolationContainer || res.Sandbox != Name || res.EnvironmentIdentity != "wslc-image:"+fakeImageID {
		t.Fatalf("project result: %+v", res)
	}
	if len(f.removes()) != 0 {
		t.Fatal("a clean run was force-removed")
	}
	snip, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "console.log(2)"})
	if err != nil {
		t.Fatal(err)
	}
	if snip.Stdout != "ran: "+snippetStep+"\n" || snip.Stderr != "err\n" || snip.ExitCode != 0 || snip.Isolation != sandbox.IsolationContainer {
		t.Fatalf("snippet result: %+v", snip)
	}
	runs := f.runs()
	if !strings.Contains(runs[len(runs)-1].Stdin, `"path":"snippet.js","content":"console.log(2)"`) {
		t.Fatalf("the snippet's plan: %s", runs[len(runs)-1].Stdin)
	}
	s := goodSetup(t)
	s.StepExit = 7
	f.set(s)
	snip, err = p.RunJavaScript(context.Background(), sandbox.Request{Code: "process.exit(7)"})
	if err != nil || snip.ExitCode != 7 {
		t.Fatalf("a snippet exiting 7: %+v, %v", snip, err)
	}
}

// A run with no authenticated report may have run: its error is never marked not
// dispatched, it never carries the container's stderr, and the container is removed by the
// name it was started with.
func TestRunWithoutReport(t *testing.T) {
	for _, mode := range []string{"silent", "fail"} {
		t.Run(mode, func(t *testing.T) {
			p, f := ready(t)
			s := goodSetup(t)
			s.Mode = mode
			f.set(s)
			_, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}})
			if err == nil {
				t.Fatal("no error for a run with no report")
			}
			if _, marked := sandbox.NotDispatchedReason(err); marked {
				t.Fatalf("a run that may have executed is marked not dispatched: %v", err)
			}
			if strings.Contains(err.Error(), "guest-controlled") {
				t.Fatalf("the container's stderr reached the error: %v", err)
			}
			name := f.runs()[0].Argv[slices.Index(f.runs()[0].Argv, "--name")+1]
			if mode == "fail" && !slices.Equal(f.removes(), []string{name}) {
				t.Fatalf("removed %v after a failed run, want %s", f.removes(), name)
			}
		})
	}
}

// A run that outlives its budget plus the start allowance ends as timed out, and its
// container is removed.
func TestRunTimeoutRemovesTheContainer(t *testing.T) {
	p, f := ready(t)
	p.cfg.StartAllowance = 200 * time.Millisecond
	s := goodSetup(t)
	s.Mode = "hang"
	f.set(s)
	start := time.Now()
	res, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}, Timeout: 100 * time.Millisecond})
	if err != nil || res.Outcome != sandbox.ProjectOutcomeTimedOut {
		t.Fatalf("a hung run: %+v, %v", res, err)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatalf("the hung run took %v to give up", time.Since(start))
	}
	if len(f.removes()) == 0 {
		t.Fatal("the hung run's container was not removed")
	}
	snip, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "for(;;);", Timeout: 100 * time.Millisecond})
	if err != nil || !snip.TimedOut {
		t.Fatalf("a hung snippet: %+v, %v", snip, err)
	}
}

// Grants, module runs, sessions and floors above container are refused before anything
// starts.
func TestRefusedBeforeDispatch(t *testing.T) {
	p, f := ready(t)
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Grant: &sandbox.HostAPIGrant{}})
	refusal(t, err, sandbox.RefusalUnsupported)
	_, err = p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}, Grant: &sandbox.HostAPIGrant{}})
	refusal(t, err, sandbox.RefusalUnsupported)
	_, err = p.RunModule(context.Background(), sandbox.ModuleRequest{})
	refusal(t, err, sandbox.RefusalUnsupported)
	_, err = p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationKernel})
	refusal(t, err, sandbox.RefusalIsolation)
	if len(f.runs()) != 0 {
		t.Fatal("a refused call started a container")
	}
	var sb sandbox.Sandbox = p
	if _, ok := sb.(sandbox.SessionProvider); ok {
		t.Fatal("wslc states sessions")
	}
	if p.SupportsJavaScriptGrants() || p.SupportsProjectGrants() || p.SupportsModules() || !p.SupportsProjects() {
		t.Fatal("the stated support is wrong")
	}
	fresh := newFake(t, goodSetup(t)).provider()
	_, err = fresh.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}})
	refusal(t, err, sandbox.RefusalEnvironment)
}

// A wslc.exe that cannot be started ran nothing.
func TestMissingWSLCIsNotDispatched(t *testing.T) {
	p, _ := ready(t)
	p.cfg.Path = filepath.Join(t.TempDir(), "gone.exe")
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	refusal(t, err, sandbox.RefusalEnvironment)
}

func TestFromEnv(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{"SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	prov, err := FromEnv(env())
	if err != nil {
		t.Fatal(err)
	}
	if prov.Resources.MemoryMB != 512 || prov.Resources.CPUs != 1 || prov.Resources.DiskMB != 176 {
		t.Fatalf("resources: %+v", prov.Resources)
	}
	for name, c := range map[string]struct {
		env  func(string) string
		want string
	}{
		"pids":         {env("SANDBOX_PIDS", "64"), "SANDBOX_PIDS"},
		"no image":     {env("SANDBOX_WSLC_IMAGE", ""), "SANDBOX_WSLC_IMAGE is required"},
		"unsafe image": {env("SANDBOX_WSLC_IMAGE", "a b"), "not a plain image reference"},
		"option image": {env("SANDBOX_WSLC_IMAGE", "--privileged"), "not a plain image reference"},
		"unpinned":     {env("SANDBOX_REQUIRE_PINNED_IMAGES", "1"), "name@sha256"},
		"upper-case pin": {func(k string) string {
			return map[string]string{"SANDBOX_REQUIRE_PINNED_IMAGES": "1", "SANDBOX_WSLC_IMAGE": "plimsoll/sandbox" + "@sha256:" + strings.Repeat("AB", 32)}[k]
		}, "lower-case"},
		"nproc":         {env("SANDBOX_WSLC_NPROC", "lots"), "must be an integer"},
		"nproc range":   {env("SANDBOX_WSLC_NPROC", "2"), "between"},
		"small disk":    {env("SANDBOX_DISK_MB", "40"), "SANDBOX_DISK_MB"},
		"relative path": {env("SANDBOX_WSLC_PATH", "wslc.exe"), "absolute"},
		"bad bool":      {env("SANDBOX_REQUIRE_PINNED_IMAGES", "maybe"), "SANDBOX_REQUIRE_PINNED_IMAGES"},
		"tiny memory":   {env("SANDBOX_MEMORY_MB", "16"), "SANDBOX_MEMORY_MB"},
	} {
		if _, err := FromEnv(c.env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// The live suite (live_test.go) runs only on request and fails rather than skips without
// its configuration; this checks the switch reads only its own variable.
func TestSuiteSwitchIsOptIn(t *testing.T) {
	if os.Getenv("WSLC_LIVE") == "1" {
		t.Skip("the live suite is running")
	}
	if liveRequested() {
		t.Fatal("the live suite is on without WSLC_LIVE=1")
	}
}

// --ulimit nproc counts the guest uid's processes across the whole
// session VM, so the shared mode runs one run at a time. Four runs started together never
// overlap in the session (the fake counts containers running at once), and all four finish.
func TestSharedModeRunsOneRunAtATime(t *testing.T) {
	p, f := ready(t)
	setup := goodSetup(t)
	setup.ContainerSleepMs = 150
	f.set(setup)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(f.runs()); got != 4 {
		t.Fatalf("%d container runs, want 4", got)
	}
	if st := f.state(); st.MaxActive != 1 {
		t.Fatalf("%d runs were in the shared session at once, want at most 1", st.MaxActive)
	}
}

// A run that waits for its turn is bounded by its own deadline: when its context ends, or
// its own budget does, before the run ahead of it finishes, it is refused with the
// capacity mark and starts nothing; the run ahead of it is not disturbed, and the next
// run goes ahead once it ends.
func TestSharedModeWaitingRunIsRefusedWithTheMark(t *testing.T) {
	p, f := ready(t)
	setup := goodSetup(t)
	setup.ContainerSleepMs = 1500
	f.set(setup)
	first := make(chan error, 1)
	go func() {
		_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
		first <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for f.state().Active != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the first run never started its container")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"})
	refusal(t, err, sandbox.RefusalCapacity)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("the wait was not bounded by the caller's deadline (%v after %v)", err, time.Since(start))
	}
	// Its own budget bounds the wait too, when the caller's context has none.
	_, err = p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}, Timeout: 100 * time.Millisecond})
	refusal(t, err, sandbox.RefusalCapacity)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if got := len(f.runs()); got != 1 {
		t.Fatalf("a refused run started a container: %d container runs", got)
	}
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatalf("the run after the first one ended: %v", err)
	}
}
