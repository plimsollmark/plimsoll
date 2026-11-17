package wslc

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// gVisor inside each run's VM (gvisor.go). The stand-in answers the scripts the provider
// sends to `sh` in a session VM by the kind on their first line, and keeps each session's
// gvisor directory beside its disk, so the template carries it into every copy. Like every
// test here it shares any misreading of how WSLC and dockerd behave; the live tests in
// live_gvisor_test.go are what ran on the real thing.

// gvisorKit is a stand-in runsc and one helper on disk, and their digests.
type gvisorKit struct {
	runsc    string
	runscSum string
	helpers  map[string]string
}

func sum512(b []byte) string {
	h := sha512.Sum512(b)
	return hex.EncodeToString(h[:])
}

func newGVisorKit(t *testing.T) gvisorKit {
	t.Helper()
	dir := t.TempDir()
	runsc := []byte("runsc stand-in bytes")
	helper := []byte("sentry stand-in bytes")
	if err := os.MkdirAll(filepath.Join(dir, helperDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runsc"), runsc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, helperDir, "gvisor_sentry"), helper, 0o755); err != nil {
		t.Fatal(err)
	}
	return gvisorKit{runsc: filepath.Join(dir, "runsc"), runscSum: sum512(runsc), helpers: map[string]string{"gvisor_sentry": sum512(helper)}}
}

// on configures gVisor in the per-run mode.
func (k gvisorKit) on(c *Config) {
	c.Mode, c.GVisor, c.RunscPath, c.RunscSHA512, c.RunscHelpers = ModePerRun, true, k.runsc, k.runscSum, k.helpers
}

// gvisorReportFor is the report the boundary test gives from inside a container under gVisor: the
// readings a trial of gVisor found different (Seccomp 0, no memory.max, gVisor's kernel string and
// its own boot ID) and a mount table as gVisor serves it (a 9p root and resolver file, no
// nodev on a tmpfs).
func gvisorReportFor(cfg Config) map[string]any {
	m := goodProbeFor(cfg)
	st := m["status"].(map[string]string)
	st["Seccomp"], st["Seccomp_filters"] = "0", "0"
	m["kernel"] = "4.19.0-gvisor"
	m["procVersion"] = "Linux version 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016"
	m["bootID"] = "eb9a4de6-96d7-43bc-b4ff-0769dc41ac7b"
	m["memoryMax"] = ""
	m["mountinfo"] = []string{
		"600 500 0:60 / / rw,relatime - 9p none rw,trans=fd",
		"601 600 0:61 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw",
		"602 600 0:62 / /dev rw,nosuid - tmpfs tmpfs rw,mode=755",
		"603 602 0:63 / /dev/shm rw,nosuid,noexec - tmpfs none rw,size=16384k,mode=1777",
		"604 600 0:64 / /tmp rw,nosuid,noexec - tmpfs none rw,size=16384k,mode=1777",
		"605 600 0:65 / /var/tmp rw,nosuid,noexec - tmpfs none rw,size=16384k,mode=1777",
		"606 600 0:66 / /work rw,nosuid,noexec - tmpfs none rw,size=" + strconv.Itoa(cfg.workMB()*1024) + "k,mode=1777",
		"607 600 0:60 /etc/resolv.conf /etc/resolv.conf rw,relatime - 9p none rw,trans=fd",
	}
	return m
}

// gvisorSetup is a fake that passes every check of a gVisor provider configured as cfg.
func gvisorSetup(t *testing.T, cfg Config) fakeSetup {
	t.Helper()
	cfg.Mode = ModePerRun
	s := goodSetupFor(t, cfg)
	report, err := json.Marshal(gvisorReportFor(cfg))
	if err != nil {
		t.Fatal(err)
	}
	s.ProbeStdout, s.KeepReportBootID = string(report), true
	return s
}

// gvisorProvider is a gVisor provider on a good fake (after setup's changes), not started.
func gvisorProvider(t *testing.T, setup func(*fakeSetup), mut ...func(*Config)) (*Provider, *fake, gvisorKit) {
	t.Helper()
	kit := newGVisorKit(t)
	var cfg Config
	kit.on(&cfg)
	s := gvisorSetup(t, cfg)
	if setup != nil {
		setup(&s)
	}
	f := newFake(t, s)
	return f.provider(append([]func(*Config){kit.on}, mut...)...), f, kit
}

// readyGVisor is a gVisor provider whose smoke test has passed, with the calls so far
// cleared.
func readyGVisor(t *testing.T, setup func(*fakeSetup), mut ...func(*Config)) (*Provider, *fake, gvisorKit) {
	t.Helper()
	p, f, kit := gvisorProvider(t, setup, mut...)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatalf("gVisor smoke test on a good fake: %v", err)
	}
	p.drain()
	f.clearCalls()
	return p, f, kit
}

// newRunRuntimes is the default runtime at each `container run` since before was read
// (sessions that had no run then).
func (f *fake) newRunRuntimes(before map[string][]string) map[string][]string {
	out := map[string][]string{}
	for s, rt := range f.state().RunRuntimes {
		if _, old := before[s]; !old {
			out[s] = rt
		}
	}
	return out
}

// scriptCalls are the recorded `system session run sh` calls whose script is of kind.
func (f *fake) scriptCalls(kind string) []fakeCall {
	var out []fakeCall
	for _, c := range f.calls() {
		if c.Prog == "wslc.exe" && strings.HasSuffix(strings.Join(c.Argv, " "), "system session run sh") && strings.HasPrefix(c.Stdin, "# plimsoll-script: "+kind+"\n") {
			out = append(out, c)
		}
	}
	return out
}

func TestGVisorConfigRefusals(t *testing.T) {
	kit := newGVisorKit(t)
	for name, c := range map[string]struct {
		mut  func(*Config)
		want string
	}{
		"no path":          {func(c *Config) { kit.on(c); c.RunscPath = "" }, "needs SANDBOX_WSLC_RUNSC_PATH"},
		"path, no digest":  {func(c *Config) { kit.on(c); c.RunscSHA512 = "" }, "needs SANDBOX_WSLC_RUNSC_SHA512"},
		"short digest":     {func(c *Config) { kit.on(c); c.RunscSHA512 = c.RunscSHA512[:100] }, "128 lowercase hex"},
		"upper digest":     {func(c *Config) { kit.on(c); c.RunscSHA512 = strings.ToUpper(c.RunscSHA512) }, "128 lowercase hex"},
		"relative path":    {func(c *Config) { kit.on(c); c.RunscPath = "bin/runsc" }, "clean absolute"},
		"unclean path":     {func(c *Config) { kit.on(c); c.RunscPath = "/usr/../bin/runsc" }, "clean absolute"},
		"helper traversal": {func(c *Config) { kit.on(c); c.RunscHelpers = map[string]string{"../x": kit.runscSum} }, "plain file name"},
		"helper digest":    {func(c *Config) { kit.on(c); c.RunscHelpers = map[string]string{"x": "abc"} }, "128 lowercase hex"},
		"settings, no on":  {func(c *Config) { kit.on(c); c.GVisor = false }, "need SANDBOX_WSLC_GVISOR=1"},
		"shared mode":      {func(c *Config) { kit.on(c); c.Mode = ModeShared }, "per-run only"},
		"shared mode bare": {func(c *Config) { c.Mode, c.GVisor = ModeShared, true }, "per-run only"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{Image: "plimsoll/sandbox:latest"}
			c.mut(&cfg)
			if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("New: %v, want %q", err, c.want)
			}
		})
	}
	// The same settings, right, build.
	cfg := Config{Image: "plimsoll/sandbox:latest"}
	kit.on(&cfg)
	if _, err := New(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestGVisorFromEnv(t *testing.T) {
	kit := newGVisorKit(t)
	env := func(kv ...string) func(string) string {
		m := map[string]string{"SANDBOX_WSLC_IMAGE": "plimsoll/sandbox:latest", "SANDBOX_WSLC_MODE": "per-run", "SANDBOX_WSLC_GVISOR": "1",
			"SANDBOX_WSLC_RUNSC_PATH": kit.runsc, "SANDBOX_WSLC_RUNSC_SHA512": kit.runscSum,
			"SANDBOX_WSLC_RUNSC_HELPERS": "gvisor_sentry=" + kit.helpers["gvisor_sentry"] + ", other=" + kit.runscSum}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	prov, err := FromEnv(env())
	if err != nil {
		t.Fatal(err)
	}
	p := prov.Sandbox.(*Provider)
	if !p.GVisor() || p.cfg.RunscPath != kit.runsc || len(p.cfg.RunscHelpers) != 2 || p.IsolationClass() != sandbox.IsolationContainer {
		t.Fatalf("config: %+v", p.cfg)
	}
	for name, c := range map[string]struct {
		env  func(string) string
		want string
	}{
		"not a boolean":   {env("SANDBOX_WSLC_GVISOR", "yes"), "SANDBOX_WSLC_GVISOR"},
		"pair no digest":  {env("SANDBOX_WSLC_RUNSC_HELPERS", "gvisor_sentry"), "not NAME=SHA512"},
		"pair empty":      {env("SANDBOX_WSLC_RUNSC_HELPERS", "x="), "not NAME=SHA512"},
		"name twice":      {env("SANDBOX_WSLC_RUNSC_HELPERS", "x="+kit.runscSum+",x="+kit.runscSum), "twice"},
		"shared mode":     {env("SANDBOX_WSLC_MODE", "shared"), "per-run only"},
		"no digest":       {env("SANDBOX_WSLC_RUNSC_SHA512", ""), "needs SANDBOX_WSLC_RUNSC_SHA512"},
		"digest, not set": {env("SANDBOX_WSLC_GVISOR", ""), "need SANDBOX_WSLC_GVISOR=1"},
	} {
		if _, err := FromEnv(c.env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// The template carries runsc and its helpers, streamed on the standard input of
// `wslc system session run tar`; the settings and the proof scripts travel on the standard
// input of `sh`; every argument is interop-safe; the digests are read back from the store;
// the evidence names the runtime, the runsc version and digest and the platform; the tier
// is unchanged (container, without SANDBOX_WSLC_ACCEPT_VM_TIER=1), stated with gVisor's
// position added.
func TestGVisorSmokeTestStatesGVisor(t *testing.T) {
	p, f, kit := gvisorProvider(t, nil)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.drain()
	if p.IsolationClass() != sandbox.IsolationContainer {
		t.Fatalf("tier %v", p.IsolationClass())
	}
	ev, ok := p.Evidence()
	g := ev.GVisor
	if !ok || g == nil || g.Runtime != "runsc" || g.RunscVersion != "runsc version release-20260907.0" || g.RunscSHA512 != kit.runscSum ||
		g.Platform != "systrap" || g.SentrySeccomp != "2" || g.Helpers["gvisor_sentry"] != kit.helpers["gvisor_sentry"] || len(ev.RunSessions) != 2 {
		t.Fatalf("evidence: %+v %+v", ev, g)
	}
	// The kernel and boot ID the evidence states are the session VM's, not gVisor's.
	if ev.KernelRelease != fakeKernel || ev.Seccomp != "0" {
		t.Fatalf("evidence: kernel %q seccomp %q", ev.KernelRelease, ev.Seccomp)
	}
	if q := p.Qualification(); !strings.HasPrefix(q, PerRunQualification) || !strings.HasSuffix(q, GVisorQualification) {
		t.Fatalf("qualification %q", q)
	}
	var mkdirs, tars int
	var registers, runsOf = map[string]int{}, map[string]int{}
	for i, c := range f.calls() {
		if err := checkArgs(c.Argv); err != nil {
			t.Fatalf("%s %v: %v", c.Prog, c.Argv, err)
		}
		if len(c.Env) != 1 || !strings.HasPrefix(c.Env[0], "PATH=") {
			t.Fatalf("%s started with environment %q", c.Prog, c.Env)
		}
		joined := strings.Join(c.Argv, " ")
		if strings.Contains(joined, "default-runtime") || strings.Contains(joined, "daemon.json") || strings.Contains(c.Script, "daemon.json") {
			t.Fatalf("the docker settings travel in an argument: %v", c.Argv)
		}
		switch {
		case strings.HasSuffix(joined, "system session run mkdir -p "+vmGVisorDir+"/"+helperDir):
			mkdirs++
		case strings.HasSuffix(joined, "system session run tar -xzf - -C "+vmGVisorDir):
			tars++
			if c.Stdin != "tar: gvisor-bin/gvisor_sentry,runsc" {
				t.Fatalf("the archive held %q", c.Stdin)
			}
		case strings.HasSuffix(joined, "system session run sh") && strings.HasPrefix(c.Stdin, scriptKind("register-runsc")):
			registers[c.Session] = i
			if !strings.Contains(c.Stdin, gvisorDaemonJSON) || !strings.Contains(c.Stdin, "kill -HUP") {
				t.Fatalf("the registration script: %s", c.Stdin)
			}
		}
	}
	for _, c := range f.runs() {
		runsOf[c.Session]++
	}
	if mkdirs != 1 || tars != 1 {
		t.Fatalf("the template build made %d directories and sent %d archives, want one each", mkdirs, tars)
	}
	// Each of the two smoke sessions registered gVisor before its container ran.
	if len(registers) != 2 || len(runsOf) != 2 {
		t.Fatalf("registrations %v, runs %v", registers, runsOf)
	}
	for session := range runsOf {
		reg, ok := registers[session]
		if !ok {
			t.Fatalf("session %s ran a container without registering gVisor", session)
		}
		for i, c := range f.calls() {
			if c.Session == session && len(c.Argv) >= 4 && c.Argv[2] == "container" && c.Argv[3] == "run" && i < reg {
				t.Fatalf("session %s ran its container before the registration", session)
			}
		}
	}
	for _, rt := range f.state().RunRuntimes {
		if !slices.Equal(rt, []string{"runsc"}) {
			t.Fatalf("a smoke container ran under %v", rt)
		}
	}
	if left := leftovers(t, p, f); len(left) != 0 {
		t.Fatalf("left: %v", left)
	}
}

// Every run registers gVisor in its own VM and starts only under runsc, and its result
// carries that gVisor was proven on for it: the Policy, which the run's record names.
func TestGVisorRunsAreProvenAndCarryThePolicy(t *testing.T) {
	p, f, _ := readyGVisor(t, nil)
	before := f.state().RunRuntimes
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationContainer})
	if err != nil || res.Policy != PolicyGVisor || res.Isolation != sandbox.IsolationContainer || res.ExitCode != 0 {
		t.Fatalf("snippet: %+v %v", res, err)
	}
	pr, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}})
	if err != nil || pr.Policy != PolicyGVisor || pr.Outcome != sandbox.ProjectOutcomeCompleted {
		t.Fatalf("project: %+v %v", pr, err)
	}
	p.drain()
	if n := len(f.scriptCalls("register-runsc")); n != 2 {
		t.Fatalf("%d registrations for two runs", n)
	}
	rt := f.newRunRuntimes(before)
	if len(rt) != 2 {
		t.Fatalf("runs in %d sessions: %v", len(rt), rt)
	}
	for s, r := range rt {
		if !slices.Equal(r, []string{"runsc"}) {
			t.Fatalf("session %s ran under %v", s, r)
		}
	}
	// Without the setting a run's result states no policy and nothing is registered.
	q, g := readyPerRun(t, nil)
	res, err = q.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if err != nil || res.Policy != "" {
		t.Fatalf("without gVisor: %+v %v", res, err)
	}
	q.drain()
	if len(g.scriptCalls("register-runsc")) != 0 || q.Qualification() != PerRunQualification {
		t.Fatal("the setting off changed the per-run mode")
	}
}

// A runsc whose bytes are not the configured ones is never sent: the startup check refuses
// before the first byte, and a helper named but not on disk fails Preflight.
func TestGVisorRefusesFilesThatAreNotThePinnedOnes(t *testing.T) {
	flip := func(sum string) string {
		if sum[0] == '0' {
			return "1" + sum[1:]
		}
		return "0" + sum[1:]
	}
	for name, mut := range map[string]func(*Config, gvisorKit){
		"runsc": func(c *Config, k gvisorKit) { c.RunscSHA512 = flip(k.runscSum) },
		"helper": func(c *Config, k gvisorKit) {
			c.RunscHelpers = map[string]string{"gvisor_sentry": flip(k.helpers["gvisor_sentry"])}
		},
	} {
		t.Run("wrong digest of "+name, func(t *testing.T) {
			var kit gvisorKit
			p, f, _ := gvisorProvider(t, nil, func(c *Config) { kit = newGVisorKit(t); kit.on(c); mut(c, kit) })
			err := p.SmokeTest(context.Background())
			if err == nil || !strings.Contains(err.Error(), "SHA-512") || !strings.Contains(err.Error(), "refusing to put it on the template") {
				t.Fatalf("smoke test: %v", err)
			}
			for _, c := range f.calls() {
				if strings.Contains(strings.Join(c.Argv, " "), "tar -xzf") {
					t.Fatal("an archive was sent for a file that failed its digest")
				}
			}
			if _, ok := p.Evidence(); ok {
				t.Fatal("evidence after a failed smoke test")
			}
			if _, err := os.Stat(filepath.Join(f.runRoot(), templateDirName)); err == nil {
				t.Fatal("a template was left")
			}
		})
	}
	t.Run("missing helper", func(t *testing.T) {
		p, _, _ := gvisorProvider(t, nil, func(c *Config) {
			c.RunscHelpers = map[string]string{"gvisor_sentry": strings.Repeat("a", 128), "checkpointgofer": strings.Repeat("b", 128)}
		})
		if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "checkpointgofer") {
			t.Fatalf("Preflight: %v", err)
		}
		if err := p.SmokeTest(context.Background()); err == nil {
			t.Fatal("the smoke test passed with a helper missing")
		}
	})
}

// The template check reads each file's SHA-512 from the store: a copy that arrived
// different, an extra file in the directory, and an extraction that failed each refuse the
// template, and nothing is left.
func TestGVisorTemplateCheckReadsTheStore(t *testing.T) {
	for name, c := range map[string]struct {
		set  func(*fakeSetup)
		want string
	}{
		"runsc differs in the store":  {func(s *fakeSetup) { s.StoreCorrupt = "runsc" }, "SHA-512"},
		"helper differs in the store": {func(s *fakeSetup) { s.StoreCorrupt = "gvisor-bin/gvisor_sentry" }, "SHA-512"},
		"extra file":                  {func(s *fakeSetup) { s.ExtraStoreFile = true }, "holds files"},
		"extraction fails":            {func(s *fakeSetup) { s.ExtractFails = true }, "sending gVisor"},
		"runsc will not run":          {func(s *fakeSetup) { s.RunscVersion = "garbage" }, "--version"},
	} {
		t.Run(name, func(t *testing.T) {
			p, f, _ := gvisorProvider(t, c.set)
			err := p.SmokeTest(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("smoke test: %v, want %q", err, c.want)
			}
			p.drain()
			if _, err := os.Stat(filepath.Join(f.runRoot(), templateDirName)); err == nil {
				t.Fatal("a template was left")
			}
			if left := leftovers(t, p, f); len(left) != 0 {
				t.Fatalf("left: %v", left)
			}
		})
	}
}

// A template built without gVisor is not trusted when the setting is on: the next startup
// builds it anew, with runsc, and the store check passes only then.
func TestGVisorStaleTemplateIsRebuilt(t *testing.T) {
	kit := newGVisorKit(t)
	var cfg Config
	kit.on(&cfg)
	f := newFake(t, gvisorSetup(t, cfg))
	plain := f.provider(perRun)
	// Its boundary test's report is gVisor's, which a runc provider refuses: the template is built before
	// the test runs, so a template without runsc is there either way.
	_ = plain.SmokeTest(context.Background())
	plain.drain()
	if _, err := os.Stat(filepath.Join(f.runRoot(), templateDirName, storageFile+".gvisor")); err == nil {
		t.Fatal("the plain provider's template holds gVisor")
	}
	f.clearCalls()
	p := f.provider(kit.on)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.drain()
	var sent bool
	for _, c := range f.calls() {
		sent = sent || strings.Contains(strings.Join(c.Argv, " "), "tar -xzf")
	}
	if _, err := os.Stat(filepath.Join(f.runRoot(), templateDirName, storageFile+".gvisor")); err != nil || !sent {
		t.Fatalf("the template was not rebuilt with gVisor (sent %v, %v)", sent, err)
	}
}

// No fallback to runc anywhere: when the VM reads runc after the settings were written and
// dockerd reloaded, the run is refused before `container run` is called, marked not
// dispatched with reason environment.
func TestGVisorReloadThatLeavesRuncRefusesTheRun(t *testing.T) {
	p, f, _ := readyGVisor(t, nil)
	before := f.state().RunRuntimes
	s := gvisorSetup(t, p.cfg)
	s.ReloadRuntime = "runc"
	f.set(s)
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	refusal(t, err, sandbox.RefusalEnvironment)
	if !strings.Contains(err.Error(), `reads default runtime "runc"`) || !strings.Contains(err.Error(), "never started under runc") {
		t.Fatalf("error: %v", err)
	}
	if res.Policy != "" {
		t.Fatalf("a refused run states a policy: %+v", res)
	}
	if len(f.runs()) != 0 {
		t.Fatalf("container run was called %d times", len(f.runs()))
	}
	if rt := f.newRunRuntimes(before); len(rt) != 0 {
		t.Fatalf("a container ran: %v", rt)
	}
	if left := leftovers(t, p, f); len(left) != 0 {
		t.Fatalf("left: %v", left)
	}
	// And the same for a project, and for a snippet after the daemon recovers: the refusal
	// is per run, not a state.
	_, err = p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}})
	refusal(t, err, sandbox.RefusalEnvironment)
	f.set(gvisorSetup(t, p.cfg))
	if res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil || res.Policy != PolicyGVisor {
		t.Fatalf("after recovery: %+v %v", res, err)
	}
}

// A boot that reset the settings and a session nobody rewrote are the same case: the VM
// reads runc, so the run is refused. The settings a VM boots with that this provider has not
// seen are refused too, rather than overwritten.
func TestGVisorSettingsThatWereNotRewrittenRefuseTheRun(t *testing.T) {
	t.Run("not rewritten", func(t *testing.T) {
		p, f, _ := readyGVisor(t, nil)
		p.pr.mu.Lock()
		p.pr.skipGVisorWrite = true
		p.pr.mu.Unlock()
		_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
		refusal(t, err, sandbox.RefusalEnvironment)
		if !strings.Contains(err.Error(), `"runc"`) || len(f.runs()) != 0 {
			t.Fatalf("error %v, %d runs", err, len(f.runs()))
		}
		for _, c := range f.scriptCalls("register-runsc") {
			if strings.Contains(c.Stdin, "kill -HUP") {
				t.Fatal("the read-only script wrote")
			}
		}
	})
	t.Run("unseen settings", func(t *testing.T) {
		p, f, _ := readyGVisor(t, nil)
		s := gvisorSetup(t, p.cfg)
		s.DaemonJSON = `{"features":{"cdi":true},"debug":true}`
		f.set(s)
		_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
		refusal(t, err, sandbox.RefusalEnvironment)
		if len(f.runs()) != 0 {
			t.Fatal("a container started")
		}
	})
}

// A VM whose runsc is not in its store (a template built without it, copied) reloads to
// nothing: the default stays runc, and the run is refused.
func TestGVisorMissingRunscInTheVMRefusesTheRun(t *testing.T) {
	p, f, _ := readyGVisor(t, nil)
	// A template without gVisor: the same template directory with the file list emptied.
	if err := os.Remove(filepath.Join(f.runRoot(), templateDirName, storageFile+".gvisor")); err != nil {
		t.Fatal(err)
	}
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	refusal(t, err, sandbox.RefusalEnvironment)
	if len(f.runs()) != 0 {
		t.Fatal("a container started")
	}
}

// Each reading gVisor answers differently is replaced by one that still proves the property,
// and each replacement fails when its property does not hold.
func TestGVisorSmokeReadingsEachRefuse(t *testing.T) {
	editReport := func(edit func(m map[string]any)) func(*fakeSetup) {
		return func(s *fakeSetup) {
			var m map[string]any
			if err := json.Unmarshal([]byte(s.ProbeStdout), &m); err != nil {
				t.Fatal(err)
			}
			edit(m)
			b, _ := json.Marshal(m)
			s.ProbeStdout = string(b)
		}
	}
	for name, c := range map[string]struct {
		set  func(*fakeSetup)
		want string
	}{
		"the Sentry has no filter":          {func(s *fakeSetup) { s.SentrySeccomp = "0" }, "not under its own system-call filter"},
		"the guest's filter line is odd":    {editReport(func(m map[string]any) { m["status"].(map[string]any)["Seccomp"] = "1" }), "Seccomp line"},
		"the memory limit is not on cgroup": {func(s *fakeSetup) { s.VMMemoryMax = "1073741824" }, "memory.max"},
		"the memory limit is unreadable":    {func(s *fakeSetup) { s.VMMemoryMax = "max" }, "memory.max"},
		"the container is under runc":       {func(s *fakeSetup) { s.ContainerRuntime = "runc" }, `not runsc`},
		"the kernel string is not gVisor's": {editReport(func(m map[string]any) { m["kernel"] = fakeKernel }), "not gVisor's"},
		"/proc/version names no gVisor":     {editReport(func(m map[string]any) { m["procVersion"] = "Linux version 6.18.58.1-microsoft-standard-WSL2" }), "does not name gVisor"},
		"the boot ID is the VM's":           {func(s *fakeSetup) { s.KeepReportBootID = false }, "boot ID of its own"},
		"the boot ID is garbage":            {editReport(func(m map[string]any) { m["bootID"] = "x" }), "boot ID of its own"},
		"the container is not in the VM":    {func(s *fakeSetup) { s.ProveFails = true }, "from the VM's side"},
		"no runsc-sandbox process":          {func(s *fakeSetup) { s.NoSentry = true }, "no runsc-sandbox process"},
		"another platform":                  {func(s *fakeSetup) { s.Platform = "kvm" }, "platform"},
		"a mount handed to the container":   {func(s *fakeSetup) { s.ContainerMounts = "1" }, "no Windows folder"},
		"a Windows folder in the table": {editReport(func(m map[string]any) {
			m["mountinfo"] = append(m["mountinfo"].([]any), "608 600 0:70 / /mnt/c rw - virtiofs drvfs rw")
		}), "reached the container"},
		"a 9p mount that is not gofer's": {editReport(func(m map[string]any) {
			m["mountinfo"] = append(m["mountinfo"].([]any), "608 600 0:71 / /data rw - 9p none rw")
		}), "reached the container"},
		"a tmpfs that is not bounded": {editReport(func(m map[string]any) {
			m["mountinfo"].([]any)[4] = "604 600 0:64 / /tmp rw,nosuid,noexec - tmpfs none rw,mode=1777"
		}), "bound is not verifiably in force"},
		"a tmpfs that can run programs": {editReport(func(m map[string]any) {
			m["mountinfo"].([]any)[4] = "604 600 0:64 / /tmp rw,nosuid - tmpfs none rw,size=16384k,mode=1777"
		}), "lack noexec"},
	} {
		t.Run(name, func(t *testing.T) {
			p, f, _ := gvisorProvider(t, c.set)
			err := p.SmokeTest(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("smoke test: %v, want %q", err, c.want)
			}
			if _, ok := p.Evidence(); ok {
				t.Fatal("evidence after a refused smoke test")
			}
			p.drain()
			if left := leftovers(t, p, f); len(left) != 0 {
				t.Fatalf("left: %v", left)
			}
		})
	}
}

// Without the setting none of the gVisor allowances exist: the same container under runc
// reading Seccomp 0 and a kernel that is not the VM's is refused as before.
func TestGVisorReadingsAreRefusedWithoutTheSetting(t *testing.T) {
	var cfg Config
	newGVisorKit(t).on(&cfg)
	f := newFake(t, gvisorSetup(t, cfg))
	p := f.provider(perRun)
	err := p.SmokeTest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Seccomp") {
		t.Fatalf("a gVisor-looking container under a provider without the setting: %v", err)
	}
	if len(f.scriptCalls("register-runsc")) != 0 || len(f.scriptCalls("prove-container")) != 0 {
		t.Fatal("gVisor scripts ran with the setting off")
	}
}

// The mount table allowances under gVisor are the three named, and only under it.
func TestCheckMountsGVisorAllowances(t *testing.T) {
	cfg := Config{}
	cfg.withDefaults()
	base := func() []string {
		return []string{
			"603 602 0:63 / /dev/shm rw,nosuid,noexec - tmpfs none rw,size=16384k,mode=1777",
			"604 600 0:64 / /tmp rw,nosuid,noexec - tmpfs none rw,size=16384k,mode=1777",
			"605 600 0:65 / /var/tmp rw,nosuid,noexec,size=16384k - tmpfs none rw",
			"606 600 0:66 / /work rw,nosuid,noexec - tmpfs none rw,size=" + strconv.Itoa(cfg.workMB()*1024) + "k,mode=1777",
			"600 500 0:60 / / rw - 9p none rw",
			"607 600 0:60 /etc/hosts /etc/hosts rw - 9p none rw",
		}
	}
	if err := checkMounts(base(), cfg, true); err != nil {
		t.Fatalf("gVisor's table: %v", err)
	}
	if err := checkMounts(base(), cfg, false); err == nil {
		t.Fatal("the same table passed without gVisor")
	}
	for _, bad := range []string{
		"608 600 0:70 /x /x rw - 9p none rw",
		"608 600 0:70 / /mnt/c rw - virtiofs drvfs rw",
		"608 600 0:70 / /mnt/c rw - drvfs C:\\ rw",
		"608 600 0:70 / /m rw - fuse.sshfs x rw",
	} {
		if err := checkMounts(append(base(), bad), cfg, true); err == nil {
			t.Fatalf("under gVisor %q passed", bad)
		}
	}
}

// The archive the template carries is gzipped tar under fixed names, owned by root,
// executable, with the helper directory first.
func TestGVisorArchiveLayout(t *testing.T) {
	kit := newGVisorKit(t)
	var cfg Config
	kit.on(&cfg)
	p := &Provider{cfg: cfg}
	files, err := p.openGVisorFiles()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := writeGVisorArchive(&buf, files); err != nil {
		t.Fatal(err)
	}
	for _, o := range files {
		o.f.Close()
	}
	gz, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Mode != 0o755 || strings.HasPrefix(h.Name, "/") || strings.Contains(h.Name, "..") {
			t.Fatalf("entry %+v", h)
		}
		names = append(names, h.Name)
	}
	if !slices.Equal(names, []string{"gvisor-bin/", "runsc", "gvisor-bin/gvisor_sentry"}) {
		t.Fatalf("entries %q", names)
	}
}

// The scripts and the archive are the only text that reaches the VM besides fixed words, and
// the one name a script holds is a run container's: anything else is refused before it is
// built.
func TestGVisorScriptsHoldOnlyCheckedNames(t *testing.T) {
	if _, err := proveScript("x; reboot"); err == nil {
		t.Fatal("a script was built around a name that is not a run container's")
	}
	if s, err := proveScript(containerName()); err != nil || !strings.HasPrefix(s, scriptKind("prove-container")) {
		t.Fatalf("%q %v", s, err)
	}
	for _, write := range []bool{true, false} {
		s := registerScript(write)
		if strings.Contains(s, "kill -HUP") != write || !strings.Contains(s, "docker info") {
			t.Fatalf("registerScript(%v):\n%s", write, s)
		}
	}
	if gvisorDaemonJSON != `{"features":{"cdi":true},"runtimes":{"runsc":{"path":"/var/lib/docker/gvisor/runsc"}},"default-runtime":"runsc"}` {
		t.Fatalf("the settings changed: %s", gvisorDaemonJSON)
	}
}
