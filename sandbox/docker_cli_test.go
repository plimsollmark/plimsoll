package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The docker CLI gets PATH and nothing else, and an empty client config this process
// owns: no variable of the daemon (a caller token, a provider key) reaches it, so
// none can reach a container through it (docker_cli.go).
func TestDockerCommandGetsNoDaemonEnvironment(t *testing.T) {
	t.Setenv("PLIMSOLL_TOKEN", "canary-daemon-secret")
	t.Setenv("DOCKER_HOST", "tcp://elsewhere.example:2375")
	t.Setenv("HTTP_PROXY", "http://user:canary@proxy.example:3128")
	cmd := dockerCommand(context.Background(), "ps")
	if cmd.Err != nil {
		t.Fatal(cmd.Err)
	}
	if !slices.Equal(cmd.Env, []string{"PATH=" + os.Getenv("PATH")}) {
		t.Fatalf("the CLI's environment is %q; want PATH alone", cmd.Env)
	}
	if len(cmd.Args) < 4 || cmd.Args[1] != "--config" || cmd.Args[3] != "ps" {
		t.Fatalf("args %q; want --config <dir> first", cmd.Args)
	}
	// Nothing docker reads: the one entry is the liveness socket the reaper checks
	// (docker_hostdirs.go), and it is a socket, not a file a setting could be in.
	entries, err := os.ReadDir(cmd.Args[2])
	if err != nil || len(entries) != 1 || entries[0].Name() != dockerAliveSocket || entries[0].Type()&fs.ModeSocket == 0 {
		t.Fatalf("the client config directory %s: %v, %v; want only the liveness socket %s", cmd.Args[2], entries, err, dockerAliveSocket)
	}
	if fi, err := os.Stat(cmd.Args[2]); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the client config directory's mode: %v, %v; want 0700", fi, err)
	}
	for _, kv := range dockerResolveCommand(context.Background(), "context", "inspect").Env {
		if strings.Contains(kv, "canary") {
			t.Fatalf("the context resolution got %q", kv)
		}
	}
}

// An -e flag is always NAME=value with a valid name, and plimsoll's own programs in a
// sandbox start from an empty environment.
func TestDockerEnvFlagsAndControlArgv(t *testing.T) {
	if f, err := dockerEnvFlag("HOST_API_SOCKET", "/run/x.sock"); err != nil || !slices.Equal(f, []string{"-e", "HOST_API_SOCKET=/run/x.sock"}) {
		t.Fatalf("dockerEnvFlag: %q, %v", f, err)
	}
	for _, bad := range []string{"", "1A", "A B", "A=B", "A;rm"} {
		if _, err := dockerEnvFlag(bad, "v"); err == nil {
			t.Errorf("dockerEnvFlag accepted the name %q", bad)
		}
	}
	if _, err := dockerEnvFlagPair("PLIMSOLL_TOKEN"); err == nil {
		t.Error("a pair with no value was accepted; the CLI would copy its own variable")
	}
}

// Any image environment of NAME=value entries is handed on as it is, code-loading
// variables included (they reach guest processes alone, review F5), and any name
// docker accepts: every entry follows a PATH= operand, after which env reads NAME=value
// as an assignment. An entry without "=" or with an empty name is refused.
func TestCheckEnvEntries(t *testing.T) {
	for _, ok := range [][]string{
		{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "NODE_VERSION=22.23.3", "YARN_VERSION=1.22.22"},
		{"PATH=/opt/wasi-sdk/bin:/usr/bin:/bin", "OPENBLAS_NUM_THREADS=1", "OMP_NUM_THREADS=1"},
		{"NODE_OPTIONS=--require /work/hook.js", "BASH_ENV=/work/x", "NODE_DEBUG=esm", "PATH=/work:/usr/bin", "EMPTY="},
		{"spring.profiles.active=dev", "my-var=1", "-x=1", "A B=1", "1A=2"},
		nil,
	} {
		if err := checkEnvEntries(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"NOVALUE", "=x"} {
		if err := checkEnvEntries([]string{"PATH=/usr/bin", bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// The variables the C library and dynamic loader read while a program starts reach
// plimsoll's first process in every container before env -i can clear them, so an
// image setting one is refused; names that only look alike are not.
func TestCheckLoaderEnv(t *testing.T) {
	for _, bad := range []string{"LD_PRELOAD=/usr/lib/x.so", "LD_LIBRARY_PATH=/opt/lib", "LD_DEBUG=all", "LD_TRACE_LOADED_OBJECTS=1",
		"LD_AUDIT=/x.so", "GLIBC_TUNABLES=glibc.malloc.check=3", "LOCPATH=/work/l", "NLSPATH=/work/%N", "GCONV_PATH=/work/g"} {
		if err := checkLoaderEnv([]string{"PATH=/usr/bin", bad}); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if err := checkLoaderEnv([]string{"LD=ld.lld", "LDFLAGS=-L/opt/lib", "NODE_OPTIONS=--require /work/x.js", "LANG=C.UTF-8", "TZ=UTC"}); err != nil {
		t.Errorf("refused: %v", err)
	}
}

// guestArgv, run as it is on this host, starts its command with exactly the
// environment docker gives a process plus the entries it was handed: nothing of the
// environment it was itself started with, which in a sandbox is the image's (review
// F5). Its marker leads stderr, written before the command exists.
func TestGuestArgvStartsWithOnlyTheHandedEnvironment(t *testing.T) {
	for _, p := range []string{"/usr/bin/env", "/bin/sh", "/etc/passwd", "/etc/hostname"} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("this host has no %s", p)
		}
	}
	argv, err := guestArgv("MARK\n", []string{"FROM_IMAGE=1", "HOME=/image/home"}, "/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"BASH_ENV=/nonexistent/hook", "ENV=/nonexistent/hook", "NODE_OPTIONS=--require /nonexistent/hook.js", "LEAKED=1"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %s", err, stderr.String())
	}
	if stderr.String() != "MARK\n" {
		t.Fatalf("stderr %q, want the marker alone", stderr.String())
	}
	hostname, _ := os.ReadFile("/etc/hostname")
	want := []string{"PATH=" + sessionkit.ControlPath, "HOME=/image/home", "HOSTNAME=" + strings.TrimSpace(string(hostname)), "FROM_IMAGE=1"}
	got := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("environment %q, want %q", got, want)
	}

	// Without a HOME entry, HOME is the passwd home of the uid it runs as, as docker
	// sets it: here the test's own uid.
	argv, err = guestArgv("", nil, "/bin/sh", "-c", `printf %s "$HOME"`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(argv[0], argv[1:]...).Output()
	if err != nil {
		t.Fatal(err)
	}
	home, uid := "/", strconv.Itoa(os.Getuid())
	passwd, _ := os.ReadFile("/etc/passwd")
	for _, line := range strings.Split(string(passwd), "\n") {
		if f := strings.Split(line, ":"); len(f) >= 6 && f[2] == uid {
			home = f[5]
			break
		}
	}
	if string(out) != home {
		t.Fatalf("HOME %q, want %q (uid %s's passwd entry)", out, home, uid)
	}
}

// The guest uid is configurable within 1 to maxGuestUID, and Preflight's account
// check refuses one that an account or a group of this host has, or whose identity
// check's uid (one more) is; the default is in no allocator's band.
func TestGuestUIDIsNoHostAccount(t *testing.T) {
	// Root, past nobody, and systemd's bands of accounts never in /etc/passwd (homed,
	// greeter, dynamic users), the uid or its identity check's uid + 1.
	for _, uid := range []int{0, -1, maxGuestUID + 1, 65533, 65534, 60001, 60513, 60577, 61183, 61184, 65519} {
		if validateGuestUID(uid) == nil {
			t.Errorf("guest uid %d was accepted", uid)
		}
	}
	for _, uid := range []int{1, 60000 - 1, 60514, 60706, 61182, 65520, maxGuestUID} {
		if err := validateGuestUID(uid); err != nil {
			t.Errorf("guest uid %d: %v", uid, err)
		}
	}
	if err := validateGuestUID(defaultGuestUID); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	passwd, group := filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(passwd, "root:x:0:0:root:/root:/bin/sh\noperator:x:1000:1000::/home/operator:/bin/bash\nsvc:x:61001:61001::/:/bin/false\npadded:x:061100:5::/:/bin/false\nmember:x:5000:61300::/:/bin/false")
	write(group, "root:x:0:\ndocker:x:62000:operator\n")
	prev, prevGroup := hostPasswdPath, hostGroupPath
	hostPasswdPath, hostGroupPath = passwd, group
	defer func() { hostPasswdPath, hostGroupPath = prev, prevGroup }()
	// 061100 is 61100 to the C library; 61300 is member's primary group, with no
	// /etc/group line of its own.
	for uid, want := range map[int]string{1000: "operator", 61000: "svc", 61999: "docker", 62000: "docker", 61100: "padded", 61299: "member"} {
		if err := checkGuestUIDUnused(uid); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("guest uid %d: %v; want it refused, naming %s", uid, err, want)
		}
	}
	if err := checkGuestUIDUnused(61500); err != nil {
		t.Errorf("a uid no account or group has: %v", err)
	}
	hostPasswdPath, hostGroupPath = filepath.Join(dir, "none"), filepath.Join(dir, "none")
	if err := checkGuestUIDUnused(1000); err != nil {
		t.Errorf("a host with neither file: %v", err)
	}
	t.Setenv("SANDBOX_PROVIDER", "docker")
	for raw, ok := range map[string]bool{"60800": true, "61500": false, "abc": false, "0": false, "70000": false} {
		p, err := Build(func(k string) string {
			if k == "SANDBOX_PROVIDER" {
				return "docker"
			}
			if k == "SANDBOX_GUEST_UID" {
				return raw
			}
			return ""
		})
		if (err == nil) != ok {
			t.Errorf("SANDBOX_GUEST_UID=%s: %v", raw, err)
		}
		if ok && p.Sandbox.(*DockerSandbox).GuestUID != 60800 {
			t.Errorf("SANDBOX_GUEST_UID=%s gave %d", raw, p.Sandbox.(*DockerSandbox).GuestUID)
		}
	}
}

// The provider starts docker only through dockerCommand (or, for resolving the
// daemon, dockerResolveCommand), and builds -e flags only through dockerEnvFlag. A
// new call site that starts docker directly, or writes "-e" or "--env" by hand, fails
// here: it would reintroduce the leaks docker_cli.go describes.
func TestDockerCLIIsStartedOnlyThroughDockerCommand(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || name == "docker_cli.go" {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "exec" || (sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext") {
					return true
				}
				for _, a := range n.Args {
					if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == `"docker"` {
						t.Errorf("%s: starts docker directly; use dockerCommand (docker_cli.go)", fset.Position(n.Pos()))
					}
				}
			case *ast.BasicLit:
				if !strings.HasPrefix(name, "docker") || n.Kind != token.STRING {
					return true
				}
				if v, _ := strconv.Unquote(n.Value); v == "-e" || v == "--env" || strings.HasPrefix(v, "--env=") || v == "--env-file" {
					t.Errorf("%s: builds a docker env flag by hand; use dockerEnvFlag (docker_cli.go)", fset.Position(n.Pos()))
				}
			}
			return true
		})
	}
}

// Every command's answer is read through a bound (review F13): no Output or
// CombinedOutput, which buffer without limit, and a command's Stdout and Stderr are
// only ever a cappedBuffer. A command here is a variable or parameter declared as one
// (dockerCommand, dockerResolveCommand, exec.Command, exec.CommandContext, *exec.Cmd);
// a pipe (StdoutPipe) is a stream its reader bounds and is not checked.
func TestDockerCLIOutputIsAlwaysCapped(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if ok && len(n.Args) == 0 && (sel.Sel.Name == "Output" || sel.Sel.Name == "CombinedOutput") {
					t.Errorf("%s: %s buffers a command's output without a bound; use dockerOutput or cappedOutput (docker_cli.go)", fset.Position(n.Pos()), sel.Sel.Name)
				}
			case *ast.AssignStmt:
				for i, lhs := range n.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || (sel.Sel.Name != "Stdout" && sel.Sel.Name != "Stderr") || !declaredCommand(sel.X) {
						continue
					}
					if i >= len(n.Rhs) || !addressOfCappedBuffer(n.Rhs[i]) {
						t.Errorf("%s: a command's %s is not a cappedBuffer", fset.Position(lhs.Pos()), sel.Sel.Name)
					}
				}
			}
			return true
		})
	}
}

// declaredCommand reports whether e names a variable or parameter declared as a
// command: assigned from a constructor of one, or of type *exec.Cmd.
func declaredCommand(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	if !ok || id.Obj == nil {
		return false
	}
	isCmdType := func(t ast.Expr) bool {
		star, ok := t.(*ast.StarExpr)
		if !ok {
			return false
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		pkg, _ := sel.X.(*ast.Ident)
		return ok && pkg != nil && pkg.Name == "exec" && sel.Sel.Name == "Cmd"
	}
	switch d := id.Obj.Decl.(type) {
	case *ast.Field:
		return isCmdType(d.Type)
	case *ast.ValueSpec:
		return d.Type != nil && isCmdType(d.Type)
	case *ast.AssignStmt:
		for _, rhs := range d.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				if fn.Name == "dockerCommand" || fn.Name == "dockerResolveCommand" {
					return true
				}
			case *ast.SelectorExpr:
				if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "exec" && (fn.Sel.Name == "Command" || fn.Sel.Name == "CommandContext") {
					return true
				}
			}
		}
	}
	return false
}

// addressOfCappedBuffer reports whether e is &x for a variable x declared as a
// cappedBuffer.
func addressOfCappedBuffer(e ast.Expr) bool {
	u, ok := e.(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return false
	}
	id, ok := u.X.(*ast.Ident)
	if !ok || id.Obj == nil {
		return false
	}
	spec, ok := id.Obj.Decl.(*ast.ValueSpec)
	if !ok {
		return false
	}
	typ, ok := spec.Type.(*ast.Ident)
	return ok && typ.Name == "cappedBuffer"
}

// cappedOutput refuses an answer past its cap instead of returning part of one, and a
// failure's error carries the bounded stderr.
func TestCappedOutputRefusesAnOversizedAnswer(t *testing.T) {
	ctx := context.Background()
	if _, err := cappedOutput(exec.CommandContext(ctx, "head", "-c", strconv.Itoa(dockerOutputCap+1), "/dev/zero")); err == nil {
		t.Fatal("an answer one byte past the cap was returned")
	}
	out, err := cappedOutput(exec.CommandContext(ctx, "head", "-c", strconv.Itoa(dockerOutputCap), "/dev/zero"))
	if err != nil || len(out) != dockerOutputCap {
		t.Fatalf("an answer at the cap: %d bytes, %v", len(out), err)
	}
	_, err = cappedOutput(exec.CommandContext(ctx, "sh", "-c", "head -c 200000 /dev/zero | tr '\\0' x >&2; exit 3"))
	if err == nil {
		t.Fatal("a failing command returned no error")
	}
	if msg := err.Error(); len(msg) > dockerErrorCap+100 || !strings.Contains(msg, "exit status 3") {
		t.Fatalf("a failure with a long stderr: %d bytes of error, starting %.80q", len(msg), msg)
	}
}

// A proxy in the host's docker client config, and a secret in the daemon's
// environment, never reach guest code (reproduced as a leak before docker_cli.go).
func TestDockerHostSettingsNeverReachGuestCode(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	cfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg, "config.json"),
		[]byte(`{"proxies":{"default":{"httpProxy":"http://user:canary@proxy.example:3128","noProxy":"canary.example"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", cfg)
	t.Setenv("PLIMSOLL_TOKEN", "canary-daemon-secret")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := d.RunJavaScript(ctx, Request{Code: `console.log(JSON.stringify(process.env))`, Timeout: 10 * time.Second})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("run: %+v, %v", res, err)
	}
	var env map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &env); err != nil {
		t.Fatalf("guest environment %q: %v", res.Stdout, err)
	}
	for k, v := range env {
		if strings.Contains(strings.ToLower(k), "proxy") || strings.Contains(v, "canary") {
			t.Errorf("guest code sees %s=%s", k, v)
		}
	}
}

// An image's environment reaches guest processes alone (review F5). An image whose
// NODE_OPTIONS loads a hook from /work passes Preflight; a snippet's node and a
// project's steps start with that environment, and with HOME and HOSTNAME as docker
// sets them; the runner never loads the hook; and a hook an earlier session call
// wrote, which exits 125 as docker does when it fails, leaves the call classified as
// the guest's own result. Before, Preflight refused such an image: a denylist of
// variables was all that stood between the hook and plimsoll's own programs.
func TestDockerImageEnvReachesOnlyGuestProcesses(t *testing.T) {
	requireDocker(t)
	const img = "crsbx-test-env-hook-image:local"
	// Every node started with the image's environment logs its argv, then loads
	// /work/hook.js when guest code has written one.
	loader := `const fs=require("fs");try{fs.appendFileSync("/tmp/loaded.log",JSON.stringify(process.argv)+"\n")}catch{}if(fs.existsSync("/work/hook.js"))require("/work/hook.js");`
	build := exec.Command("docker", "build", "-q", "-t", img, "-")
	build.Stdin = strings.NewReader("FROM plimsoll/sandbox:latest\nUSER root\nRUN printf '%s\\n' '" + loader + "' > /usr/local/lib/plimsoll-test-loader.js\nUSER node\n" +
		"ENV NODE_OPTIONS=\"--require /usr/local/lib/plimsoll-test-loader.js\" NODE_DEBUG=esm PLIMSOLL_TEST_CANARY=image\n")
	if out, err := build.CombinedOutput(); err != nil {
		infraSkip(t, "cannot build throwaway image: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", img).Run() })
	d := testDocker()
	d.Image, d.ProjectImage = img, img
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatalf("Preflight: %v; an image's environment no longer decides whether it runs", err)
	}
	logLines := func(log string) []string { return strings.Split(strings.TrimSpace(log), "\n") }

	res, err := d.RunJavaScript(ctx, Request{Code: `const os = require("os");
console.log(JSON.stringify([process.env.PLIMSOLL_TEST_CANARY, process.env.HOME, process.env.HOSTNAME === os.hostname(),
  require("fs").readFileSync("/tmp/loaded.log", "utf8").trim().split("\n").length]))`})
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != `["image","/",true,1]` {
		t.Fatalf("snippet: %+v, %v; want the image's variable, HOME / (the guest uid has no passwd entry, so docker's /), HOSTNAME the container's, the hook loaded once (by the snippet's node)", res, err)
	}

	pres, err := d.RunProject(ctx, ProjectRequest{Steps: []string{
		`node -e 'console.log(process.env.PLIMSOLL_TEST_CANARY + " " + process.env.HOME)'`,
		`cat /tmp/loaded.log`,
	}})
	if err != nil || pres.Outcome != ProjectOutcomeCompleted || len(pres.Steps) != 2 {
		t.Fatalf("project: %+v, %v", pres, err)
	}
	if got := strings.TrimSpace(pres.Steps[0].Stdout); got != "image /" {
		t.Fatalf("a step saw %q, want the image's variable and HOME", got)
	}
	if lines := logLines(pres.Steps[1].Stdout); len(lines) != 1 || strings.Contains(pres.Steps[1].Stdout, "runner.mjs") {
		t.Fatalf("processes that loaded the image's hook: %q; want the step's node alone, never the runner", lines)
	}

	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	r1, err := s.RunJavaScript(ctx, Request{Code: `require("fs").writeFileSync("/work/hook.js", 'process.stderr.write("HOOKED\\n"); process.exit(125)')`})
	if err != nil || r1.ExitCode != 0 {
		t.Fatalf("writing the hook: %+v, %v", r1, err)
	}
	r2, err := s.RunJavaScript(ctx, Request{Code: `console.log("unreached")`})
	if err != nil || r2.ExitCode != 125 || !strings.Contains(r2.Stderr, "HOOKED") {
		t.Fatalf("a call whose node the guest's hook ends with 125: %+v, %v; want the guest's result, exit 125, not docker's failure", r2, err)
	}
	r3, err := s.RunProject(ctx, ProjectRequest{Steps: []string{`rm /work/hook.js && cat /tmp/loaded.log`}})
	if err != nil || r3.Outcome != ProjectOutcomeCompleted || len(r3.Steps) != 1 || r3.Steps[0].ExitCode != 0 {
		t.Fatalf("a project call with the hook in place: %+v, %v; the runner would have exited 125 had it loaded the hook", r3, err)
	}
	if lines := logLines(r3.Steps[0].Stdout); len(lines) != 2 || strings.Contains(r3.Steps[0].Stdout, "runner.mjs") {
		t.Fatalf("processes that loaded the image's hook in the session: %q; want the two snippets' nodes alone", lines)
	}
	// A cell's interpreter is guest-facing too: it starts with the image's environment,
	// while its launcher, plimsoll's, starts with none of it.
	c, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: `console.log(process.env.PLIMSOLL_TEST_CANARY + " " + process.env.HOME)`})
	if err != nil || c.ExitCode != 0 || strings.TrimSpace(c.Stdout) != "image /" {
		t.Fatalf("a cell: %+v, %v; want the image's variable and HOME", c, err)
	}
}

// An image whose environment sets a dynamic-loader variable is refused before any run:
// docker hands it to the first process of every container command, plimsoll's
// /usr/bin/env, whose loader reads it before env -i clears anything. Under glibc an
// LD_PRELOAD naming a missing library printed the loader's warning ahead of a call's
// start marker, so a guest's exit read as docker's
// failure; LD_DEBUG does the same under musl and glibc.
func TestDockerPreflightRefusesLoaderEnv(t *testing.T) {
	// Preflight also inspects the snippet image, so without the configured images the
	// refusal under test is never reached (a hosted runner has docker and no images).
	requireSnippetImage(t, testDocker())
	for _, c := range []struct{ base, env, name string }{
		{"node:22-alpine", "LD_DEBUG=all", "LD_DEBUG"},
		{"plimsoll/sandbox-sim:latest", "LD_PRELOAD=/plimsoll/missing.so", "LD_PRELOAD"},
	} {
		img := "crsbx-test-loader-env-" + strings.ToLower(c.name) + ":local"
		build := exec.Command("docker", "build", "-q", "-t", img, "-")
		build.Stdin = strings.NewReader("FROM " + c.base + "\nENV " + c.env + "\n")
		if out, err := build.CombinedOutput(); err != nil {
			infraSkip(t, "cannot build throwaway image: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", img).Run() })
		d := testDocker()
		d.ProjectImage = img
		if err := d.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), c.name) {
			t.Errorf("%s over %s: Preflight = %v, want %s refused", c.env, c.base, err, c.name)
		}
	}
}

// An image's HEALTHCHECK never runs inside a sandbox: dockerd would otherwise run the
// image's command in the container on an interval (it did, every second, before
// --no-healthcheck).
func TestDockerImageHealthcheckNeverRuns(t *testing.T) {
	requireDocker(t)
	const img = "crsbx-test-healthcheck-image:local"
	build := exec.Command("docker", "build", "-q", "-t", img, "-")
	build.Stdin = strings.NewReader("FROM plimsoll/sandbox:latest\nHEALTHCHECK --interval=1s --start-period=0s CMD [\"sh\",\"-c\",\"echo ran > /tmp/hc; echo ran > /work/hc\"]\n")
	if out, err := build.CombinedOutput(); err != nil {
		infraSkip(t, "cannot build throwaway image: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", img).Run() })
	d := testDocker()
	d.ProjectImage = img
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	time.Sleep(3 * time.Second)
	res, err := s.RunJavaScript(ctx, Request{Code: `const fs = require("fs"); console.log(fs.existsSync("/tmp/hc") || fs.existsSync("/work/hc"))`, Timeout: 10 * time.Second})
	if err != nil || strings.TrimSpace(res.Stdout) != "false" {
		t.Fatalf("after 3 s: %+v, %v; want no trace of the healthcheck", res, err)
	}
}

// The smoke probe's ids pass only when every uid, gid and supplementary group is the
// guest uid.
func TestCheckGuestIDs(t *testing.T) {
	ok := []string{"61000", "61000", "61000", "61000"}
	if err := checkGuestIDs(ok, ok, nil, 61000); err != nil {
		t.Fatal(err)
	}
	if err := checkGuestIDs(ok, ok, []string{"61000"}, 61000); err != nil {
		t.Fatal(err)
	}
	for name, ids := range map[string][3][]string{
		"another uid":         {{"61000", "1000", "61000", "61000"}, ok, nil},
		"another gid":         {ok, {"1000", "1000", "1000", "1000"}, nil},
		"a supplementary one": {ok, ok, {"61000", "999"}},
		"none read":           {nil, nil, nil},
	} {
		if checkGuestIDs(ids[0], ids[1], ids[2], 61000) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// SANDBOX_GUEST_UID set for a provider that does not pick its guests' uid fails
// Build, rather than look applied.
func TestGuestUIDOnlyForDocker(t *testing.T) {
	for _, provider := range []string{"wasm", "e2b", "dockercloud", ""} {
		_, err := Build(func(k string) string {
			switch k {
			case "SANDBOX_PROVIDER":
				return provider
			case "SANDBOX_GUEST_UID":
				return "61500"
			}
			return ""
		})
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_GUEST_UID") {
			t.Errorf("provider %q with SANDBOX_GUEST_UID: %v; want refused", provider, err)
		}
	}
}
