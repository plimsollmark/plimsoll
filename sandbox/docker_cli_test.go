package sandbox

import (
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
	argv, err := controlArgv(map[string]string{"PLIMSOLL_WORK": "/work"}, "node", "-")
	if err != nil || !slices.Equal(argv, []string{"env", "-i", "PATH=" + controlPath, "PLIMSOLL_WORK=/work", "node", "-"}) {
		t.Fatalf("controlArgv: %q, %v", argv, err)
	}
	if _, err := controlArgv(map[string]string{"A B": "x"}); err == nil {
		t.Error("controlArgv accepted an invalid name")
	}
}

// What an image may declare: the shipped images pass; a variable that loads code, or
// a search path into a place guest code writes, is refused.
func TestCheckImageEnv(t *testing.T) {
	for _, ok := range [][]string{
		{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "NODE_VERSION=22.23.3", "YARN_VERSION=1.22.22"},
		{"PATH=/opt/wasi-sdk/bin:/usr/bin:/bin", "OPENBLAS_NUM_THREADS=1", "OMP_NUM_THREADS=1"},
		{"NODE_PATH=/usr/lib/node_modules", "PYTHONPATH=/opt/lib/python", "PYTHONDONTWRITEBYTECODE=1", "PYTHON_VERSION=3.14.0"},
		nil,
	} {
		if err := checkImageEnv(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"NODE_OPTIONS=--require /work/hook.js", "NODE_OPTIONS=--max-old-space-size=64", "LD_PRELOAD=/usr/lib/x.so",
		"LD_LIBRARY_PATH=/opt/lib", "GLIBC_TUNABLES=glibc.malloc.check=3", "BASH_ENV=/etc/x", "PYTHONSTARTUP=/opt/s.py",
		"NODE_EXTRA_CA_CERTS=/etc/ca.pem", "PATH=/work/bin:/usr/bin", "PATH=.:/usr/bin", "PATH=/usr/bin:", "NODE_PATH=/tmp/m",
		"PYTHONPATH=lib", "PATH=/dev/shm/x", "NODE_PATH=/proc/self/fd/3",
		// The same places spelled another way, and node's compile cache (node 22.1 and
		// later reads cached compiled code for every module, the runner's included).
		"PATH=//tmp:/usr/bin", "PATH=/usr/../tmp", "NODE_PATH=/./work/node_modules", "PYTHONPATH=/opt/../work",
		"NODE_COMPILE_CACHE=/tmp/cc", "NODE_COMPILE_CACHE=/opt/cache",
		// node writes these before a call's start marker.
		"NODE_DEBUG=esm", "NODE_DEBUG_NATIVE=fs",
	} {
		if err := checkImageEnv([]string{"PATH=/usr/bin", bad}); err == nil {
			t.Errorf("%s was accepted", bad)
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

// An image whose environment would load code guest code wrote is refused before any
// run: NODE_OPTIONS ran a guest-written file inside plimsoll's own node processes.
func TestDockerPreflightRejectsImageWhoseEnvLoadsCode(t *testing.T) {
	requireDocker(t)
	const img = "crsbx-test-env-hook-image:local"
	build := exec.Command("docker", "build", "-q", "-t", img, "-")
	build.Stdin = strings.NewReader("FROM node:22-alpine\nENV NODE_OPTIONS=\"--require /work/hook.js\"\n")
	if out, err := build.CombinedOutput(); err != nil {
		infraSkip(t, "cannot build throwaway image: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", img).Run() })
	d := testDocker()
	d.Image = img
	d.ProjectImage = img
	err := d.Preflight(context.Background())
	if err == nil || !strings.Contains(err.Error(), "NODE_OPTIONS") {
		t.Fatalf("Preflight = %v, want NODE_OPTIONS refused", err)
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
