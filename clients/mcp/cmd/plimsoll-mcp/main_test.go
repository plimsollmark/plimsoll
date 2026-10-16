package main_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
)

// build compiles the command once per test, as a host would run it. With
// PLIMSOLL_MCP_COMMAND set (scripts/release-check.sh sets it), the tests run that
// command instead: the npm launcher as installed from its packed tarball, or a
// bundle's binary.
func build(t *testing.T) string {
	t.Helper()
	if cmd := os.Getenv("PLIMSOLL_MCP_COMMAND"); cmd != "" {
		return cmd
	}
	bin := filepath.Join(t.TempDir(), "plimsoll-mcp")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// reachable waits, for a Windows binary run through WSL interop, until Windows can
// reach the fake daemon: WSL forwards a new localhost port to Windows only after a
// moment, and a call sent before then is refused by a daemon that is up.
func reachable(t *testing.T, bin, url string) {
	t.Helper()
	if !strings.HasSuffix(bin, ".exe") {
		return
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		out, _ := exec.Command("curl.exe", "-s", "-o", "NUL", "-w", "%{http_code}", url+"/").Output()
		if code := strings.TrimSpace(string(out)); code != "" && code != "000" {
			return
		}
	}
	t.Fatalf("Windows cannot reach %s through WSL's localhost forwarding", url)
}

func command(bin string, env ...string) *exec.Cmd {
	cmd := exec.Command(bin)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	if strings.HasSuffix(bin, ".exe") {
		// A Windows binary run through WSL interop sees only the variables WSLENV names.
		var names []string
		for _, kv := range env {
			names = append(names, kv[:strings.IndexByte(kv, '=')])
		}
		cmd.Env = append(cmd.Env, "WSLENV="+strings.Join(names, ":"))
	}
	return cmd
}

// Over real stdio, through the SDK's own client at its current protocol: the server
// answers, and when the host closes stdin it closes its sandboxes on the daemon and exits.
func TestStdioServesAndClosesItsSandboxes(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	bin := build(t)
	reachable(t, bin, d.URL)
	cmd := command(bin, "PLIMSOLL_URL="+d.URL, "PLIMSOLL_MIN_ISOLATION=container")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	ctx := context.Background()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "open_sandbox", Arguments: map[string]any{}})
	if err != nil || opened.IsError {
		t.Fatalf("open_sandbox: %v %+v", err, opened)
	}
	h := opened.StructuredContent.(map[string]any)["sandbox"]
	ran, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "run_code", Arguments: map[string]any{"code": "y = 2", "sandbox": h}})
	if err != nil || ran.IsError || ran.StructuredContent.(map[string]any)["stdout"] != "python 1: y = 2" {
		t.Fatalf("run_code: %v %+v", err, ran)
	}
	if d.OpenSessions() != 1 {
		t.Fatalf("%d sessions open", d.OpenSessions())
	}
	if err := cs.Close(); err != nil {
		t.Fatal(err)
	}
	if state, _ := cmd.Process.Wait(); state != nil && !state.Success() {
		t.Errorf("exited %v", state)
	}
	if d.OpenSessions() != 0 {
		t.Errorf("%d sessions still open after the host closed the server", d.OpenSessions())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr: %s", stderr.String())
	}
}

// A 2025-era host opens with initialize, which the server must answer at that
// revision, and then list and call tools as before.
func TestStdioServesA2025Host(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	bin := build(t)
	reachable(t, bin, d.URL)
	cmd := command(bin, "PLIMSOLL_URL="+d.URL, "PLIMSOLL_MIN_ISOLATION=container")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 1<<20), 1<<20)
	send := func(msg string) map[string]any {
		t.Helper()
		if _, err := stdin.Write([]byte(msg + "\n")); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(msg, `"id"`) {
			return nil
		}
		done := make(chan bool, 1)
		go func() { done <- lines.Scan() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("no answer to %s", msg)
		}
		var m map[string]any
		if err := json.Unmarshal(lines.Bytes(), &m); err != nil {
			t.Fatalf("%v: %s", err, lines.Text())
		}
		return m
	}
	init := send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"old-host","version":"0"}}}`)
	result, _ := init["result"].(map[string]any)
	info, _ := result["serverInfo"].(map[string]any)
	if result["protocolVersion"] != "2025-11-25" || info["name"] != server.Name || info["version"] != server.Version {
		t.Fatalf("initialize: %v", init)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	list := send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if tools, _ := list["result"].(map[string]any)["tools"].([]any); len(tools) != 5 {
		t.Fatalf("tools/list: %v", list)
	}
	call := send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_code","arguments":{"code":"print(2)"}}}`)
	res, _ := call["result"].(map[string]any)
	if sc, _ := res["structuredContent"].(map[string]any); sc["stdout"] != "fresh python: print(2)" {
		t.Fatalf("tools/call: %v", call)
	}
}

func TestStartedWithoutAURLItSaysWhyOnStderr(t *testing.T) {
	cmd := command(build(t))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
		t.Errorf("exit: %v", err)
	}
	if stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "plimsoll-mcp: PLIMSOLL_URL is not set") {
		t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}

// A signal cancels a call in progress and closes the
// sandboxes at once, rather than waiting for the call (which a host would not).
// SIGHUP too: a terminal closing sends it, and the npm launcher forwards it.
func TestASignalCancelsRunningCallsAndClosesSandboxes(t *testing.T) {
	bin := build(t)
	if strings.HasSuffix(bin, ".exe") {
		t.Skip("a signal does not reach a Windows process through WSL interop")
	}
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
			cmd := command(bin, "PLIMSOLL_URL="+d.URL, "PLIMSOLL_MIN_ISOLATION=container")
			ctx := context.Background()
			cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer cs.Close()
			opened, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "open_sandbox", Arguments: map[string]any{}})
			if err != nil || opened.IsError {
				t.Fatalf("open_sandbox: %v %+v", err, opened)
			}
			blocked := d.Provider.Blocked()
			go func() {
				_, _ = cs.CallTool(ctx, &mcp.CallToolParams{Name: "run_code", Arguments: map[string]any{"code": fakedaemon.Block, "sandbox": opened.StructuredContent.(map[string]any)["sandbox"]}})
			}()
			<-blocked
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			exited := make(chan struct{})
			go func() { _, _ = cmd.Process.Wait(); close(exited) }()
			select {
			case <-exited:
			case <-time.After(3 * time.Second):
				t.Fatalf("the server was still running 3 s after %s, with a call in progress", sig)
			}
			if n := d.OpenSessions(); n != 0 {
				t.Errorf("%d sessions open after %s", n, sig)
			}
		})
	}
}
