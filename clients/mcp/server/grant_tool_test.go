package server_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// An API description in plimsoll-specgen's shape.
const grantAPI = "Echo lights (v1).\n  host.getLight(id)  ->  GET /v1/lights/*\n"

func grantedConfig(url, profile string) server.Config {
	cfg := local(url)
	cfg.Token = fakedaemon.GrantToken
	cfg.GrantProfile, cfg.GrantDescription = profile, grantAPI
	return cfg
}

func runCodeTool(t *testing.T, c *conn) (string, map[string]any) {
	t.Helper()
	list, err := c.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range list.Tools {
		if tool.Name == "run_code" {
			props := tool.InputSchema.(map[string]any)["properties"].(map[string]any)
			return tool.Description, props
		}
	}
	t.Fatal("no run_code")
	return "", nil
}

// A server installed with a grant: run_code without a sandbox carries the installer's
// profile and nothing else does; the model is told what the code can call and that a
// sandbox's kept state cannot call it; no tool argument names a profile.
func TestGrantedRunCodeCarriesTheInstallersProfileOnFreshCallsOnly(t *testing.T) {
	d := fakedaemon.ServeGranted(t, "docker")
	c := connect(t, grantedConfig(d.URL, fakedaemon.GrantProfile))
	text, props := runCodeTool(t, c)
	for _, want := range []string{grantAPI[:len(grantAPI)-1], "with no network access except, without sandbox, the one web API described below",
		"Code run in a sandbox from open_sandbox cannot call the API", "import plimsoll_host", "adds the API's key outside the sandbox"} {
		if !strings.Contains(text, want) {
			t.Errorf("run_code's description lacks %q", want)
		}
	}
	for name := range props {
		if name != "code" && name != "language" && name != "files" && name != "sandbox" && name != "trace" {
			t.Errorf("run_code takes %q, which no model should set", name)
		}
	}
	js := c.ok("run_code", map[string]any{"code": "1", "language": "javascript"})
	if got := js["stdout"]; got != "granted GET /v1/lights/*|fresh javascript: 1" {
		t.Errorf("a fresh JavaScript call: stdout %q", got)
	}
	if !strings.Contains(js["summary"].(string), "with the API this server's grant allows") {
		t.Errorf("summary %q", js["summary"])
	}
	py := c.ok("run_code", map[string]any{"code": "import plimsoll_host", "language": "python"})
	if got := py["stdout"]; got != "granted GET /v1/lights/*|module|fresh python: import plimsoll_host" {
		t.Errorf("a fresh Python call: stdout %q", got)
	}
	// A call in a kept sandbox carries no grant.
	handle := c.ok("open_sandbox", nil)["sandbox"].(string)
	kept := c.ok("run_code", map[string]any{"code": "1", "language": "javascript", "sandbox": handle})
	if strings.Contains(kept["stdout"].(string), "granted") {
		t.Errorf("a call in a kept sandbox carried the grant: %q", kept["stdout"])
	}
	info := c.ok("server_info", nil)["summary"].(string)
	if !strings.Contains(info, `run_code carries grant profile "echo-api"`) || !strings.Contains(info, "JavaScript and Python code") {
		t.Errorf("server_info's summary does not name the profile in force: %q", info)
	}
}

// On a daemon whose Python steps cannot reach the broker, a fresh Python call is refused
// before anything runs, with what to write instead, and the description says so first.
func TestGrantedPythonWhereItCannotReachTheBrokerIsRefused(t *testing.T) {
	d := fakedaemon.ServeGranted(t, "e2b")
	c := connect(t, grantedConfig(d.URL, fakedaemon.GrantProfile))
	text, _ := runCodeTool(t, c)
	if !strings.Contains(text, "Python code cannot call the API on this daemon (its provider, e2b") || strings.Contains(text, "import plimsoll_host") {
		t.Errorf("run_code's description does not say Python cannot call the API here:\n%s", text)
	}
	before := d.Calls("Run")
	f := c.fail("run_code", map[string]any{"code": "print(1)", "language": "python"})
	if f.Ran != "no" || f.Refusal != "unsupported" || !strings.Contains(f.Summary, "Write the program in JavaScript") {
		t.Errorf("a fresh Python call: %+v", f)
	}
	// An omitted language is the server's first, Python here: refused too, never run as
	// JavaScript, which the code may not be.
	if f := c.fail("run_code", map[string]any{"code": "print(1)"}); f.Ran != "no" || f.Refusal != "unsupported" {
		t.Errorf("a fresh call without a language: %+v", f)
	}
	if d.Calls("Run") != before {
		t.Error("the refused call reached the daemon")
	}
	if got := c.ok("run_code", map[string]any{"code": "2", "language": "javascript"})["stdout"]; got != "granted GET /v1/lights/*|fresh javascript: 2" {
		t.Errorf("JavaScript: %q", got)
	}
}

// On a daemon that runs snippets only (wasm, which grants snippets), a granted call is a
// snippet, evaluated as a script where top-level await fails
// (sandbox's TestGrantedSnippetCellNeedsAnAsyncFunction): run_code's description says so and
// names the form that works, where a project daemon's says to await.
func TestGrantedSnippetDaemonIsToldNotToAwaitAtTopLevel(t *testing.T) {
	cfg := local(fakedaemon.ServeWasm(t))
	cfg.MinimumIsolation = sandbox.IsolationProcess
	cfg.GrantProfile, cfg.GrantDescription = fakedaemon.GrantProfile, grantAPI
	text, _ := runCodeTool(t, connect(t, cfg))
	if !strings.Contains(text, "Top-level await does not work in this sandbox") || strings.Contains(text, "so await it") {
		t.Errorf("a snippet daemon's run_code description:\n%s", text)
	}
	project, _ := runCodeTool(t, connect(t, grantedConfig(fakedaemon.ServeGranted(t, "docker").URL, fakedaemon.GrantProfile)))
	if !strings.Contains(project, "so await it") || strings.Contains(project, "Top-level await does not work") {
		t.Errorf("a project daemon's run_code description:\n%s", project)
	}
}

// An unknown profile is the daemon's permission refusal, said to be the operator's.
func TestGrantedUnknownProfileIsTheOperatorsToFix(t *testing.T) {
	d := fakedaemon.ServeGranted(t, "docker")
	c := connect(t, grantedConfig(d.URL, "no-such-api"))
	f := c.fail("run_code", map[string]any{"code": "1", "language": "javascript"})
	if f.Ran != "no" || f.Refusal != "permission" || !strings.Contains(f.Summary, "That is the operator's to fix") {
		t.Errorf("%+v", f)
	}
}

// A server whose grant the daemon cannot carry, or cannot ask about, does not start; a
// grant is a profile and its description together, read from the environment.
func TestGrantedServerRefusesToStartWithoutADaemonThatCarriesIt(t *testing.T) {
	plain := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 1})
	for name, cfg := range map[string]server.Config{
		"no grants":   grantedConfig(plain.URL, fakedaemon.GrantProfile),
		"unreachable": grantedConfig("http://127.0.0.1:9", fakedaemon.GrantProfile),
	} {
		if _, err := server.New(cfg); err == nil {
			t.Errorf("%s: the server started", name)
		}
	}
	half := local(plain.URL)
	half.GrantProfile = "echo-api"
	if _, err := server.New(half); err == nil || !strings.Contains(err.Error(), "set both, or neither") {
		t.Errorf("a profile without a description: %v", err)
	}
	file := filepath.Join(t.TempDir(), "description.txt")
	if err := os.WriteFile(file, []byte(grantAPI), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_GRANT_PROFILE": "echo-api", "PLIMSOLL_GRANT_DESCRIPTION_FILE": file}
	cfg, err := server.FromEnv(func(k string) string { return env[k] })
	if err != nil || cfg.GrantProfile != "echo-api" || cfg.GrantDescription != grantAPI {
		t.Errorf("FromEnv: %+v %v", cfg.GrantProfile, err)
	}
	env["PLIMSOLL_GRANT_DESCRIPTION_FILE"] = filepath.Join(t.TempDir(), "missing.txt")
	if _, err := server.FromEnv(func(k string) string { return env[k] }); err == nil {
		t.Error("a description file that is not there was accepted")
	}
	// Without a grant nothing is asked of the daemon, and run_code says nothing of an API.
	c := connect(t, local("http://127.0.0.1:9"))
	if text, _ := runCodeTool(t, c); strings.Contains(text, "web API") {
		t.Error("an ungranted run_code speaks of an API")
	}
}
