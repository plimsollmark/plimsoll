package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

type conn struct {
	t  *testing.T
	s  *server.Server
	cs *mcp.ClientSession
	// wire is every JSON-RPC message the client sent and read, as the SDK's
	// LoggingTransport writes them, one per line.
	wire *lockedBuffer
}

func connect(t *testing.T, cfg server.Config) *conn {
	t.Helper()
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return connectServer(t, s)
}

// connectServer serves s to an in-memory client, closing both at the test's end.
func connectServer(t *testing.T, s *server.Server) *conn {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := s.MCP().Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire := &lockedBuffer{}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, &mcp.LoggingTransport{Transport: ct, Writer: wire}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
	return &conn{t: t, s: s, cs: cs, wire: wire}
}

func local(url string) server.Config {
	return server.Config{URL: url, MinimumIsolation: sandbox.IsolationContainer}
}

func (c *conn) call(name string, args map[string]any) *mcp.CallToolResult {
	c.t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	res, err := c.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		c.t.Fatalf("%s: %v", name, err)
	}
	return res
}

// ok checks the shape every success has (one text block, the JSON of the structured
// value, which carries a summary) and returns the value.
func (c *conn) ok(name string, args map[string]any) map[string]any {
	c.t.Helper()
	res := c.call(name, args)
	if res.IsError {
		c.t.Fatalf("%s failed: %s", name, text(res))
	}
	if len(res.Content) != 1 {
		c.t.Fatalf("%s: %d content blocks, want 1 (no prose outside the value, where a host can drop it)", name, len(res.Content))
	}
	var fromText, fromStructured map[string]any
	if err := json.Unmarshal([]byte(text(res)), &fromText); err != nil {
		c.t.Fatalf("%s: the text block is not JSON: %v", name, err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &fromStructured)
	if fmt.Sprint(fromText) != fmt.Sprint(fromStructured) {
		c.t.Fatalf("%s: text %v differs from structuredContent %v", name, fromText, fromStructured)
	}
	if s, _ := fromStructured["summary"].(string); s == "" {
		c.t.Fatalf("%s: no summary in %v", name, fromStructured)
	}
	return fromStructured
}

type failure struct {
	Summary       string   `json:"summary"`
	Ran           string   `json:"ran"`
	Refusal       string   `json:"refusal"`
	SandboxEnded  string   `json:"sandboxEnded"`
	RecordSHA256  string   `json:"recordSha256"`
	SandboxUsable *bool    `json:"sandboxUsable"`
	IdleSandboxes []string `json:"idleSandboxes"`
}

// fail checks a tool error is a failure value and returns it.
func (c *conn) fail(name string, args map[string]any) failure {
	c.t.Helper()
	res := c.call(name, args)
	if !res.IsError {
		c.t.Fatalf("%s succeeded: %s", name, text(res))
	}
	var f failure
	if err := json.Unmarshal([]byte(text(res)), &f); err != nil || f.Summary == "" || (f.Ran != "no" && f.Ran != "maybe") {
		c.t.Fatalf("%s: the error is not a failure value (%v): %s", name, err, text(res))
	}
	return f
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

func TestServerInfoIsWhatToolsListSends(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	list, err := c.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	info := c.ok("server_info", nil)
	var names []any
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
		if tool.OutputSchema == nil {
			t.Errorf("%s states no output schema", tool.Name)
		}
	}
	slices.SortFunc(names, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	if fmt.Sprint(info["tools"]) != fmt.Sprint(names) || fmt.Sprint(names) != "[close_sandbox get_record open_sandbox run_code server_info]" {
		t.Errorf("server_info lists %v, tools/list sends %v", info["tools"], names)
	}
	if got := server.SurfaceDigest(list.Tools); info["surfaceDigest"] != got {
		t.Errorf("surfaceDigest %v; over what tools/list sent it is %s", info["surfaceDigest"], got)
	}
	// The digest moves with any schema or annotation, not only names and descriptions.
	changed := slices.Clone(list.Tools)
	tool := *changed[0]
	tool.Annotations = &mcp.ToolAnnotations{ReadOnlyHint: true}
	changed[0] = &tool
	if server.SurfaceDigest(changed) == info["surfaceDigest"] {
		t.Error("changing an annotation left the digest as it was")
	}
	// Read-only, or else destructive unless it says it is not (MCP's default is true):
	// opening deletes nothing, since an open at the cap is refused rather than closing one.
	hints := map[string]string{}
	for _, tool := range list.Tools {
		a := tool.Annotations
		switch {
		case a.ReadOnlyHint:
			hints[tool.Name] = "read-only"
		case a.DestructiveHint == nil || *a.DestructiveHint:
			hints[tool.Name] = "destructive"
		default:
			hints[tool.Name] = "additive"
		}
	}
	want := map[string]string{"run_code": "destructive", "open_sandbox": "additive", "close_sandbox": "destructive", "get_record": "read-only", "server_info": "read-only"}
	if !maps.Equal(hints, want) {
		t.Errorf("hints %v, want %v", hints, want)
	}
	daemon, _ := info["daemon"].(map[string]any)
	if daemon["provider"] != "fake-sessions" || daemon["isolation"] != "container" || daemon["sessions"] != true {
		t.Errorf("daemon: %v", daemon)
	}
}

func TestRunCodeFresh(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	c := connect(t, local(d.URL))
	out := c.ok("run_code", map[string]any{"code": "print(1)", "files": []any{map[string]any{"path": "data/in.csv", "content": "a,b"}}})
	if out["stdout"] != "fresh python: print(1)" || out["stderr"] != "data/in.csv\n" || out["exitCode"] != float64(0) || out["stateKept"] != false || out["isolation"] != "container" {
		t.Errorf("run_code: %v", out)
	}
	digest, _ := out["recordSha256"].(string)
	summary, _ := out["summary"].(string)
	for _, want := range []string{`behind the "container" isolation tier`, "not hardware attestation", digest, "fresh sandbox; nothing is kept"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q lacks %q", summary, want)
		}
	}
	rec := c.ok("get_record", map[string]any{"recordSha256": digest})
	record, _ := rec["record"].(map[string]any)
	if record["sha256"] != digest || record["provider"] != "fake-sessions" || record["session"] != "" {
		t.Errorf("get_record: %v", rec)
	}
	if failed := c.ok("run_code", map[string]any{"code": "exit 3", "language": "javascript"}); failed["exitCode"] != float64(3) || failed["language"] != "javascript" {
		t.Errorf("a failing program is a result: %v", failed)
	}
	if f := c.fail("run_code", map[string]any{"code": "1", "files": []any{map[string]any{"path": ".plimsoll/run.py", "content": ""}}}); f.Ran != "no" || f.Refusal != "request" {
		t.Errorf("a file under .plimsoll/: %+v", f)
	}
	if f := c.fail("get_record", map[string]any{"recordSha256": strings.Repeat("0", 64)}); f.Ran != "no" || !strings.Contains(f.Summary, "keeps no record") {
		t.Errorf("an unknown record: %+v", f)
	}
}

func TestSandboxKeepsStateAndCloses(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	opened := c.ok("open_sandbox", nil)
	h, _ := opened["sandbox"].(string)
	if !regexp.MustCompile(`^sbx_[A-Za-z0-9_-]{22}$`).MatchString(h) || opened["expiresAt"] == "" || fmt.Sprint(opened["languages"]) != "[python javascript]" {
		t.Fatalf("open_sandbox: %v", opened)
	}
	if d.OpenSessions() != 1 {
		t.Errorf("the open is done when open_sandbox answers: %d sessions open", d.OpenSessions())
	}
	a := c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	b := c.ok("run_code", map[string]any{"code": "x + 1", "sandbox": h, "files": []any{map[string]any{"path": "f.txt", "content": "1"}}})
	if a["stdout"] != "python 1: x = 1" || a["freshSandbox"] != true || a["freshInterpreter"] != true {
		t.Errorf("first call: %v", a)
	}
	if b["stdout"] != "python 2: x + 1" || b["stderr"] != "f.txt\n" || b["stateKept"] != true || b["filesPersist"] != true || b["freshSandbox"] != nil {
		t.Errorf("second call: %v", b)
	}
	if !strings.Contains(b["summary"].(string), "ran in sandbox "+h+"; state kept for the next call: true, files kept: true") {
		t.Errorf("summary: %v", b["summary"])
	}
	rec := c.ok("get_record", map[string]any{"recordSha256": b["recordSha256"]})["record"].(map[string]any)
	if rec["sequence"] != float64(2) || rec["session"] == "" {
		t.Errorf("the session's second call: %v", rec)
	}
	other := c.ok("open_sandbox", nil)
	if got := c.ok("run_code", map[string]any{"code": "x", "sandbox": other["sandbox"]}); got["stdout"] != "python 1: x" {
		t.Errorf("another handle is another sandbox: %v", got)
	}
	closed := c.ok("close_sandbox", map[string]any{"sandbox": h})
	if closed["deleted"] != true || d.OpenSessions() != 1 {
		t.Errorf("close_sandbox: %v, %d open", closed, d.OpenSessions())
	}
	if f := c.fail("run_code", map[string]any{"code": "x", "sandbox": h}); f.Ran != "no" || !strings.HasPrefix(f.Summary, "Nothing ran: no sandbox sbx_") {
		t.Errorf("a closed handle: %+v", f)
	}
	if f := c.fail("close_sandbox", map[string]any{"sandbox": h}); f.Ran != "no" {
		t.Errorf("closing twice: %+v", f)
	}
}

// An open at the cap closes nothing: it is refused, naming the idle sandboxes, every
// open sandbox goes on where it was, and an explicit close makes room.
func TestAnOpenAtTheCapClosesNothingAndNamesTheIdle(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg := local(d.URL)
	cfg.MaxSandboxes = 2
	c := connect(t, cfg)
	first := c.ok("open_sandbox", nil)["sandbox"].(string)
	second := c.ok("open_sandbox", nil)["sandbox"].(string)
	c.ok("run_code", map[string]any{"code": "x", "sandbox": first})
	f := c.fail("open_sandbox", nil)
	idle := []string{first, second}
	slices.Sort(idle)
	if f.Ran != "no" || f.Refusal != "capacity" || !slices.Equal(f.IdleSandboxes, idle) ||
		!strings.Contains(f.Summary, "Nothing was closed to make room") || !strings.Contains(f.Summary, first) {
		t.Errorf("open past the cap: %+v", f)
	}
	if out := c.ok("run_code", map[string]any{"code": "y", "sandbox": first}); out["stdout"] != "python 2: y" || out["freshSandbox"] == true {
		t.Errorf("the first sandbox, after the refused open: %v", out)
	}
	if d.OpenSessions() != 2 {
		t.Errorf("%d sessions open, want 2", d.OpenSessions())
	}
	c.ok("close_sandbox", map[string]any{"sandbox": second})
	c.ok("open_sandbox", nil)
}

// An open at the cap while every sandbox is running a call names none as idle.
func TestAnOpenAtTheCapNamesNoBusySandbox(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg := local(d.URL)
	cfg.MaxSandboxes = 1
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	blocked := d.Provider.Blocked()
	done := make(chan map[string]any)
	go func() { done <- c.ok("run_code", map[string]any{"code": fakedaemon.Block, "sandbox": h}) }()
	<-blocked
	if f := c.fail("open_sandbox", nil); f.Ran != "no" || f.Refusal != "capacity" || len(f.IdleSandboxes) != 0 || !strings.Contains(f.Summary, "running a call") {
		t.Errorf("open while the only sandbox runs: %+v", f)
	}
	d.Provider.Release()
	if out := <-done; out["stdout"] != "python 1: "+fakedaemon.Block {
		t.Errorf("the running call: %v", out)
	}
	if f := c.fail("open_sandbox", nil); len(f.IdleSandboxes) != 1 || f.IdleSandboxes[0] != h {
		t.Errorf("once idle it is named, and still not closed: %+v", f)
	}
}

func TestAFailedOpenClosesNothing(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 1})
	cfg := local(d.URL)
	cfg.MaxSandboxes = 2
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	// The daemon holds one session, so the second open, within this server's cap, is
	// refused by the daemon.
	if f := c.fail("open_sandbox", nil); f.Ran != "no" || f.Refusal != "capacity" {
		t.Errorf("open past the daemon's cap: %+v", f)
	}
	if out := c.ok("run_code", map[string]any{"code": "y", "sandbox": h}); out["stdout"] != "python 1: y" {
		t.Errorf("the open sandbox is still there: %v", out)
	}
}

func TestAnEndedSandboxIsReplacedAndSaysSo(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	last := c.ok("run_code", map[string]any{"code": fakedaemon.EndsSession, "sandbox": h})
	if last["filesPersist"] != false || last["stateKept"] != false || last["sandboxEnded"] == nil ||
		!strings.Contains(last["summary"].(string), "sandbox ended as it answered") {
		t.Errorf("the call after which the sandbox ended: %v", last)
	}
	next := c.ok("run_code", map[string]any{"code": "z", "sandbox": h})
	if next["freshSandbox"] != true || next["stdout"] != "python 1: z" || next["sandboxReplaced"] != "ended ("+fmt.Sprint(last["sandboxEnded"])+")" ||
		!strings.Contains(next["summary"].(string), "earlier sandbox ended (") {
		t.Errorf("the next call runs in a new sandbox and says why: %v", next)
	}
	if again := c.ok("run_code", map[string]any{"code": "w", "sandbox": h}); again["sandboxReplaced"] != nil {
		t.Errorf("the replacement is told once: %v", again)
	}
}

func TestAnUnansweredCallKeepsItsRecordAndTheSandbox(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	f := c.fail("run_code", map[string]any{"code": fakedaemon.Breaks, "sandbox": h})
	if f.Ran != "maybe" || f.RecordSHA256 == "" || f.SandboxUsable == nil || !*f.SandboxUsable {
		t.Fatalf("an unanswered call: %+v", f)
	}
	rec := c.ok("get_record", map[string]any{"recordSha256": f.RecordSHA256})
	if r := rec["record"].(map[string]any); r["unanswered"] == "" || !strings.Contains(rec["summary"].(string), "it may have run") {
		t.Errorf("its record: %v", rec)
	}
	if out := c.ok("run_code", map[string]any{"code": "after", "sandbox": h}); out["stdout"] != "python 2: after" {
		t.Errorf("the session goes on: %v", out)
	}
}

func TestOnlyTheSessionEnvironmentsLanguagesAreOffered(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, SessionLanguages: []sandbox.Language{sandbox.LanguageJavaScript}})
	c := connect(t, local(d.URL))
	opened := c.ok("open_sandbox", nil)
	if fmt.Sprint(opened["languages"]) != "[javascript]" {
		t.Errorf("open_sandbox languages: %v", opened["languages"])
	}
	if out := c.ok("run_code", map[string]any{"code": "1", "sandbox": opened["sandbox"]}); out["language"] != "javascript" {
		t.Errorf("a call without a language takes its sandbox's: %v", out)
	}
	if f := c.fail("run_code", map[string]any{"code": "1", "language": "python", "sandbox": opened["sandbox"]}); f.Ran != "no" || f.Refusal != "unsupported" {
		t.Errorf("python in a javascript sandbox: %+v", f)
	}
	if daemon := c.ok("server_info", nil)["daemon"].(map[string]any); fmt.Sprint(daemon["sandboxLanguages"]) != "[javascript]" || fmt.Sprint(daemon["languages"]) != "[python javascript]" {
		t.Errorf("server_info: %v", daemon)
	}
}

// On a daemon that runs JavaScript snippets only, code without a language runs as
// JavaScript, whatever language comes first in the server's list.
func TestNoSessionsAndSnippetsOnly(t *testing.T) {
	url := fakedaemon.ServeWasm(t)
	for _, langs := range [][]sandbox.Language{{sandbox.LanguageJavaScript}, nil} {
		c := connect(t, server.Config{URL: url, MinimumIsolation: sandbox.IsolationProcess, Languages: langs})
		if f := c.fail("open_sandbox", nil); f.Ran != "no" || f.Refusal != "unsupported" || !strings.Contains(f.Summary, "keeps no sessions") {
			t.Errorf("%v, open_sandbox: %+v", langs, f)
		}
		if out := c.ok("run_code", map[string]any{"code": "1 + 1"}); out["stdout"] != "2\n" || out["isolation"] != "process" || out["language"] != "javascript" {
			t.Errorf("%v, a snippet: %v", langs, out)
		}
	}
}

func TestTheFloorDefaultsToKernel(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, server.Config{URL: d.URL})
	if f := c.fail("run_code", map[string]any{"code": "1"}); f.Ran != "no" || f.Refusal != "isolation" {
		t.Errorf("run_code on a container daemon: %+v", f)
	}
	if f := c.fail("open_sandbox", nil); f.Ran != "no" || f.Refusal != "isolation" {
		t.Errorf("open_sandbox on a container daemon: %+v", f)
	}
	if got := c.ok("server_info", nil)["minimumIsolation"]; got != "kernel" {
		t.Errorf("minimumIsolation %v", got)
	}
}

func TestEvidenceThatDoesNotCheckIsNeverAResultOrARetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts fakedaemon.Options
	}{
		{"a weaker tier in the answer", fakedaemon.Options{Tier: sandbox.IsolationKernel, ResultTier: sandbox.IsolationContainer}},
		{"an answer not bound to its request", fakedaemon.Options{StripRequestID: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := fakedaemon.Serve(t, tc.opts)
			cfg := local(d.URL)
			if tc.opts.Tier != sandbox.IsolationUnknown {
				cfg.MinimumIsolation = tc.opts.Tier
			}
			c := connect(t, cfg)
			if f := c.fail("run_code", map[string]any{"code": "1"}); f.Ran != "maybe" || !strings.Contains(f.Summary, "It was not retried") {
				t.Errorf("%+v", f)
			}
			if total, _ := d.Service.RunCounts(); total != 1 {
				t.Errorf("the daemon ran %d calls; the server must not send it again", total)
			}
		})
	}
}

func TestADaemonThatDoesNotAnswer(t *testing.T) {
	c := connect(t, local(fakedaemon.DownURL(t)))
	if f := c.fail("run_code", map[string]any{"code": "1"}); f.Ran != "no" {
		t.Errorf("run_code: %+v", f)
	}
	info := c.ok("server_info", nil)
	if info["daemon"] != nil || info["daemonError"] == "" || !strings.Contains(info["summary"].(string), "did not answer Describe") {
		t.Errorf("server_info: %v", info)
	}
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cfg, err := server.FromEnv(env(map[string]string{
		"PLIMSOLL_URL": " https://plimsoll.example ", "PLIMSOLL_TOKEN": "t", "PLIMSOLL_MIN_ISOLATION": "vm", "PLIMSOLL_TIMEOUT_MS": "60000",
		"PLIMSOLL_LANGUAGES": "javascript,python", "PLIMSOLL_MAX_SANDBOXES": "5", "PLIMSOLL_SOFTWARE_IDENTITY": "oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64),
	}))
	if err != nil || cfg.URL != "https://plimsoll.example" || cfg.MinimumIsolation != sandbox.IsolationVM || cfg.RunTimeout != time.Minute ||
		fmt.Sprint(cfg.Languages) != "[javascript python]" || cfg.MaxSandboxes != 5 || cfg.Software.Mode != sandbox.SoftwareExact {
		t.Errorf("FromEnv: %+v, %v", cfg, err)
	}
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{}, "PLIMSOLL_URL is not set"},
		{map[string]string{"PLIMSOLL_URL": "${user_config.daemon_url}"}, "placeholder the MCP host did not fill in"},
		{map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_TOKEN": "${user_config.token}"}, "PLIMSOLL_TOKEN is ${user_config.token}"},
		{map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_MIN_ISOLATION": "none"}, "vm, kernel, container or process"},
		{map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_LANGUAGES": "python,python"}, "once each"},
		{map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_TIMEOUT_MS": "0"}, "PLIMSOLL_TIMEOUT_MS must be whole milliseconds"},
		{map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_MAX_SANDBOXES": "17"}, "from 1 to 16"},
		{map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_TIMEOUT_MS": "18446744073759552"}, "PLIMSOLL_TIMEOUT_MS must be whole milliseconds"},
		{map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_INSECURE_HTTP": "true"}, "must be 1 or unset"},
		{map[string]string{"PLIMSOLL_URL": "http://127.0.0.1:1", "PLIMSOLL_SOFTWARE_IDENTITY": "not an identity"}, "PLIMSOLL_SOFTWARE_IDENTITY"},
	} {
		if _, err := server.FromEnv(env(tc.env)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.env, err, tc.want)
		}
	}
	if _, err := server.New(server.Config{URL: "http://127.0.0.1:1", RunTimeout: 75 * time.Second}); err == nil || !strings.Contains(err.Error(), "under the call timeout") {
		t.Errorf("a run timeout the call deadline cannot hold: %v", err)
	}
	if _, err := server.New(server.Config{URL: "http://plimsoll.example"}); err == nil {
		t.Error("cleartext to another host is refused without InsecureHTTP")
	}
}

func TestASandboxTheDaemonEndedBetweenCallsIsReopenedOnce(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	for _, s := range d.Provider.Opened() {
		s.End(sandbox.SessionExpired)
	}
	out := c.ok("run_code", map[string]any{"code": "x", "sandbox": h})
	if out["freshSandbox"] != true || out["stdout"] != "python 1: x" || !strings.Contains(fmt.Sprint(out["sandboxReplaced"]), "expired") {
		t.Errorf("the call after the daemon ended its sandbox, and why: %v", out)
	}
	if d.OpenSessions() != 1 {
		t.Errorf("%d sessions open", d.OpenSessions())
	}
}

// eventually waits for cond, as a background close takes a moment.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("never: %s", what)
}

// A call admitted before a close, waiting for its turn,
// must not reopen a sandbox once the close has won.
func TestACallWaitingWhenItsSandboxClosesRunsNothing(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	blocked := d.Provider.Blocked()
	first := make(chan map[string]any)
	go func() { first <- c.ok("run_code", map[string]any{"code": fakedaemon.Block, "sandbox": h}) }()
	<-blocked
	waiting := make(chan failure)
	go func() { waiting <- c.fail("run_code", map[string]any{"code": "after", "sandbox": h}) }()
	time.Sleep(100 * time.Millisecond) // the second call is admitted and waits for the turn
	closed := make(chan map[string]any)
	go func() { closed <- c.ok("close_sandbox", map[string]any{"sandbox": h}) }()
	time.Sleep(100 * time.Millisecond)
	d.Provider.Release()
	<-first
	if out := <-closed; out["deleted"] != true {
		t.Errorf("close_sandbox: %v", out)
	}
	if f := <-waiting; f.Ran != "no" || !strings.Contains(f.Summary, "closed while this call waited its turn") {
		t.Errorf("the waiting call: %+v", f)
	}
	if n := d.OpenSessions(); n != 0 {
		t.Errorf("%d sessions open: the waiting call opened a sandbox after the close", n)
	}
}

// A handle whose sandbox is replaced again and again holds no record of the closes once
// they finish, and neither does the server.
func TestReplacedSandboxesLeaveNoClosings(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"].(string)
	for range 5 {
		c.ok("run_code", map[string]any{"code": fakedaemon.EndsSession, "sandbox": h})
	}
	eventually(t, "every replaced sandbox's close finishes and is let go", func() bool {
		server, sandbox := server.ClosingsHeld(c.s, h)
		return server == 0 && sandbox == 0 && d.OpenSessions() == 0
	})
}

// A sandbox being closed holds its place under the cap until the daemon has deleted it:
// an open meanwhile is refused, and one after the close is answered.
func TestAClosingSandboxHoldsItsPlace(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, CloseDelay: 300 * time.Millisecond})
	cfg := local(d.URL)
	cfg.MaxSandboxes = 1
	c := connect(t, cfg)
	h := c.ok("open_sandbox", nil)["sandbox"]
	closed := make(chan map[string]any)
	go func() { closed <- c.ok("close_sandbox", map[string]any{"sandbox": h}) }()
	eventually(t, "the handle is taken out", func() bool { return server.SandboxesHeld(c.s) == 0 })
	if f := c.fail("open_sandbox", nil); f.Refusal != "capacity" || len(f.IdleSandboxes) != 0 {
		t.Errorf("an open while the only sandbox is being deleted: %+v", f)
	}
	if out := <-closed; out["deleted"] != true {
		t.Errorf("the close: %v", out)
	}
	c.ok("open_sandbox", nil)
}

// Opens at once hold their places, so they cannot pass the cap.
func TestOpensAtOnceStayWithinTheCap(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 8, OpenDelay: 300 * time.Millisecond})
	cfg := local(d.URL)
	cfg.MaxSandboxes = 1
	c := connect(t, cfg)
	results := make(chan *mcp.CallToolResult, 3)
	for range 3 {
		go func() { results <- c.call("open_sandbox", nil) }()
	}
	opened := 0
	for range 3 {
		if !(<-results).IsError {
			opened++
		}
	}
	if opened != 1 || d.OpenSessions() != 1 {
		t.Errorf("%d opens answered, %d sessions open; the cap is 1", opened, d.OpenSessions())
	}
}

// A session the client stopped (an answer it could not bind to its call)
// is closed on the daemon, not abandoned.
func TestAStoppedSessionIsClosedNotAbandoned(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, StripRequestID: true})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	f := c.fail("run_code", map[string]any{"code": "1", "sandbox": h})
	if f.Ran != "maybe" || f.SandboxUsable == nil || *f.SandboxUsable || !strings.Contains(f.Summary, "The handle still works") {
		t.Errorf("a call whose answer was not bound to it: %+v", f)
	}
	eventually(t, "the stopped session is closed on the daemon", func() bool { return d.OpenSessions() == 0 })
}

// Shutdown waits for every close, one started by a call that has already ended
// included: Close returns only once the daemon has deleted the stopped session.
func TestShutdownWaitsForABackgroundClose(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, StripRequestID: true, CloseDelay: 300 * time.Millisecond})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.fail("run_code", map[string]any{"code": "1", "sandbox": h}) // stopped, so closed in the background
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if n := d.OpenSessions(); n != 0 {
		t.Errorf("Close returned with %d sessions still open on the daemon", n)
	}
}

// recorder keeps nothing: every Record fails, as a full disk would.
type recorder struct{}

func (recorder) Record(*plimsollv1.RunRequest, *plimsollv1.RunResponse) error {
	return errors.New("the disk is full")
}
func (recorder) RecordUnanswered(*plimsollv1.RunRequest, *plimsollv1.RunRecord) error { return nil }
func (recorder) RecordClose(string, uint64, string) error                             { return nil }

// A result that checked but whose record could not be kept is still the
// result, with its record digest, and says the receipt failed.
func TestAFailedReceiptKeepsTheResult(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	cfg := local(d.URL)
	cfg.Recorder = recorder{}
	c := connect(t, cfg)
	out := c.ok("run_code", map[string]any{"code": "exit 2"})
	receipt, _ := out["receipt"].(map[string]any)
	if out["exitCode"] != float64(2) || out["recordSha256"] == "" || receipt["status"] != "failed" || !strings.Contains(out["summary"].(string), "keeping its record failed") {
		t.Errorf("fresh: %v", out)
	}
	c.ok("get_record", map[string]any{"recordSha256": out["recordSha256"]})
	h := c.ok("open_sandbox", nil)["sandbox"]
	first := c.ok("run_code", map[string]any{"code": "x = 1", "sandbox": h})
	second := c.ok("run_code", map[string]any{"code": "x", "sandbox": h})
	if first["receipt"].(map[string]any)["status"] != "failed" || first["freshSandbox"] != true || second["freshSandbox"] != nil {
		t.Errorf("in a sandbox: %v then %v", first, second)
	}
}

// After a call that may have run, the sandbox is not new.
func TestAfterAnUnansweredFirstCallTheSandboxIsNotNew(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.fail("run_code", map[string]any{"code": fakedaemon.Breaks, "sandbox": h})
	if out := c.ok("run_code", map[string]any{"code": "y", "sandbox": h}); out["freshSandbox"] != nil {
		t.Errorf("the call after one that may have run: %v", out)
	}
}

// A replaced sandbox runs what the daemon states now.
func TestAReplacedSandboxTakesTheDaemonsLanguagesNow(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	c.ok("run_code", map[string]any{"code": "1", "sandbox": h})
	d.Provider.SetSessionLanguages([]sandbox.Language{sandbox.LanguageJavaScript})
	for _, s := range d.Provider.Opened() {
		s.End(sandbox.SessionExpired)
	}
	if out := c.ok("run_code", map[string]any{"code": "2", "language": "javascript", "sandbox": h}); out["freshSandbox"] != true {
		t.Errorf("javascript in the replaced sandbox: %v", out)
	}
	if f := c.fail("run_code", map[string]any{"code": "3", "language": "python", "sandbox": h}); f.Ran != "no" || f.Refusal != "unsupported" {
		t.Errorf("python, which the replaced sandbox does not run: %+v", f)
	}
}

// A sandbox holds a bounded number of calls; more are refused, not queued.
func TestASandboxHoldsBoundedCalls(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4})
	c := connect(t, local(d.URL))
	h := c.ok("open_sandbox", nil)["sandbox"]
	blocked := d.Provider.Blocked()
	held := make(chan *mcp.CallToolResult, 4)
	go func() { held <- c.call("run_code", map[string]any{"code": fakedaemon.Block, "sandbox": h}) }()
	<-blocked
	for range 3 {
		go func() { held <- c.call("run_code", map[string]any{"code": "q", "sandbox": h}) }()
	}
	time.Sleep(150 * time.Millisecond)
	if f := c.fail("run_code", map[string]any{"code": "one too many", "sandbox": h}); f.Ran != "no" || f.Refusal != "capacity" {
		t.Errorf("a fifth call: %+v", f)
	}
	d.Provider.Release()
	for range 4 {
		if r := <-held; r.IsError {
			t.Errorf("a held call failed: %s", text(r))
		}
	}
}

// Guest output is arbitrary bytes. A cut lands on a rune boundary, moving back at most
// one rune: a long run of continuation bytes (never a rune's start) must not walk it
// back to the start of the output and hide everything before it behind truncated.
func TestCutMovesBackAtMostOneRune(t *testing.T) {
	hostile := "shown" + strings.Repeat("\x80", 20_000) + "hidden"
	kept, truncated := server.Cut(hostile, 16_000)
	if !truncated || len(kept) < 16_000-utf8.UTFMax || !strings.HasPrefix(kept, "shown") {
		t.Errorf("a run of continuation bytes: kept %d bytes %.8q, truncated %v", len(kept), kept, truncated)
	}
	if kept, truncated := server.Cut("abéc", 3); kept != "ab" || !truncated {
		t.Errorf("a rune cut in two is dropped whole: %q %v", kept, truncated)
	}
	if kept, truncated := server.Cut("abéc", 4); kept != "abé" || !truncated {
		t.Errorf("a cut on a boundary keeps the rune before it: %q %v", kept, truncated)
	}
	if kept, truncated := server.Cut("abé", 4); kept != "abé" || truncated {
		t.Errorf("output within the limit is whole: %q %v", kept, truncated)
	}
}

// Arguments the input schema refuses are answered by the SDK before the handler; the answer
// still has this server's shape: ran "no", refusal "request", and the SDK's reason.
func TestASchemaRefusalIsAStructuredFailure(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 1})
	c := connect(t, local(d.URL))
	f := c.fail("run_code", map[string]any{"code": "1", "sandbox": "not-a-handle"})
	if f.Ran != "no" || f.Refusal != "request" || !strings.Contains(f.Summary, "input schema") {
		t.Errorf("a handle the schema refuses: %+v", f)
	}
	g := c.fail("get_record", map[string]any{"recordSha256": "xyz"})
	if g.Ran != "no" || g.Refusal != "request" {
		t.Errorf("a digest the schema refuses: %+v", g)
	}
	// A 2026-07-28 host refuses a result without resultType, so the refusal must keep
	// what the SDK set (found in Claude Desktop on 2026-10-16: the answer was dropped).
	if v := c.cs.InitializeResult().ProtocolVersion; v < "2026-07-28" {
		t.Fatalf("the session negotiated %s; this check needs 2026-07-28 or later", v)
	}
	var answers int
	for _, line := range strings.Split(c.wire.String(), "\n") {
		if !strings.Contains(line, "input schema") {
			continue
		}
		answers++
		if !strings.Contains(line, `"resultType":"complete"`) {
			t.Errorf("a schema refusal without resultType on the wire: %s", line)
		}
	}
	if answers != 2 {
		t.Errorf("found %d refusals on the wire, want 2:\n%s", answers, c.wire.String())
	}
}

// A daemon whose sessions state no languages proved none: its sandbox is offered no
// language, so nothing is sent to it, where it used to be let try every one (review B9,
// 2026-10-23).
func TestASessionThatStatesNoLanguagesIsOfferedNone(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, SessionLanguages: []sandbox.Language{}})
	c := connect(t, local(d.URL))
	if f := c.fail("open_sandbox", nil); f.Ran != "no" {
		t.Fatalf("open_sandbox on a daemon whose sessions run no language: %+v", f)
	}
	if n := d.OpenSessions(); n != 0 {
		t.Errorf("%d sessions opened", n)
	}
}
