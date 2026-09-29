// Command sessions runs one session on an NVIDIA OpenShell sandbox through the real
// daemon, with the harness signing every call, and writes a page that shows the
// calls, their chained records, and the verifier accepting the signed bundle and
// refusing it with one call dropped or one byte changed.
//
// The session is a small edit loop: a project whose test fails, a snippet that
// patches the file in place, the same test passing without the files being sent
// again, a snippet that leaves a detached process behind, and a snippet that finds
// it gone. Files persist between calls; processes do not.
//
// It needs an OpenShell gateway (docker driver) and the five settings plimsolld
// reads for one; it spends nothing. Run it from the repository root:
//
//	SANDBOX_OPENSHELL_GATEWAY_URL=https://127.0.0.1:17670 \
//	SANDBOX_OPENSHELL_CA_FILE=... SANDBOX_OPENSHELL_CERT_FILE=... \
//	SANDBOX_OPENSHELL_KEY_FILE=... SANDBOX_OPENSHELL_IMAGE=plimsoll/sandbox:latest \
//	go run ./examples/sessions
//
// Writes docs/examples/sessions/index.html, and beside it the signed bundle
// (bundle.jsonl) and the harness's public key (harness.pub), so anyone can check
// the bundle: go run ./cmd/plimsoll-attest verify -pub harness.pub bundle.jsonl.
// The signing key exists only in this process's memory and is discarded.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

//go:embed page.html
var pageTemplate string

var gatewaySettings = []string{
	"SANDBOX_OPENSHELL_GATEWAY_URL", "SANDBOX_OPENSHELL_CA_FILE",
	"SANDBOX_OPENSHELL_CERT_FILE", "SANDBOX_OPENSHELL_KEY_FILE", "SANDBOX_OPENSHELL_IMAGE",
}

func main() {
	out := flag.String("out", filepath.Join("docs", "examples", "sessions", "index.html"), "the page to write; the bundle and key go beside it")
	flag.Parse()
	var missing []string
	for _, name := range gatewaySettings {
		if os.Getenv(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "this example needs an OpenShell gateway; set %s (docs/openshell.md)\n", strings.Join(missing, ", "))
		os.Exit(2)
	}
	if err := run(context.Background(), *out); err != nil {
		fmt.Fprintln(os.Stderr, "example failed:", err)
		os.Exit(1)
	}
}

// call is one call of the session as the page shows it.
type call struct {
	N        int
	Kind     string // snippet or project
	Intent   string // what the call is for, in a sentence
	Sent     string // the code, or the files and steps
	Result   string // exit status or outcome
	Output   string // an excerpt of what came back
	Millis   int64  // the call's round trip as the client measured it
	Record   string
	Previous string
	Request  string
	Resp     string
}

type check struct {
	What    string
	Pass    bool
	Verdict string
	Detail  string
}

type pageData struct {
	Date        string
	Provider    string
	Tier        string
	Environment string
	Policy      string
	Session     string
	Calls       []call
	Close       string
	Checks      []check
	KeyID       string
	Median      int64
	Chain       template.HTML
}

func run(ctx context.Context, out string) error {
	workDir, err := os.MkdirTemp("", "plimsoll-sessions-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)
	binary, err := daemonproc.Build(ctx, workDir)
	if err != nil {
		return err
	}
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	token := hex.EncodeToString(tok)
	d, err := daemonproc.Start(ctx, binary, []string{
		"SANDBOX_PROVIDER=openshell", "PLIMSOLL_TOKEN=" + token,
		"SANDBOX_MAX_SESSIONS=1", "SANDBOX_SESSION_LIFETIME=10m", "SANDBOX_SESSION_IDLE=5m", "SANDBOX_SESSION_DISK_MB=64",
	}, 2*time.Minute)
	if err != nil {
		return err
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = d.Stop(2 * time.Minute)
		}
	}()

	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var bundle bytes.Buffer
	remote, err := client.New(d.BaseURL, client.WithToken(token), client.WithRecorder(attest.NewHarness(attest.NewSigner(key), &bundle)))
	if err != nil {
		return err
	}
	info, err := remote.Describe(ctx)
	if err != nil {
		return err
	}
	if !info.SupportsSessions {
		return errors.New("the daemon states no sessions")
	}
	s, err := remote.OpenSession(ctx, client.SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		return err
	}
	fmt.Printf("session   | opened on %s at the %s tier (fingerprint %s…)\n", info.Sandbox, s.Isolation(), s.Fingerprint()[:16])

	data := pageData{
		Date: time.Now().UTC().Format("2006-01-02"), Provider: info.Sandbox, Tier: s.Isolation().String(),
		Environment: orNone(info.Environments.Project.Identity), Policy: orNone(info.Environments.Policy),
		Session: s.Fingerprint(), KeyID: attest.KeyID(pub),
	}
	add := func(kind, intent, sent string, t0 time.Time, result, output string, rec *sandbox.RunRecord) {
		c := call{N: len(data.Calls) + 1, Kind: kind, Intent: intent, Sent: sent, Result: result, Output: output, Millis: time.Since(t0).Milliseconds()}
		if rec != nil {
			c.Record, c.Previous, c.Request, c.Resp = rec.SHA256, rec.PreviousSHA256, rec.RequestSHA256, rec.ResultSHA256
		}
		data.Calls = append(data.Calls, c)
		fmt.Printf("call %d    | %s: %s (%d ms)\n", c.N, kind, result, c.Millis)
	}

	test := `const add = require("./lib.js");
if (add(2, 3) !== 5) { console.error("add(2, 3) =", add(2, 3), "but should be 5"); process.exit(1); }
console.log("test passed: add(2, 3) = 5");`
	t0 := time.Now()
	p1, err := s.RunProject(ctx, sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "lib.js", Content: "module.exports = (a, b) => a - b;\n"}, {Path: "test.js", Content: test + "\n"}},
		Steps: []string{"node test.js"},
	})
	if err != nil {
		return err
	}
	add("project", "Write lib.js and test.js, run the test. lib.js has a bug.",
		"files: lib.js, test.js\nstep:  node test.js", t0, projectVerdict(p1), projectOutput(p1), p1.Record)

	patch := `const fs = require("fs");
const path = "/tmp/work/lib.js";
fs.writeFileSync(path, fs.readFileSync(path, "utf8").replace("a - b", "a + b"));
console.log("patched " + path);`
	t0 = time.Now()
	r2, err := s.RunJavaScript(ctx, sandbox.Request{Code: patch})
	if err != nil {
		return err
	}
	add("snippet", "Fix the bug in place: the file the first call wrote is still there.", patch, t0, fmt.Sprintf("exit %d", r2.ExitCode), r2.Stdout+r2.Stderr, r2.Record)

	t0 = time.Now()
	p3, err := s.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"node test.js"}})
	if err != nil {
		return err
	}
	add("project", "Run the same test again. No files are sent: they persisted.", "step:  node test.js", t0, projectVerdict(p3), projectOutput(p3), p3.Record)

	leave := `const { spawn } = require("child_process");
const child = spawn("sleep", ["600"], { detached: true, stdio: "ignore" });
child.unref();
console.log("started sleep 600 as pid " + child.pid + " and exited");`
	t0 = time.Now()
	r4, err := s.RunJavaScript(ctx, sandbox.Request{Code: leave})
	if err != nil {
		return err
	}
	add("snippet", "Leave a detached process behind, as careless or hostile code might.", leave, t0, fmt.Sprintf("exit %d", r4.ExitCode), r4.Stdout+r4.Stderr, r4.Record)

	look := `const fs = require("fs");
const left = [];
for (const d of fs.readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(d)) continue;
  let cmd = "";
  try { cmd = fs.readFileSync("/proc/" + d + "/cmdline", "latin1").split("\0").join(" ").trim(); } catch { continue; }
  if (cmd === "sleep 600") left.push(+d);
}
console.log("sleep 600 still running: " + (left.length ? left.join(", ") : "none"));
console.log("lib.js now: " + fs.readFileSync("/tmp/work/lib.js", "utf8").trim());`
	t0 = time.Now()
	r5, err := s.RunJavaScript(ctx, sandbox.Request{Code: look})
	if err != nil {
		return err
	}
	add("snippet", "Look for that process, and read lib.js once more.", look, t0, fmt.Sprintf("exit %d", r5.ExitCode), r5.Stdout+r5.Stderr, r5.Record)
	if !strings.Contains(r5.Stdout, "still running: none") || !strings.Contains(r5.Stdout, "a + b") {
		return fmt.Errorf("the session did not behave as a session should: %q", r5.Stdout)
	}

	sum, err := s.Close(ctx)
	if err != nil {
		return err
	}
	data.Close = fmt.Sprintf("closed after %d calls; last record %s", sum.Calls, sum.LastRecordSHA256)
	stopped = true
	if err := d.Stop(2 * time.Minute); err != nil {
		return err
	}

	entries, err := attest.ReadBundle(bytes.NewReader(bundle.Bytes()))
	if err != nil {
		return err
	}
	v := attest.NewVerifier(pub)
	data.Checks = append(data.Checks, verify("The bundle as the harness wrote it", entries, v))
	var dropped []attest.Entry
	for i, e := range entries {
		if i != 2 {
			dropped = append(dropped, e)
		}
	}
	data.Checks = append(data.Checks, verify("The same bundle with call 3 removed", dropped, v))
	edited, err := editOutput(entries, 1, "patched", "Patched")
	if err != nil {
		return err
	}
	data.Checks = append(data.Checks, verify("The same bundle with one byte of call 2's output changed", edited, v))
	if !data.Checks[0].Pass || data.Checks[1].Pass || data.Checks[2].Pass {
		return fmt.Errorf("the verifier did not accept the bundle and refuse both edits: %+v", data.Checks)
	}
	data.Median = median(data.Calls)
	data.Chain = chainSVG(data.Calls)

	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.jsonl"), bundle.Bytes(), 0o644); err != nil {
		return err
	}
	_, pubPEM, err := publicPEM(pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "harness.pub"), pubPEM, 0o644); err != nil {
		return err
	}
	tmpl, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		return err
	}
	var page bytes.Buffer
	if err := tmpl.Execute(&page, data); err != nil {
		return err
	}
	if err := os.WriteFile(out, page.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("page      | wrote %s, with bundle.jsonl and harness.pub beside it\n", out)
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(none stated)"
	}
	return s
}

func projectVerdict(p sandbox.ProjectResult) string {
	if len(p.Steps) == 0 {
		return p.Outcome.String()
	}
	return fmt.Sprintf("%s, step exited %d", p.Outcome, p.Steps[len(p.Steps)-1].ExitCode)
}

func projectOutput(p sandbox.ProjectResult) string {
	var b strings.Builder
	for _, st := range p.Steps {
		b.WriteString(st.Stdout)
		b.WriteString(st.Stderr)
	}
	return b.String()
}

func verify(what string, entries []attest.Entry, v *attest.Verifier) check {
	rep, err := attest.VerifyBundle(entries, v)
	if err != nil {
		return check{What: what, Verdict: "refused", Detail: err.Error()}
	}
	return check{What: what, Pass: true, Verdict: "verified",
		Detail: fmt.Sprintf("%d entries; one session of %d calls, every record signed, chained and closed", len(entries), rep.Sessions[0].Calls)}
}

// editOutput returns a copy of entries whose i-th stored response has old replaced
// by new in its snippet output: what a tampered copy of the bundle looks like.
func editOutput(entries []attest.Entry, i int, old, new string) ([]attest.Entry, error) {
	out := append([]attest.Entry(nil), entries...)
	resp := &plimsollv1.RunResponse{}
	if err := proto.Unmarshal(out[i].Response, resp); err != nil {
		return nil, err
	}
	js := resp.GetJavascript()
	if js == nil {
		return nil, errors.New("call 2 is not a snippet")
	}
	js.Stdout = []byte(strings.Replace(string(js.GetStdout()), old, new, 1))
	b, err := proto.Marshal(resp)
	if err != nil {
		return nil, err
	}
	out[i].Response = b
	return out, nil
}

func median(calls []call) int64 {
	ms := make([]int64, 0, len(calls))
	for _, c := range calls {
		ms = append(ms, c.Millis)
	}
	for i := range ms {
		for j := i + 1; j < len(ms); j++ {
			if ms[j] < ms[i] {
				ms[i], ms[j] = ms[j], ms[i]
			}
		}
	}
	return ms[len(ms)/2]
}
