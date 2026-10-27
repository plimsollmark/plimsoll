// Command nemotron-agent is a coding agent on an NVIDIA Nemotron model served by Nebius
// Token Factory, whose only tool runs code in a plimsoll session behind gVisor. Every run
// the agent makes leaves a signed run record (what was sent, what came back, where it
// ran) in a bundle the page writes beside itself; anyone can recheck the bundle offline
// with the public key, so the agent's "it passed" is evidence, not its word.
//
// It starts plimsolld on the docker provider under gVisor (runsc) with the Python image,
// opens one session, gives the model the task, and loops: the model writes code, the
// code runs in the session, the result goes back to the model, until the model answers
// without a tool call or the turn budget ends. The harness signs each call as the client
// makes it, and the session's close is signed too. Run it from the repository root:
//
//	NEBIUS_API_KEY=... go run ./examples/nemotron-agent -task "..."
//
// Writes docs/examples/nemotron-agent/index.html, and beside it bundle.jsonl,
// harness.pub and transcript.json. The signing key exists only in this process's memory.
// Nothing here is attestation: the tier is the daemon's configuration and provider
// evidence plus its startup checks.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

//go:embed page.html
var pageTemplate string

// defaultTask is a task with a wrong first attempt built in: the agent has to run the
// code to find out, which is the point.
const defaultTask = `Write a Python function days_between(a, b) that returns the number of days between two ISO dates given as strings, handling leap years, then test it on ("2024-02-28", "2024-03-01") and ("2023-02-28", "2023-03-01") and on a pair spanning a year boundary. Run your tests. Report the results you actually observed.`

func main() {
	task := flag.String("task", defaultTask, "the task the agent is given")
	model := flag.String("model", "nvidia/Nemotron-3_5-Lightning", "the Nemotron model on Nebius Token Factory")
	base := flag.String("base", "https://api.tokenfactory.nebius.com/v1", "the OpenAI-compatible API base")
	daemon := flag.String("daemon", "", "a running plimsolld to use instead of starting one (its token in PLIMSOLL_TOKEN)")
	runtime := flag.String("runtime", "runsc", "the docker runtime for the daemon this program starts: runsc (gVisor) or runc")
	image := flag.String("image", "plimsoll/sandbox-python:latest", "the session image for the daemon this program starts")
	maxTurns := flag.Int("max-turns", 8, "the most model turns the agent takes")
	out := flag.String("out", filepath.Join("docs", "examples", "nemotron-agent", "index.html"), "the page to write; the bundle, key and transcript go beside it")
	flag.Parse()
	key := os.Getenv("NEBIUS_API_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "set NEBIUS_API_KEY (a Nebius Token Factory key; it is read from the environment and never written)")
		os.Exit(2)
	}
	m := &chat{base: *base, key: key, model: *model, http: &http.Client{Timeout: 4 * time.Minute}}
	if err := run(context.Background(), m, *task, *daemon, *runtime, *image, *maxTurns, *out); err != nil {
		fmt.Fprintln(os.Stderr, "example failed:", err)
		os.Exit(1)
	}
}

// run starts (or reaches) the daemon, opens the session, runs the agent, verifies the
// bundle and writes the page.
func run(ctx context.Context, m *chat, task, daemonURL, runtime, image string, maxTurns int, out string) error {
	token := os.Getenv("PLIMSOLL_TOKEN")
	if daemonURL == "" {
		workDir, err := os.MkdirTemp("", "plimsoll-nemotron-")
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
		token = hex.EncodeToString(tok)
		d, err := daemonproc.Start(ctx, binary, daemonproc.Options{Env: []string{
			"SANDBOX_PROVIDER=docker", "SANDBOX_DOCKER_RUNTIME=" + runtime, "SANDBOX_DOCKER_PROJECT_IMAGE=" + image,
			"PLIMSOLL_TOKEN=" + token, "SANDBOX_MAX_SESSIONS=1", "SANDBOX_SESSION_LIFETIME=30m",
			"SANDBOX_SESSION_IDLE=10m", "SANDBOX_SESSION_DISK_MB=64",
		}, Ready: 3 * time.Minute})
		if err != nil {
			return err
		}
		defer func() { _ = d.Stop(2 * time.Minute) }()
		daemonURL = d.BaseURL
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var bundle bytes.Buffer
	harness := attest.NewHarness(attest.NewSigner(key), &bundle)
	opts := []client.Option{client.WithRecorder(harness)}
	if token != "" {
		opts = append(opts, client.WithToken(token))
	}
	remote, err := client.New(daemonURL, opts...)
	if err != nil {
		return err
	}
	ev, err := agent(ctx, m, remote, task, maxTurns)
	if err != nil {
		return err
	}
	if err := harness.Checkpoint(); err != nil {
		return err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundle.Bytes()))
	if err != nil {
		return err
	}
	rep, verr := attest.VerifyBundle(entries, attest.NewVerifier(pub))
	ev.Verified = verr == nil
	if verr != nil {
		ev.VerifyDetail = verr.Error()
	} else {
		ev.VerifyDetail = fmt.Sprintf("%d lines, %d %s; the session's chain of %d calls closed", len(entries), len(rep.Sessions), plural(len(rep.Sessions), "session", "sessions"), ev.Calls)
	}
	ev.KeyID = attest.KeyID(pub)
	ev.Usage = m.usage
	ev.Model = m.model
	ev.Date = time.Now().UTC().Format("2006-01-02")
	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	transcript, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{"bundle.jsonl": bundle.Bytes(), "harness.pub": pubPEM, "transcript.json": transcript} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	page, err := renderPage(ev)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, page, 0o644); err != nil {
		return err
	}
	fmt.Printf("done      | %d runs, %d model calls, %d prompt and %d completion tokens; bundle %s; page %s\n",
		len(ev.Runs), m.usage.Calls, m.usage.Prompt, m.usage.Completion, verdict(ev.Verified), out)
	if !ev.Verified {
		return errors.New("the bundle did not verify: " + ev.VerifyDetail)
	}
	return nil
}

func verdict(ok bool) string {
	if ok {
		return "verified"
	}
	return "NOT verified"
}

// evidence is everything the page shows and transcript.json keeps.
type evidence struct {
	Date         string
	Model        string
	Task         string
	Provider     string
	Tier         string
	Environment  string
	Session      string
	Turns        []turn
	Runs         []runRow
	Final        string
	Calls        uint64
	Verified     bool
	VerifyDetail string
	KeyID        string
	Usage        usage
}

// turn is one assistant message of the conversation: its text, and the runs its tool
// calls made (by their number).
type turn struct {
	N    int
	Text string
	Runs []int
}

// run is one tool call: the code, what came back, and the signed record's digests.
type runRow struct {
	N        int
	Language string
	Code     string
	ExitCode int
	TimedOut bool
	Stdout   string
	Stderr   string
	Millis   int64
	Record   string
	Request  string
	Result   string
	Previous string
	Sequence uint64
}

// runCodeTool is the one tool: run code in the session, in one of its languages.
func runCodeTool(langs []sandbox.Language) tool {
	var t tool
	t.Type = "function"
	t.Function.Name = "run_code"
	t.Function.Description = "Run code in the sandbox. Files and interpreter state persist between calls in the same language; processes do not. Returns the exit code, stdout, stderr, whether it timed out, and the SHA-256 of the signed run record."
	names := make([]string, len(langs))
	for i, l := range langs {
		names[i] = string(l)
	}
	t.Function.Parameters = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"language": map[string]any{"type": "string", "enum": names},
			"code":     map[string]any{"type": "string", "description": "the code to run"},
		},
		"required": []string{"language", "code"},
	}
	return t
}

const systemPrompt = `You are a careful coding agent. You have one tool, run_code, which runs code in a sandbox that keeps files and interpreter state between calls in the same language. Write code, run it, read the real output, fix what is wrong and run again. When the task is done, answer in plain words with what you ran and what you observed, quoting the actual output. Never claim a result you did not run. Keep each run small.`

// maxToolOutput is what of a run's output goes back to the model, per stream.
const maxToolOutput = 8 << 10

// agent opens the session and runs the loop; the harness on remote signs every call.
func agent(ctx context.Context, m *chat, remote *client.Remote, task string, maxTurns int) (*evidence, error) {
	info, err := remote.Describe(ctx)
	if err != nil {
		return nil, err
	}
	if !info.SupportsSessions {
		return nil, errors.New("the daemon states no sessions; this agent needs one (SANDBOX_MAX_SESSIONS)")
	}
	langs := info.SessionEnvironment.Languages
	if len(langs) == 0 {
		return nil, errors.New("the daemon states no session languages")
	}
	sess, err := remote.OpenSession(ctx, client.SessionOptions{MinimumIsolation: sandbox.IsolationContainer, Languages: langs})
	if err != nil {
		return nil, err
	}
	ev := &evidence{Task: task, Provider: info.Sandbox, Tier: sess.Isolation().String(), Environment: info.SessionEnvironment.Identity, Session: sess.Fingerprint()}
	if ev.Environment == "" {
		ev.Environment = "none stated"
	}
	fmt.Printf("session   | opened on %s at the %s tier (fingerprint %s…)\n", info.Sandbox, ev.Tier, ev.Session[:16])
	messages := []message{{Role: "system", Content: systemPrompt}, {Role: "user", Content: task}}
	tools := []tool{runCodeTool(langs)}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	defer func() {
		if sum, err := sess.Close(closeCtx); err == nil {
			ev.Calls = sum.Calls
		}
	}()
	for t := 1; t <= maxTurns; t++ {
		reply, err := m.complete(ctx, messages, tools)
		if err != nil {
			return nil, fmt.Errorf("turn %d: %w", t, err)
		}
		messages = append(messages, reply)
		tr := turn{N: t, Text: reply.Content}
		if len(reply.ToolCalls) == 0 {
			ev.Final = reply.Content
			ev.Turns = append(ev.Turns, tr)
			fmt.Printf("turn %-4d | the model answered without a run\n", t)
			return ev, nil
		}
		for _, call := range reply.ToolCalls {
			var args struct {
				Language string `json:"language"`
				Code     string `json:"code"`
			}
			result := map[string]any{}
			if call.Function.Name != "run_code" || json.Unmarshal([]byte(call.Function.Arguments), &args) != nil || args.Code == "" {
				result["error"] = "the only tool is run_code(language, code); the arguments did not fit"
			} else {
				r, err := runOnce(ctx, sess, langs, args.Language, args.Code, len(ev.Runs)+1)
				if err != nil {
					// The client's checks failed or the session ended: the model is told, the
					// loop ends, and the page says so. Nothing unverified is reported as run.
					return nil, fmt.Errorf("run %d: %w", len(ev.Runs)+1, err)
				}
				ev.Runs = append(ev.Runs, r)
				tr.Runs = append(tr.Runs, r.N)
				result = map[string]any{"exit_code": r.ExitCode, "timed_out": r.TimedOut, "stdout": clip(r.Stdout, maxToolOutput), "stderr": clip(r.Stderr, maxToolOutput), "record_sha256": r.Record, "isolation": ev.Tier}
				fmt.Printf("run %-5d | %s, exit %d, %d ms, record %s…\n", r.N, r.Language, r.ExitCode, r.Millis, r.Record[:16])
			}
			b, _ := json.Marshal(result)
			messages = append(messages, message{Role: "tool", ToolCallID: call.ID, Name: "run_code", Content: string(b)})
		}
		ev.Turns = append(ev.Turns, tr)
	}
	ev.Final = fmt.Sprintf("(the agent reached its budget of %d turns without a final answer)", maxTurns)
	return ev, nil
}

// runOnce runs one cell in the session and keeps what the record states.
func runOnce(ctx context.Context, sess *client.Session, langs []sandbox.Language, language, code string, n int) (runRow, error) {
	lang := sandbox.Language(strings.ToLower(strings.TrimSpace(language)))
	known := false
	for _, l := range langs {
		known = known || l == lang
	}
	if !known {
		lang = langs[0]
	}
	start := time.Now()
	res, err := sess.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: code, Timeout: 60 * time.Second, MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		return runRow{}, err
	}
	r := runRow{N: n, Language: string(lang), Code: code, ExitCode: res.ExitCode, TimedOut: res.TimedOut, Stdout: res.Stdout, Stderr: res.Stderr, Millis: time.Since(start).Milliseconds()}
	if res.Record != nil {
		r.Record, r.Request, r.Result, r.Previous, r.Sequence = res.Record.SHA256, res.Record.RequestSHA256, res.Record.ResultSHA256, res.Record.PreviousSHA256, res.Record.Sequence
	}
	return r, nil
}

func renderPage(ev *evidence) ([]byte, error) {
	tmpl, err := template.New("page").Funcs(template.FuncMap{"short": func(s string) string {
		if len(s) > 16 {
			return s[:16] + "…"
		}
		return s
	}}).Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ev); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// plural picks the word for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
