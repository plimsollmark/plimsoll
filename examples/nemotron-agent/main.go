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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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
	suite := flag.String("suite", "", "run a batch instead of one task: a suite file (suite/tasks.json); -models, -only, -tries, -parallel and -suite-out apply")
	models := flag.String("models", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B,nvidia/Nemotron-3_5-Lightning,nvidia/nemotron-3-super-120b-a12b,nvidia/Nemotron-3-Ultra-550b-a55b", "the batch's models, comma-separated")
	only := flag.String("only", "", "the batch's task ids, comma-separated (default: every task)")
	tries := flag.Int("tries", 3, "the batch's tries per task and model, one session each")
	parallel := flag.Int("parallel", 4, "the batch's sessions at once")
	budget := flag.Float64("budget", 0, "the batch's spending limit in dollars at list price (required with -suite): no session starts once the spend so far plus a worst-case reserve for the sessions in flight would pass it")
	tokenCap := flag.Int("token-cap", 400000, "the batch's per-session cap on prompt plus completion tokens, the same for every model")
	suiteOut := flag.String("suite-out", filepath.Join("docs", "examples", "nemotron-agent", "batch"), "the batch's directory: results.json, the public keys, and each session's bundle and transcript")
	render := flag.Bool("render", false, "rewrite the page from the transcript beside it and the batch's results (-suite-out), calling no model")
	flag.Parse()
	titles := *suite
	if titles == "" {
		titles = filepath.Join("examples", "nemotron-agent", "suite", "tasks.json")
	}
	if *render {
		if err := renderOnly(*out, *suiteOut, titles); err != nil {
			fmt.Fprintln(os.Stderr, "render failed:", err)
			os.Exit(1)
		}
		return
	}
	key := os.Getenv("NEBIUS_API_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "set NEBIUS_API_KEY (a Nebius Token Factory key; it is read from the environment and never written)")
		os.Exit(2)
	}
	// The daemon this program starts inherits its environment; it has no use for the key.
	_ = os.Unsetenv("NEBIUS_API_KEY")
	if *suite != "" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := runSuite(ctx, *base, key, *suite, *models, *only, *tries, *parallel, *maxTurns, *daemon, *runtime, *image, *suiteOut, *budget, *tokenCap); err != nil {
			fmt.Fprintln(os.Stderr, "batch failed:", err)
			os.Exit(1)
		}
		return
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
	ev, err := agent(ctx, m, remote, task, maxTurns, func(f string, a ...any) { fmt.Printf(f, a...) }, nil)
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
	batch, err := readBatch(filepath.Join(dir, "batch"), "batch", filepath.Join("examples", "nemotron-agent", "suite", "tasks.json"))
	if err != nil {
		return err
	}
	page, err := renderPage(ev, batch)
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
	Answered     bool
	CloseError   string  `json:",omitempty"`
	Grader       *runRow `json:",omitempty"`
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

// closeTimeout is how long a session's close may take, counted from the close.
var closeTimeout = 2 * time.Minute

// lengthNudge follows a reply that reached the token limit with nothing in it.
const lengthNudge = "Your last reply reached the length limit before any answer or tool call. Continue, more briefly."

// maxToolOutput is what of a run's output goes back to the model, per stream.
const maxToolOutput = 8 << 10

// agent opens the session and runs the loop; the harness on remote signs every call.
// say prints progress. after, when set, runs in the session once the loop has ended and
// before the session closes, so what it runs is recorded and signed in the same chain.
func agent(ctx context.Context, m *chat, remote *client.Remote, task string, maxTurns int, say func(string, ...any), after func(context.Context, *client.Session, []sandbox.Language, *evidence) error) (*evidence, error) {
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
	sess, err := whenAdmitted(ctx, func() (*client.Session, error) {
		return remote.OpenSession(ctx, client.SessionOptions{MinimumIsolation: sandbox.IsolationContainer, Languages: langs})
	})
	if err != nil {
		return nil, err
	}
	ev := &evidence{Task: task, Provider: info.Sandbox, Tier: sess.Isolation().String(), Environment: info.SessionEnvironment.Identity, Session: sess.Fingerprint()}
	if ev.Environment == "" {
		ev.Environment = "none stated"
	}
	say("session   | opened on %s at the %s tier (fingerprint %s…)\n", info.Sandbox, ev.Tier, ev.Session[:16])
	messages := []message{{Role: "system", Content: systemPrompt}, {Role: "user", Content: task}}
	tools := []tool{runCodeTool(langs)}
	defer func() {
		// The close gets its own two minutes from the moment it starts: a deadline taken
		// when the session opened had passed by the close of any session longer than that,
		// which then had no signed close and so no verifiable bundle.
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
		defer cancel()
		sum, err := sess.Close(closeCtx)
		if err != nil {
			// Without a signed close a verifier cannot rule out a cut session, so the bundle
			// will not verify; the reason is kept where the page and the batch can show it.
			ev.CloseError = err.Error()
			say("close     | %v\n", err)
			return
		}
		ev.Calls = sum.Calls
	}()
	for t := 1; t <= maxTurns; t++ {
		if m.tokenCap > 0 && m.usage.Prompt+m.usage.Completion >= m.tokenCap {
			ev.Final = fmt.Sprintf("(the agent reached the session's cap of %d tokens without a final answer)", m.tokenCap)
			say("turn %-4d | token cap reached\n", t)
			return ev, finish(ctx, after, sess, langs, ev)
		}
		reply, err := m.complete(ctx, messages, tools)
		if err != nil {
			return nil, fmt.Errorf("turn %d: %w", t, err)
		}
		messages = append(messages, reply)
		tr := turn{N: t, Text: reply.Content}
		if len(reply.ToolCalls) == 0 && strings.TrimSpace(reply.Content) == "" && reply.Finish == "length" && t < maxTurns {
			// Cut off at the token budget before any answer or tool call: the same nudge for
			// every model, and the turn counts against its budget.
			messages = append(messages, message{Role: "user", Content: lengthNudge})
			tr.Text = "(the reply reached the token limit with no answer and no tool call; the program asked the model to continue, more briefly)"
			ev.Turns = append(ev.Turns, tr)
			say("turn %-4d | cut off at the token limit; asked to continue\n", t)
			continue
		}
		if len(reply.ToolCalls) == 0 {
			ev.Final = reply.Content
			ev.Answered = true
			ev.Turns = append(ev.Turns, tr)
			say("turn %-4d | the model answered without a run\n", t)
			return ev, finish(ctx, after, sess, langs, ev)
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
				if errors.Is(err, errLanguage) {
					result["error"] = err.Error()
					b, _ := json.Marshal(result)
					messages = append(messages, message{Role: "tool", ToolCallID: call.ID, Name: "run_code", Content: string(b)})
					say("turn %-4d | %v\n", t, err)
					continue
				}
				if err != nil {
					// The client's checks failed or the session ended: the model is told, the
					// loop ends, and the page says so. Nothing unverified is reported as run.
					return nil, fmt.Errorf("run %d: %w", len(ev.Runs)+1, err)
				}
				ev.Runs = append(ev.Runs, r)
				tr.Runs = append(tr.Runs, r.N)
				result = map[string]any{"exit_code": r.ExitCode, "timed_out": r.TimedOut, "stdout": clip(r.Stdout, maxToolOutput), "stderr": clip(r.Stderr, maxToolOutput), "record_sha256": r.Record, "isolation": ev.Tier}
				say("run %-5d | %s, exit %d, %d ms, record %s…\n", r.N, r.Language, r.ExitCode, r.Millis, r.Record[:16])
			}
			b, _ := json.Marshal(result)
			messages = append(messages, message{Role: "tool", ToolCallID: call.ID, Name: "run_code", Content: string(b)})
		}
		ev.Turns = append(ev.Turns, tr)
	}
	ev.Final = fmt.Sprintf("(the agent reached its budget of %d turns without a final answer)", maxTurns)
	return ev, finish(ctx, after, sess, langs, ev)
}

// finish runs after, when there is one, in the still-open session.
func finish(ctx context.Context, after func(context.Context, *client.Session, []sandbox.Language, *evidence) error, sess *client.Session, langs []sandbox.Language, ev *evidence) error {
	if after == nil {
		return nil
	}
	return after(ctx, sess, langs, ev)
}

// errLanguage is a run_code call naming a language the session does not run; the model
// is told, and nothing runs.
var errLanguage = errors.New("unknown language")

// pickLanguage reads the language a model named, with the usual aliases. It never falls
// back to another language: code run under the wrong interpreter fails for a reason that
// is the harness's, not the model's.
func pickLanguage(name string, langs []sandbox.Language) (sandbox.Language, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "py", "python3", "python 3", "py3":
		n = "python"
	case "js", "node", "nodejs", "node.js":
		n = "javascript"
	}
	for _, l := range langs {
		if string(l) == n {
			return l, nil
		}
	}
	names := make([]string, len(langs))
	for i, l := range langs {
		names[i] = string(l)
	}
	return "", fmt.Errorf("%w %q: run_code takes one of %s", errLanguage, name, strings.Join(names, ", "))
}

// runOnce runs one cell in the session and keeps what the record states.
func runOnce(ctx context.Context, sess *client.Session, langs []sandbox.Language, language, code string, n int) (runRow, error) {
	lang, err := pickLanguage(language, langs)
	if err != nil {
		return runRow{}, err
	}
	start := time.Now()
	res, err := whenAdmitted(ctx, func() (sandbox.CellResult, error) {
		start = time.Now()
		return sess.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: code, Timeout: 60 * time.Second, MinimumIsolation: sandbox.IsolationContainer})
	})
	if err != nil {
		return runRow{}, err
	}
	r := runRow{N: n, Language: string(lang), Code: code, ExitCode: res.ExitCode, TimedOut: res.TimedOut, Stdout: res.Stdout, Stderr: res.Stderr, Millis: time.Since(start).Milliseconds()}
	if res.Record != nil {
		r.Record, r.Request, r.Result, r.Previous, r.Sequence = res.Record.SHA256, res.Record.RequestSHA256, res.Record.ResultSHA256, res.Record.PreviousSHA256, res.Record.Sequence
	}
	return r, nil
}

// admitRetries and admitPause bound the wait on a refusal the daemon marks as capacity
// (admission full, or the per-caller rate limit). Such a refusal is marked as sent before
// any code was dispatched, so asking again is safe and the session stays usable. The pause
// doubles from 2 s: five retries wait about a minute, one window of the rate limit. Before
// this, the batch recorded 46 of its 120 sessions as errors on this refusal (2026-10-27).
const admitRetries = 5

var admitPause = 2 * time.Second

func whenAdmitted[T any](ctx context.Context, f func() (T, error)) (T, error) {
	pause := admitPause
	for i := 0; ; i++ {
		v, err := f()
		if reason, marked := sandbox.NotDispatchedReason(err); err == nil || !marked || reason != sandbox.RefusalCapacity || i == admitRetries {
			return v, err
		}
		select {
		case <-ctx.Done():
			return v, err
		case <-time.After(pause):
		}
		pause *= 2
	}
}

// plural picks the word for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
