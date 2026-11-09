package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// A rebuild is one fresh agent in one fresh plimsoll session: the caller's model, the brief
// (the course and, unless it is the control, the recipe), and three tools. Every call it makes
// into its sandbox is signed, the brief included, so what the rebuild held is evidence, and the
// leak scan reads it. The model itself runs outside plimsoll: what it was sent is the brief this
// program wrote, which the page shows, and the scan cannot see inside the model.

// rebuildSpec says which rebuild to make.
type rebuildSpec struct {
	Course, Group string
	N             int
	Recipe        string // as the rebuild is given it; "" for the control group
	Scrambled     bool   // the recipe is its loop's with the words shuffled
	Turns         int
	FlightsPerFly int
	FlyCalls      int
	AskAfter      bool
	// Avoid are the sealed seeds: a new practice seed is never one of them, so no practice run
	// holds a sealed seed even by a one-in-fifty-million chance.
	Avoid map[uint32]bool
}

func (s rebuildSpec) trace(purpose string) string {
	return fmt.Sprintf("sq.%s.%s.%d.%s", s.Course, s.Group, s.N, purpose)
}

// Built is what a rebuild left, as run.json keeps it beside the bundle.
type Built struct {
	Course   string `json:"course"`
	Group    string `json:"group"`
	N        int    `json:"n"`
	Session  string `json:"session"`
	Turns    int    `json:"turns"`
	Runs     int    `json:"runs"`      // run_code and write_file calls
	FlyCalls int    `json:"fly_calls"` // practice runs started, in separate sandboxes
	Flights  int    `json:"flights"`   // practice flights flown
	Final    string `json:"final"`     // the model's last words, clipped
	// Ended says why the conversation stopped: answered (the model stopped calling tools),
	// turns, prompt_cap, budget, refusal, model_error, or harness_fault (a call into the
	// sandbox failed with no answer, so the session the agent had is not the one designed).
	Ended string `json:"ended,omitempty"`
	// ControllerFrom is where the graded controller.js came from: write_file (exactly the last
	// write_file of it), changed (the session's file differs from the last write_file), or none.
	ControllerFrom string `json:"controller_from,omitempty"`
	Problem        string `json:"problem,omitempty"`
}

// Transcript is one rebuild's whole conversation as the harness held it: what was sent, every
// answer with its reasoning summary and tool calls, every tool result, the controller graded and
// the answer to the question asked after. The model runs outside plimsoll, so this is the
// harness's account, unsigned; the controller's digest ties it to the signed grading runs.
type Transcript struct {
	Course     string           `json:"course"`
	Group      string           `json:"group"`
	N          int              `json:"n"`
	Recipe     string           `json:"recipe"`
	Scrambled  bool             `json:"scrambled,omitempty"`
	System     string           `json:"system"`
	Prompt     string           `json:"prompt"`
	Turns      []TranscriptTurn `json:"turns"`
	Controller string           `json:"controller"`
	SHA256     string           `json:"controller_sha256"`
	From       string           `json:"controller_from"`
	Question   string           `json:"question,omitempty"`
	After      *answer          `json:"after,omitempty"`
	AfterError string           `json:"after_error,omitempty"`
	Ended      string           `json:"ended"`
}

// TranscriptTurn is one model answer and the results of the tool calls it made.
type TranscriptTurn struct {
	Answer  answer       `json:"answer"`
	Results []toolResult `json:"results,omitempty"`
}

// systemPrompt is the same for every rebuild.
const systemPrompt = `You are building a flight controller in a Linux sandbox. You have three tools. write_file writes a file into your work directory. run_code runs JavaScript or Python in your sandbox; files persist between calls. fly flies controller.js from your work directory in a separate sandbox that holds the simulator and answers with each flight's result; it flies controller.js only as your last write_file of it left it, so write controller.js with write_file. Read API.md first. Build, fly, read the results, fix, and fly again.`

// brief is the user prompt, after the hackathon's reproducer prompt (did-it-learn
// loop/reproduce.py), with the fly tool where the hackathon had the simulator.
func brief(course, recipe string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are building a flight controller for %s, in a Linux sandbox.\n\n", courseIDs[course])
	b.WriteString(courseFile("API-" + course + ".md"))
	b.WriteString("\nYour artifact lives at controller.js in your work directory.\n")
	if recipe != "" {
		b.WriteString("A builder before you worked on exactly this task for a long time. Everything it learned was compressed into this recipe, which is all you get from it:\n\n    " + recipe + "\n\nBuild controller.js following the recipe. ")
	} else {
		b.WriteString("Build the best one you can in controller.js. ")
	}
	b.WriteString("You may fly the smoke flights and any new flights you choose; you will not see the flights you are graded on. Leave your best version in controller.js, and end your reply with one line: SMOKE=<passed>/4.")
	return b.String()
}

// afterQuestion is asked once a rebuild's controller has been read, with no tool run: point 7
// of the rules this was built under, a treatment the model may skip is asked about.
func afterQuestion(recipe string) string {
	q := "Your session is over. Nothing you do now changes your controller or its score, and no tool will run. In a few sentences: "
	if recipe != "" {
		return q + "did you follow the recipe you were given? Which parts did you use, which did you change or leave out, and why?"
	}
	return q + "what approach did your controller take, and why?"
}

func rebuildTools(flightsPerFly int) []toolSpec {
	return []toolSpec{
		newTool("write_file", "Write a text file into your work directory (a relative path).", map[string]any{
			"path":    map[string]any{"type": "string"},
			"content": map[string]any{"type": "string"},
		}, "path", "content"),
		newTool("run_code", "Run code in your sandbox; files and interpreter state persist between calls in the same language. Returns the exit code, stdout and stderr.", map[string]any{
			"language": map[string]any{"type": "string", "enum": []string{"javascript", "python"}},
			"code":     map[string]any{"type": "string"},
		}, "language", "code"),
		newTool("fly", fmt.Sprintf("Fly controller.js from your work directory in a separate sandbox. smoke=true flies the four smoke flights; otherwise count (1 to %d) new random flights; again lists seeds an earlier fly call gave you, to fly them again.", flightsPerFly), map[string]any{
			"smoke": map[string]any{"type": "boolean"},
			"count": map[string]any{"type": "integer"},
			"again": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
		}),
	}
}

// maxToolOutput is what of a run's stdout or stderr goes back to the model.
const maxToolOutput = 8 << 10

var relPath = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}(/[A-Za-z0-9_][A-Za-z0-9._-]{0,63}){0,3}$`)

// rebuild is one rebuild's state while it runs.
type rebuild struct {
	spec    rebuildSpec
	sess    *client.Session
	remote  *client.Remote
	bctx    context.Context
	issued  map[uint32]bool
	written []byte // the last write_file of controller.js, or nil
	out     *Built
}

// buildOne makes one rebuild. remote signs every call; the session is closed (and the close
// signed) before it returns. It returns the controller the rebuild left, or nil, and the
// conversation's transcript.
func buildOne(ctx context.Context, m agentModel, remote *client.Remote, spec rebuildSpec) ([]byte, Built, Transcript, error) {
	controller, out, tr, err := buildSession(ctx, m, remote, spec)
	if err != nil && out.Ended == "" {
		// The harness, not the model, ended the session: run.json, agents.json and the export
		// name it, so the attempt is excluded by its reason rather than read as a short session.
		out.Ended, tr.Ended = endHarnessFault, endHarnessFault
	}
	return controller, out, tr, err
}

// endHarnessFault is the ending of a session a call into its sandbox ended with no answer.
const endHarnessFault = "harness_fault"

func buildSession(ctx context.Context, m agentModel, remote *client.Remote, spec rebuildSpec) ([]byte, Built, Transcript, error) {
	out := Built{Course: spec.Course, Group: spec.Group, N: spec.N}
	prompt := brief(spec.Course, spec.Recipe)
	tr := Transcript{Course: spec.Course, Group: spec.Group, N: spec.N, Recipe: spec.Recipe, Scrambled: spec.Scrambled, System: systemPrompt, Prompt: prompt, Turns: []TranscriptTurn{}}
	bctx := client.NewTraceContext(ctx, spec.trace("build"))
	sess, err := whenFree(bctx, spec.trace("build")+" open", func() (*client.Session, error) {
		return remote.OpenSession(bctx, client.SessionOptions{MinimumIsolation: sandbox.IsolationContainer,
			Languages: []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython}, Lifetime: 2 * time.Hour, IdleTimeout: 20 * time.Minute})
	})
	if err != nil {
		return nil, out, tr, fmt.Errorf("open the rebuild's session: %w", err)
	}
	out.Session = sess.Fingerprint()
	// The close gets closeTimeout from when it starts, not from the open: a deadline set at
	// the open ran out during a rebuild of two minutes (pilot, 2026-10-27), the close was
	// never sent, and with no signed close the bundle did not verify.
	closed := false
	closeSession := func() error {
		if closed {
			return nil
		}
		closed = true
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
		defer cancel()
		_, err := sess.Close(closeCtx)
		return err
	}
	defer func() { _ = closeSession() }()

	files := append([]sandbox.File{{Path: "BRIEF.md", Content: "# System\n\n" + systemPrompt + "\n\n# User\n\n" + prompt + "\n"}}, rebuildFiles(spec.Course)...)
	if _, err := whenFree(bctx, spec.trace("build")+" brief", func() (sandbox.CellResult, error) {
		return sess.RunCell(bctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: briefCell, Files: files, Timeout: 30 * time.Second, MinimumIsolation: sandbox.IsolationContainer})
	}); err != nil {
		return nil, out, tr, fmt.Errorf("hand the rebuild its brief: %w", err)
	}

	r := &rebuild{spec: spec, sess: sess, remote: remote, bctx: bctx, issued: map[uint32]bool{}, out: &out}
	for _, s := range smokeSeeds(spec.Course) {
		r.issued[s] = true
	}
	d := m.start(systemPrompt, prompt, rebuildTools(spec.FlightsPerFly))
	for out.Turns < spec.Turns {
		reply, err := d.next(ctx, true)
		if err != nil {
			out.Problem, out.Ended = err.Error(), stopOf(err)
			break
		}
		out.Turns++
		turn := TranscriptTurn{Answer: reply}
		if reply.Stop == "refusal" {
			out.Final, out.Ended = clip(reply.Text, 600), "refusal"
			tr.Turns = append(tr.Turns, turn)
			break
		}
		if len(reply.Calls) == 0 {
			out.Final, out.Ended = clip(reply.Text, 600), "answered"
			tr.Turns = append(tr.Turns, turn)
			break
		}
		for _, call := range reply.Calls {
			result, kind, err := r.runTool(ctx, call)
			if err != nil {
				tr.Turns = append(tr.Turns, turn) // what the model asked for, up to the call that failed
				return nil, out, tr, err
			}
			b, _ := json.Marshal(result)
			turn.Results = append(turn.Results, toolResult{ID: call.ID, Name: call.Name, Content: string(b), Kind: kind})
		}
		d.results(turn.Results)
		tr.Turns = append(tr.Turns, turn)
	}
	if out.Ended == "" {
		out.Ended = "turns"
		out.Final = fmt.Sprintf("(the rebuild reached its budget of %d turns)", spec.Turns)
	}
	controller, err := readController(bctx, sess)
	if err != nil {
		out.Ended = ""
		return nil, out, tr, err
	}
	switch {
	case controller == nil:
		out.ControllerFrom = "none"
	case r.written != nil && bytes.Equal(controller, r.written):
		out.ControllerFrom = "write_file"
	default:
		out.ControllerFrom = "changed"
	}
	tr.Controller, tr.From, tr.Ended = string(controller), out.ControllerFrom, out.Ended
	if controller != nil {
		tr.SHA256 = digest(controller)
	}
	if spec.AskAfter && out.Ended != "model_error" {
		// The controller is already read: nothing the model says now reaches it.
		tr.Question = afterQuestion(spec.Recipe)
		d.say(tr.Question)
		if a, err := d.next(ctx, false); err != nil {
			tr.AfterError = err.Error()
		} else {
			tr.After = &a
		}
	}
	if err := closeSession(); err != nil {
		// The controller is still graded; the failure is kept, since the bundle will not verify.
		return controller, out, tr, fmt.Errorf("close the rebuild's session, so the bundle cannot show it was not cut: %w", err)
	}
	return controller, out, tr, nil
}

// stopOf names why a model call ended a rebuild.
func stopOf(err error) string {
	switch {
	case errors.Is(err, errBudget):
		return "budget"
	case errors.Is(err, errPromptCap):
		return "prompt_cap"
	}
	return "model_error"
}

// closeTimeout bounds a rebuild's session close, counted from when the close starts.
var closeTimeout = 2 * time.Minute

// briefCell is the first call of every rebuild's session: it carries the brief, the API text
// and the baseline as files, and lists the work directory.
const briefCell = `require("fs").readdirSync(".").join(" ")`

// readController reads controller.js from the session through a project run's artifacts, the
// exact bytes. A rebuild that left none returns nil.
func readController(ctx context.Context, sess *client.Session) ([]byte, error) {
	res, err := whenFree(ctx, "hand-in read", func() (sandbox.ProjectResult, error) {
		return sess.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"test -f controller.js"}, Artifacts: []string{"controller.js"}, Timeout: 30 * time.Second, MinimumIsolation: sandbox.IsolationContainer})
	})
	if err != nil {
		return nil, fmt.Errorf("read the rebuild's controller: %w", err)
	}
	for _, a := range res.Artifacts {
		if a.Path == "controller.js" {
			return a.Content, nil
		}
	}
	return nil, nil
}

// runTool runs one tool call and says how it went (ok, refused or fault). An error ends the
// rebuild (the session or a client check failed); a refused call is a result the model reads.
func (r *rebuild) runTool(ctx context.Context, call toolCallReq) (map[string]any, string, error) {
	spec, sess, bctx, out := r.spec, r.sess, r.bctx, r.out
	refuse := func(msg string) (map[string]any, string, error) { return map[string]any{"error": msg}, "refused", nil }
	switch call.Name {
	case "write_file":
		var a struct{ Path, Content string }
		if json.Unmarshal(call.Input, &a) != nil || !relPath.MatchString(a.Path) || strings.Contains(a.Path, "..") {
			return refuse("write_file needs a relative path (letters, digits, . _ - and up to three /) and content")
		}
		if len(a.Content) > 256<<10 {
			return refuse("files are limited to 256 KiB")
		}
		res, err := whenFree(bctx, spec.trace("write_file"), func() (sandbox.CellResult, error) {
			return sess.RunCell(bctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: `"written"`, Files: []sandbox.File{{Path: a.Path, Content: a.Content}}, Timeout: 30 * time.Second, MinimumIsolation: sandbox.IsolationContainer})
		})
		if err != nil {
			var nd *sandbox.NotDispatchedError
			if errors.As(err, &nd) {
				return map[string]any{"error": "not written: " + clip(err.Error(), 300)}, "fault", nil
			}
			return nil, "", err
		}
		out.Runs++
		if path.Clean(a.Path) == "controller.js" {
			r.written = []byte(a.Content)
		}
		return map[string]any{"written": a.Path, "bytes": len(a.Content), "exit_code": res.ExitCode}, "ok", nil
	case "run_code":
		var a struct{ Language, Code string }
		if json.Unmarshal(call.Input, &a) != nil || a.Code == "" {
			return refuse("run_code needs language (javascript or python) and code")
		}
		lang := sandbox.Language(strings.ToLower(strings.TrimSpace(a.Language)))
		if lang != sandbox.LanguagePython {
			lang = sandbox.LanguageJavaScript
		}
		res, err := whenFree(bctx, spec.trace("run_code"), func() (sandbox.CellResult, error) {
			return sess.RunCell(bctx, sandbox.CellRequest{Language: lang, Code: a.Code, Timeout: 60 * time.Second, MinimumIsolation: sandbox.IsolationContainer})
		})
		if err != nil {
			return nil, "", err
		}
		out.Runs++
		return map[string]any{"exit_code": res.ExitCode, "timed_out": res.TimedOut, "stdout": clip(res.Stdout, maxToolOutput), "stderr": clip(res.Stderr, maxToolOutput)}, "ok", nil
	case "fly":
		if out.FlyCalls >= spec.FlyCalls {
			return refuse(fmt.Sprintf("this rebuild has used its %d fly calls", spec.FlyCalls))
		}
		var a struct {
			Smoke bool
			Count int
			Again []int64
		}
		if json.Unmarshal(call.Input, &a) != nil {
			return refuse("fly takes smoke (boolean), count (integer) and again (a list of seeds)")
		}
		seeds, refusal := flySeeds(spec, a.Smoke, a.Count, a.Again, r.issued)
		if refusal != "" {
			return refuse(refusal)
		}
		controller, err := readController(bctx, sess)
		if err != nil {
			return nil, "", err
		}
		if controller == nil {
			return refuse("there is no controller.js in your work directory")
		}
		if r.written == nil || !bytes.Equal(controller, r.written) {
			return refuse("controller.js is not what your last write_file of it wrote (it was changed another way, or never written with write_file); write it with write_file, then fly")
		}
		req, err := flyRequest(spec.Course, controller, seeds)
		if err != nil {
			return nil, "", err
		}
		out.FlyCalls++
		res, err := whenFree(ctx, spec.trace("fly"), func() (sandbox.ProjectResult, error) {
			return r.remote.RunProject(client.NewTraceContext(ctx, spec.trace("fly")), req)
		})
		if err != nil {
			return nil, "", fmt.Errorf("fly: %w", err)
		}
		if len(res.Steps) == 0 {
			return map[string]any{"error": "the practice run did not fly (" + res.Outcome.String() + ")"}, "fault", nil
		}
		fs, err := parseFlights([]byte(res.Steps[0].Stdout))
		if err != nil {
			return map[string]any{"error": "the practice run's answer could not be read: " + err.Error()}, "fault", nil
		}
		out.Flights += len(fs.Results)
		if !fs.Valid {
			return map[string]any{"valid": false, "error": fs.Error}, "ok", nil
		}
		return map[string]any{"passed": fs.Passed, "flown": fs.Total, "flights": fs.Results}, "ok", nil
	}
	return refuse("the tools are write_file, run_code and fly")
}

// flySeeds picks the seeds of a fly call: the smoke flights, seeds this rebuild was given
// before, and new ones drawn at random for it. It answers no question about any other seed, so
// it cannot tell a rebuild whether a seed is in a sealed set.
func flySeeds(spec rebuildSpec, smoke bool, count int, again []int64, issued map[uint32]bool) ([]uint32, string) {
	var seeds []uint32
	if smoke {
		seeds = append(seeds, smokeSeeds(spec.Course)...)
	}
	for _, s := range again {
		if s < 0 || s > 0xffffffff || !issued[uint32(s)] {
			return nil, "again may list only seeds a fly call gave you: " + strconv.FormatInt(s, 10) + " is not one"
		}
		seeds = append(seeds, uint32(s))
	}
	if count < 0 || count > spec.FlightsPerFly {
		return nil, fmt.Sprintf("count is 1 to %d", spec.FlightsPerFly)
	}
	var b [4]byte
	for drawn := 0; drawn < count; {
		if _, err := rand.Read(b[:]); err != nil {
			return nil, "no randomness: " + err.Error()
		}
		s := binary.BigEndian.Uint32(b[:])
		if spec.Avoid[s] || issued[s] {
			continue
		}
		issued[s] = true
		seeds = append(seeds, s)
		drawn++
	}
	if len(seeds) == 0 {
		return nil, "ask for smoke, count or again"
	}
	if len(seeds) > spec.FlightsPerFly+4 {
		return nil, fmt.Sprintf("at most %d flights a call", spec.FlightsPerFly+4)
	}
	return seeds, ""
}
