package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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
	Recipe        string // "" for the control group
	Turns         int
	FlightsPerFly int
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
	FlyCalls int    `json:"fly_calls"` // practice flights asked for, in separate runs
	Flights  int    `json:"flights"`   // practice flights flown
	Final    string `json:"final"`     // the model's last words, clipped
	Problem  string `json:"problem,omitempty"`
}

// systemPrompt is the same for every rebuild.
const systemPrompt = `You are building a flight controller in a Linux sandbox. You have three tools. write_file writes a file into your work directory. run_code runs JavaScript or Python in your sandbox; files persist between calls. fly flies controller.js from your work directory in a separate sandbox that holds the simulator and answers with each flight's result. Read API.md first. Build, fly, read the results, fix, and fly again.`

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

func rebuildTools(flightsPerFly int) []tool {
	return []tool{
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

// maxFlyCalls bounds the practice runs one rebuild may start.
const maxFlyCalls = 60

var relPath = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}(/[A-Za-z0-9_][A-Za-z0-9._-]{0,63}){0,3}$`)

// buildOne makes one rebuild. remote signs every call; the session is closed (and the close
// signed) before it returns. It returns the controller the rebuild left, or nil.
func buildOne(ctx context.Context, m *chat, remote *client.Remote, spec rebuildSpec) ([]byte, Built, error) {
	out := Built{Course: spec.Course, Group: spec.Group, N: spec.N}
	bctx := client.NewTraceContext(ctx, spec.trace("build"))
	sess, err := remote.OpenSession(bctx, client.SessionOptions{MinimumIsolation: sandbox.IsolationContainer,
		Languages: []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython}, Lifetime: 2 * time.Hour, IdleTimeout: 20 * time.Minute})
	if err != nil {
		return nil, out, fmt.Errorf("open the rebuild's session: %w", err)
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

	prompt := brief(spec.Course, spec.Recipe)
	files := append([]sandbox.File{{Path: "BRIEF.md", Content: "# System\n\n" + systemPrompt + "\n\n# User\n\n" + prompt + "\n"}}, rebuildFiles(spec.Course)...)
	if _, err := sess.RunCell(bctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: briefCell, Files: files, Timeout: 30 * time.Second, MinimumIsolation: sandbox.IsolationContainer}); err != nil {
		return nil, out, fmt.Errorf("hand the rebuild its brief: %w", err)
	}

	issued := map[uint32]bool{}
	for _, s := range smokeSeeds(spec.Course) {
		issued[s] = true
	}
	messages := []message{{Role: "system", Content: systemPrompt}, {Role: "user", Content: prompt}}
	tools := rebuildTools(spec.FlightsPerFly)
	for out.Turns < spec.Turns {
		reply, err := m.complete(ctx, messages, tools)
		if err != nil {
			out.Problem = err.Error()
			break
		}
		out.Turns++
		messages = append(messages, reply)
		if len(reply.ToolCalls) == 0 {
			out.Final = clip(reply.Content, 600)
			break
		}
		for _, call := range reply.ToolCalls {
			result, err := runTool(ctx, bctx, sess, remote, spec, call, issued, &out)
			if err != nil {
				return nil, out, err
			}
			b, _ := json.Marshal(result)
			messages = append(messages, message{Role: "tool", ToolCallID: call.ID, Name: call.Function.Name, Content: string(b)})
		}
	}
	if out.Final == "" && out.Problem == "" {
		out.Final = fmt.Sprintf("(the rebuild reached its budget of %d turns)", spec.Turns)
	}
	controller, err := readController(bctx, sess)
	if err != nil {
		return nil, out, err
	}
	if err := closeSession(); err != nil {
		// The controller is still graded; the failure is kept, since the bundle will not verify.
		return controller, out, fmt.Errorf("close the rebuild's session, so the bundle cannot show it was not cut: %w", err)
	}
	return controller, out, nil
}

// closeTimeout bounds a rebuild's session close, counted from when the close starts.
var closeTimeout = 2 * time.Minute

// briefCell is the first call of every rebuild's session: it carries the brief, the API text
// and the baseline as files, and lists the work directory.
const briefCell = `require("fs").readdirSync(".").join(" ")`

// readController reads controller.js from the session through a project run's artifacts, the
// exact bytes. A rebuild that left none returns nil.
func readController(ctx context.Context, sess *client.Session) ([]byte, error) {
	res, err := sess.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"test -f controller.js"}, Artifacts: []string{"controller.js"}, Timeout: 30 * time.Second, MinimumIsolation: sandbox.IsolationContainer})
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

// runTool runs one tool call. An error ends the rebuild (the session or a client check failed);
// a refused call is a result the model reads.
func runTool(ctx, bctx context.Context, sess *client.Session, remote *client.Remote, spec rebuildSpec, call toolCall, issued map[uint32]bool, out *Built) (map[string]any, error) {
	switch call.Function.Name {
	case "write_file":
		var a struct{ Path, Content string }
		if json.Unmarshal([]byte(call.Function.Arguments), &a) != nil || !relPath.MatchString(a.Path) || strings.Contains(a.Path, "..") {
			return map[string]any{"error": "write_file needs a relative path (letters, digits, . _ - and up to three /) and content"}, nil
		}
		if len(a.Content) > 256<<10 {
			return map[string]any{"error": "files are limited to 256 KiB"}, nil
		}
		res, err := sess.RunCell(bctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: `"written"`, Files: []sandbox.File{{Path: a.Path, Content: a.Content}}, Timeout: 30 * time.Second, MinimumIsolation: sandbox.IsolationContainer})
		if err != nil {
			var nd *sandbox.NotDispatchedError
			if errors.As(err, &nd) {
				return map[string]any{"error": "not written: " + clip(err.Error(), 300)}, nil
			}
			return nil, err
		}
		out.Runs++
		return map[string]any{"written": a.Path, "bytes": len(a.Content), "exit_code": res.ExitCode}, nil
	case "run_code":
		var a struct{ Language, Code string }
		if json.Unmarshal([]byte(call.Function.Arguments), &a) != nil || a.Code == "" {
			return map[string]any{"error": "run_code needs language (javascript or python) and code"}, nil
		}
		lang := sandbox.Language(strings.ToLower(strings.TrimSpace(a.Language)))
		if lang != sandbox.LanguagePython {
			lang = sandbox.LanguageJavaScript
		}
		res, err := sess.RunCell(bctx, sandbox.CellRequest{Language: lang, Code: a.Code, Timeout: 60 * time.Second, MinimumIsolation: sandbox.IsolationContainer})
		if err != nil {
			return nil, err
		}
		out.Runs++
		return map[string]any{"exit_code": res.ExitCode, "timed_out": res.TimedOut, "stdout": clip(res.Stdout, maxToolOutput), "stderr": clip(res.Stderr, maxToolOutput)}, nil
	case "fly":
		if out.FlyCalls >= maxFlyCalls {
			return map[string]any{"error": fmt.Sprintf("this rebuild has used its %d fly calls", maxFlyCalls)}, nil
		}
		var a struct {
			Smoke bool
			Count int
			Again []int64
		}
		if json.Unmarshal([]byte(call.Function.Arguments), &a) != nil {
			return map[string]any{"error": "fly takes smoke (boolean), count (integer) and again (a list of seeds)"}, nil
		}
		seeds, refusal := flySeeds(spec, a.Smoke, a.Count, a.Again, issued)
		if refusal != "" {
			return map[string]any{"error": refusal}, nil
		}
		controller, err := readController(bctx, sess)
		if err != nil {
			return nil, err
		}
		if controller == nil {
			return map[string]any{"error": "there is no controller.js in your work directory"}, nil
		}
		req, err := flyRequest(spec.Course, controller, seeds)
		if err != nil {
			return nil, err
		}
		out.FlyCalls++
		res, err := remote.RunProject(client.NewTraceContext(ctx, spec.trace("fly")), req)
		if err != nil {
			return nil, fmt.Errorf("fly: %w", err)
		}
		if len(res.Steps) == 0 {
			return map[string]any{"error": "the practice run did not fly (" + res.Outcome.String() + ")"}, nil
		}
		fs, err := parseFlights([]byte(res.Steps[0].Stdout))
		if err != nil {
			return map[string]any{"error": "the practice run's answer could not be read: " + err.Error()}, nil
		}
		out.Flights += len(fs.Results)
		if !fs.Valid {
			return map[string]any{"valid": false, "error": fs.Error}, nil
		}
		return map[string]any{"passed": fs.Passed, "flown": fs.Total, "flights": fs.Results}, nil
	}
	return map[string]any{"error": "the tools are write_file, run_code and fly"}, nil
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
