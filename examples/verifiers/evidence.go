package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// evidence is everything the page states, gathered from one run of the program and
// written beside the page as evidence.json. The page renders from it alone, and -verify
// checks it against the record logs published with it.
type evidence struct {
	Date      string         `json:"date"`      // the run's date, UTC
	Verifiers string         `json:"verifiers"` // the installed verifiers version
	Pin       string         `json:"pin"`       // the requirement the hash-locked environment pins
	Client    string         `json:"client"`    // the plimsoll-client version the run imported
	Python    string         `json:"python"`    // the evaluator's Python
	Scripted  bool           `json:"scripted"`  // the model was the scripted policy, not a language model
	Image     string         `json:"image"`     // the session image every plimsoll run used, by tag
	ImageID   string         `json:"image_id"`  // and by content identity, as the records name it
	Baseline  string         `json:"baseline"`  // verifiers' docker runtime's image, by tag
	BaseID    string         `json:"baseline_id"`
	Task      pinned         `json:"task"` // the outside task's source, pinned
	Validate  []validation   `json:"validate"`
	Attempts  []attempt      `json:"attempts"`
	Same      equivalence    `json:"equivalence"`
	Calls     callCosts      `json:"calls"`
	Census    census         `json:"census"`
	Logs      []publishedLog `json:"logs"`
}

// pinned is an outside repository read or run at one commit, with the files the run
// loaded by SHA-256.
type pinned struct {
	Repo   string            `json:"repo"`
	Commit string            `json:"commit"`
	Path   string            `json:"path"`
	Files  map[string]string `json:"files"`
}

// publishedLog is one record log published beside the page, and what each checker said.
type publishedLog struct {
	File   string   `json:"file"`
	Floor  string   `json:"floor"`
	Python logCheck `json:"python"` // the Python client's check_record_log, when the run ended
	Go     logCheck `json:"go"`     // this program's checker, which -verify reruns
}

// validation is one vf-validate of plimsoll-sum: the gold answer, and the untouched task
// graded in a fresh sandbox.
type validation struct {
	DockerRuntime string   `json:"docker_runtime"`
	Floor         string   `json:"floor"`
	Valid         bool     `json:"valid"`
	Gold          checkRow `json:"gold"`
	Untouched     checkRow `json:"untouched"`
	Log           string   `json:"log"`
}

type checkRow struct {
	Valid   bool               `json:"valid"`
	Reason  string             `json:"reason"`
	Reward  *float64           `json:"reward,omitempty"`
	Rewards map[string]float64 `json:"rewards,omitempty"`
	Error   string             `json:"error,omitempty"`
}

// attempt is one vf-eval of one configuration.
type attempt struct {
	Name          string             `json:"name"`
	Task          string             `json:"task"`
	Policy        string             `json:"policy"`
	Harness       string             `json:"harness"`
	Runtime       string             `json:"runtime"`
	DockerRuntime string             `json:"docker_runtime,omitempty"`
	Floor         string             `json:"floor,omitempty"`
	Reward        *float64           `json:"reward"`
	Rewards       map[string]float64 `json:"rewards,omitempty"`
	Metrics       map[string]float64 `json:"metrics,omitempty"`
	Stop          string             `json:"stop"`
	Error         string             `json:"error,omitempty"` // the line of the error that says why, quoted
	Seconds       map[string]float64 `json:"seconds,omitempty"`
	Total         float64            `json:"total_s"`
	ModelTurns    int                `json:"model_turns"`
	ToolResults   int                `json:"tool_results"`
	Session       string             `json:"session,omitempty"` // the trace's runtime id: the session fingerprint
	Log           string             `json:"log,omitempty"`
	Chain         []phaseCall        `json:"chain,omitempty"`
	Tools         []toolCall         `json:"tools,omitempty"`
}

// phaseCall is a record placed in the verifiers phase its call ran in.
type phaseCall struct {
	chainCall
	Phase string `json:"phase"`
}

// toolCall is one tool call of the scripted policy and the record of the session call
// that served it.
type toolCall struct {
	Tool   string `json:"tool"`
	Input  string `json:"input"`
	Output string `json:"output"` // the first line of the tool result, cut to 90 characters
	Lines  int    `json:"lines"`
	Record string `json:"record,omitempty"`
}

// equivalence compares the transcript of plimsoll-bash on plimsoll with the shipped bash
// harness's on verifiers' docker runtime, message by message, tool call ids aside.
type equivalence struct {
	Messages  int      `json:"messages"`
	Identical int      `json:"identical"`
	Diffs     []string `json:"diffs"`
	SameTools bool     `json:"same_tools"`
}

// callCosts is measure_calls.py's result: each runtime call through verifiers' own
// runtime API, timed on the evaluator.
type callCosts struct {
	Rounds int                `json:"rounds"`
	Calls  int                `json:"calls_per_round"`
	Rows   map[string]opCosts `json:"rows"` // docker, plimsoll-runc, plimsoll-runsc
}

type opCosts map[string]stat // start, run_true, write_1k, read_1k, teardown

type stat struct {
	Median float64 `json:"median_ms"`
	Min    float64 `json:"min_ms"`
	Max    float64 `json:"max_ms"`
	N      int     `json:"n"`
}

// --- reading what the Python harness wrote ---------------------------------------------

// summary is run_attempt.py's summary.json, the fields the page uses.
type summary struct {
	Task          string          `json:"task"`
	Policy        string          `json:"policy"`
	Harness       string          `json:"harness"`
	Runtime       string          `json:"runtime"`
	DockerRuntime *string         `json:"docker_runtime"`
	Floor         *string         `json:"floor"`
	Exit          int             `json:"vf_eval_exit"`
	Rollouts      []rollout       `json:"rollouts"`
	RecordLog     json.RawMessage `json:"record_log"`
}

type rollout struct {
	Reward      *float64           `json:"reward"`
	Rewards     map[string]float64 `json:"rewards"`
	Metrics     map[string]float64 `json:"metrics"`
	Stop        string             `json:"stop_condition"`
	Errors      []json.RawMessage  `json:"errors"`
	Seconds     map[string]float64 `json:"seconds"`
	Total       *float64           `json:"total_s"`
	ModelTurns  int                `json:"model_turns"`
	ToolResults int                `json:"tool_results"`
}

// pyCheck is check_record_log's answer as the Python harness printed it.
type pyCheck struct {
	Sessions   int               `json:"sessions"`
	Records    int               `json:"records"`
	Closed     int               `json:"closed"`
	Tiers      map[string]int    `json:"tiers"`
	Incomplete []json.RawMessage `json:"incomplete"`
	Error      string            `json:"error"`
}

func (p pyCheck) logCheck() logCheck {
	c := logCheck{Sessions: p.Sessions, Records: p.Records, Closed: p.Closed, Tiers: p.Tiers, Incomplete: []string{}}
	for _, raw := range p.Incomplete {
		var x struct {
			Session string `json:"session"`
			Reason  string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &x)
		c.Incomplete = append(c.Incomplete, fmt.Sprintf("%.12s: %s", x.Session, x.Reason))
	}
	sort.Strings(c.Incomplete)
	return c
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// trace is the part of one verifiers trace the page reads.
type trace struct {
	Agent struct {
		Runtime struct {
			ID string `json:"id"`
		} `json:"runtime"`
	} `json:"agent"`
	Nodes []struct {
		Tools   json.RawMessage `json:"tools"`
		Message *traceMessage   `json:"message"`
	} `json:"nodes"`
	Timing map[string]json.RawMessage `json:"timing"`
}

type traceMessage struct {
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	ToolCalls []struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"tool_calls"`
}

// text is a message's content as text: a string, or the text parts of a list.
func (m traceMessage) text() string {
	var s string
	if json.Unmarshal(m.Content, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(m.Content, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(p.Text)
		}
		return b.String()
	}
	return ""
}

// readTrace reads the one trace a configuration's vf-eval saved.
func readTrace(runDir string) (*trace, error) {
	var found []string
	err := filepath.WalkDir(runDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "traces.jsonl" {
			found = append(found, p)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("%s: %d traces.jsonl files, want 1", runDir, len(found))
	}
	f, err := os.Open(found[0])
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	var traces []trace
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var ep struct {
			Traces []trace `json:"traces"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ep); err != nil {
			return nil, fmt.Errorf("%s: %w", found[0], err)
		}
		traces = append(traces, ep.Traces...)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(traces) != 1 {
		return nil, fmt.Errorf("%s: %d traces, want 1", found[0], len(traces))
	}
	return &traces[0], nil
}

// phases are verifiers' attempt phases in order; a record belongs to the phase whose
// span holds its start.
var phases = []string{"boot", "setup", "agent", "finalize", "scoring"}

func (t *trace) phaseOf(startedMs int64) string {
	at := float64(startedMs) / 1000
	for _, name := range phases {
		var span struct {
			Start float64 `json:"start"`
			End   float64 `json:"end"`
		}
		if raw, ok := t.Timing[name]; !ok || json.Unmarshal(raw, &span) != nil || span.End == 0 {
			continue
		}
		if at >= span.Start && at < span.End {
			return name
		}
	}
	return "after"
}

// toolCalls pairs each tool call in the transcript with its result and, when the agent
// phase holds exactly one record per call, that record.
func (t *trace) toolCalls(agentRecords []phaseCall) []toolCall {
	var calls []toolCall
	results := map[int]string{}
	nResults := 0
	for _, n := range t.Nodes {
		if n.Message == nil {
			continue
		}
		switch n.Message.Role {
		case "assistant":
			for _, c := range n.Message.ToolCalls {
				calls = append(calls, toolCall{Tool: c.Name, Input: describeArgs(c.Name, c.Arguments)})
			}
		case "tool":
			results[nResults] = n.Message.text()
			nResults++
		}
	}
	for i := range calls {
		out := strings.TrimRight(results[i], "\n")
		calls[i].Lines = len(strings.Split(out, "\n"))
		// The first line that says something: a JSON answer's first line is "{".
		first := ""
		for _, l := range strings.Split(out, "\n") {
			if len(strings.TrimSpace(l)) > 2 {
				first = strings.TrimSpace(l)
				break
			}
		}
		if len([]rune(first)) > 90 {
			first = string([]rune(first)[:89]) + "…"
		}
		calls[i].Output = first
		if len(agentRecords) == len(calls) {
			calls[i].Record = agentRecords[i].SHA256
		}
	}
	return calls
}

func describeArgs(tool, arguments string) string {
	var a map[string]string
	if json.Unmarshal([]byte(arguments), &a) != nil {
		return arguments
	}
	if tool == "bash" {
		return a["command"]
	}
	if tool == "edit" {
		return fmt.Sprintf("in %s, replace %q with %q", a["path"], a["old_str"], a["new_str"])
	}
	return arguments
}

// compareTranscripts is the equivalence check: each message's role, text and tool calls.
func compareTranscripts(a, b *trace) equivalence {
	msgs := func(t *trace) []traceMessage {
		var out []traceMessage
		for _, n := range t.Nodes {
			if n.Message != nil {
				out = append(out, *n.Message)
			}
		}
		return out
	}
	tools := func(t *trace) string {
		for _, n := range t.Nodes {
			if len(n.Tools) > 0 {
				return string(n.Tools)
			}
		}
		return ""
	}
	ma, mb := msgs(a), msgs(b)
	eq := equivalence{Messages: max(len(ma), len(mb)), Diffs: []string{}, SameTools: tools(a) == tools(b) && tools(a) != ""}
	for i := 0; i < len(ma) || i < len(mb); i++ {
		if i >= len(ma) || i >= len(mb) {
			eq.Diffs = append(eq.Diffs, fmt.Sprintf("message %d is in one transcript only", i+1))
			continue
		}
		x, y := ma[i], mb[i]
		same := x.Role == y.Role && x.text() == y.text() && len(x.ToolCalls) == len(y.ToolCalls)
		for j := 0; same && j < len(x.ToolCalls); j++ {
			same = x.ToolCalls[j].Name == y.ToolCalls[j].Name && x.ToolCalls[j].Arguments == y.ToolCalls[j].Arguments
		}
		if same {
			eq.Identical++
			continue
		}
		eq.Diffs = append(eq.Diffs, describeDiff(i+1, x, y))
	}
	return eq
}

// describeDiff names the lines one message has and the other lacks.
func describeDiff(n int, plimsoll, docker traceMessage) string {
	lines := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, l := range strings.Split(s, "\n") {
			if strings.TrimSpace(l) != "" {
				m[strings.TrimSpace(l)] = true
			}
		}
		return m
	}
	a, b := lines(plimsoll.text()), lines(docker.text())
	var onlyA, onlyB []string
	for l := range a {
		if !b[l] {
			onlyA = append(onlyA, l)
		}
	}
	for l := range b {
		if !a[l] {
			onlyB = append(onlyB, l)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	desc := fmt.Sprintf("message %d (%s)", n, plimsoll.Role)
	if len(onlyA) > 0 {
		desc += fmt.Sprintf(": only on plimsoll, %q", strings.Join(onlyA, " / "))
	}
	if len(onlyB) > 0 {
		desc += fmt.Sprintf(": only on docker, %q", strings.Join(onlyB, " / "))
	}
	if len(onlyA) == 0 && len(onlyB) == 0 {
		desc += ": differs in tool calls or whitespace"
	}
	return desc
}

// errorLine quotes the line of an attempt's error that says why, never a whole message
// (which can carry the evaluator's paths).
func errorLine(errs []json.RawMessage, home string) string {
	for _, raw := range errs {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			s = string(raw)
		}
		for _, l := range strings.Split(s, "\n") {
			l = strings.TrimSpace(l)
			if strings.Contains(l, "bad address") || strings.Contains(l, "Could not resolve") {
				if home != "" && strings.Contains(l, home) {
					continue
				}
				if i := strings.Index(l, "wget:"); i >= 0 {
					l = l[i:]
				}
				return strings.Trim(l, `"\`)
			}
		}
	}
	if len(errs) > 0 {
		return "an error, not quoted here (no line names the cause)"
	}
	return ""
}
