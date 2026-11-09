package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

// The real-model section of the page. Unlike everything else here it is not produced by a run
// of this program: a run with a real model spends money, so it is made by hand with
// attempt/run_attempt.py --model, and -real-model DIR gathers that run's output beside the page.
// The section renders only when realFile exists, and a dry run (a scripted upstream) is refused,
// so a script's score can never be shown as a model's.
const (
	realDir     = "real-model"
	realFile    = realDir + "/results.json"
	realLogFile = realDir + "/records.jsonl"
)

// realResults is the file the section renders from: the run's settings, one row per attempt,
// and the checks that say the numbers can be trusted.
type realResults struct {
	Date          string        `json:"date"` // the first record's date, UTC
	Model         string        `json:"model"`
	Upstream      string        `json:"upstream_host"`
	Preset        string        `json:"preset"`
	Tasks         int           `json:"tasks"`
	Concurrency   int           `json:"concurrency"`
	AttemptCap    int           `json:"max_total_tokens_per_attempt"` // verifiers' cap, on new tokens
	AttemptBudget int           `json:"attempt_token_budget"`         // a backstop on billed tokens, set so the dollars stop an attempt first
	RunBudget     int           `json:"run_token_budget"`             // the same, for the run
	MaxCallOut    int           `json:"max_call_output_tokens"`       // the relay's cap on one answer
	CostCap       float64       `json:"cost_cap_usd"`                 // the relay's dollar budget
	PriceIn       float64       `json:"price_in_per_million"`
	PriceCached   float64       `json:"price_cached_per_million"`
	PriceOut      float64       `json:"price_out_per_million"`
	Attempts      []realAttempt `json:"attempts"`
	Relay         realRelay     `json:"relay"`
	CostUSD       float64       `json:"cost_usd"` // from the relay's count of the API's usage fields
	TraceTokens   int           `json:"trace_total_tokens"`
	TracesMatch   bool          `json:"traces_match_relay"`
	Log           publishedLog  `json:"log"`
	FilesChecked  bool          `json:"key_absent_from_every_file"`
	ChildChecked  int           `json:"children_checked_for_the_key"`
	OtherChecked  int           `json:"other_files_checked_for_the_key"` // files outside the output directory, such as the driver's own log
	Solvable      *solvable     `json:"solvable,omitempty"`              // a model-free solver's result on the same instances, if one was checked
}

// solvable is the result of the private check that a script reading only the sandbox's corpus
// recovers the expected value: Solved of Of instances. It is a statement about the task, not the
// model, and is shown only when it covers every attempt and every instance was solved.
type solvable struct {
	Solved    int    `json:"solvable_from_corpus"`
	Of        int    `json:"of"`
	CheckedOn string `json:"checked_on"`
}

// solvableFile is the checked result, put beside summary.json before the run is gathered.
const solvableFile = "solvable.json"

// realAttempt is one attempt. Reward and Rewards are the task's grader's, read from verifiers'
// trace; nothing here comes from what the model said about itself.
type realAttempt struct {
	Task        int                `json:"task"`
	Reward      *float64           `json:"reward"`
	Rewards     map[string]float64 `json:"rewards,omitempty"`
	Sources     *float64           `json:"source_uuid_fraction,omitempty"`
	Stop        string             `json:"stop"`
	Error       string             `json:"error,omitempty"`
	Stopped     string             `json:"stopped_by_relay,omitempty"` // the budget that ended it: says nothing about the model
	Input       int                `json:"input_tokens"`               // billed: every call's whole prompt, cached part included
	Cached      int                `json:"cached_input_tokens"`        // the part of Input the API served from cache
	LastFinish  string             `json:"last_finish_reason,omitempty"`
	CallCap     int                `json:"max_call_output_tokens,omitempty"` // the per-call output cap in force, for LastFinish "length"
	Output      int                `json:"output_tokens"`
	Total       int                `json:"total_tokens"`
	CostUSD     float64            `json:"cost_usd"`
	Turns       int                `json:"model_turns"`
	Tools       int                `json:"tool_results"`
	AnswerFirst string             `json:"answer_first_role,omitempty"` // "", assistant or tool: never system or user
}

// realRelay is the relay's own count, from the usage field of each answer.
type realRelay struct {
	Prompt         int     `json:"prompt_tokens"` // includes Cached
	Cached         int     `json:"cached_prompt_tokens"`
	Completion     int     `json:"completion_tokens"`
	Total          int     `json:"total_tokens"`
	Unknown        int     `json:"charged_without_usage"`
	Counted        int     `json:"tokens_counted"`
	Budget         int     `json:"token_budget"`
	UsdSpent       float64 `json:"usd_spent"`
	UsdBudget      float64 `json:"usd_budget"`
	Forwarded      int     `json:"forwarded"`
	Refused        int     `json:"refused"`
	UpstreamErrors int     `json:"upstream_errors"`
	UsageMissing   int     `json:"usage_missing"`
	BudgetReached  bool    `json:"budget_reached"`
	AnswerKeySeen  bool    `json:"answer_key_seen"`
}

// realSummary is run_attempt.py's summary.json, as far as this reads it.
type realSummary struct {
	Exit      *int            `json:"vf_eval_exit"`
	TimedOut  bool            `json:"timed_out"`
	Floor     *string         `json:"floor"`
	RecordLog json.RawMessage `json:"record_log"`
	Rollouts  []struct {
		Task        *int               `json:"task_idx"`
		Stopped     *string            `json:"relay_refused"`
		Reward      *float64           `json:"reward"`
		Rewards     map[string]float64 `json:"rewards"`
		Metrics     map[string]float64 `json:"metrics"`
		Stop        string             `json:"stop_condition"`
		Errors      []json.RawMessage  `json:"errors"`
		Input       int                `json:"input_tokens"`
		Cached      int                `json:"cached_input_tokens"`
		LastFinish  string             `json:"last_finish_reason"`
		Output      int                `json:"output_tokens"`
		Total       int                `json:"total_tokens"`
		CostUSD     float64            `json:"cost_usd"`
		Turns       int                `json:"model_turns"`
		Tools       int                `json:"tool_results"`
		AnswerFirst *string            `json:"answer_first_role"`
	} `json:"rollouts"`
	Real *struct {
		DryRun        bool      `json:"dry_run"`
		Model         string    `json:"model"`
		Upstream      string    `json:"upstream_host"`
		Preset        string    `json:"preset"`
		Tasks         int       `json:"tasks"`
		Concurrency   int       `json:"concurrency"`
		AttemptCap    int       `json:"max_total_tokens_per_attempt"`
		AttemptBudget int       `json:"attempt_token_budget"`
		RunBudget     int       `json:"run_token_budget"`
		MaxCallOut    int       `json:"max_call_output_tokens"`
		CostCap       float64   `json:"cost_cap_usd"`
		PriceIn       float64   `json:"price_in_per_million"`
		PriceCached   float64   `json:"price_cached_per_million"`
		PriceOut      float64   `json:"price_out_per_million"`
		Relay         realRelay `json:"relay"`
		CostUSD       float64   `json:"cost_usd"`
		TraceTokens   int       `json:"trace_total_tokens"`
		TracesMatch   bool      `json:"traces_match_relay"`
		AnswerKey     struct {
			Refused bool     `json:"refused_requests"`
			Roles   []string `json:"first_role_system_or_user"`
		} `json:"answer_key"`
	} `json:"real_model"`
	KeyCheck *struct {
		Files        []string `json:"files_with_the_key"`
		OtherFiles   []string `json:"other_files_with_the_key"`
		OtherChecked int      `json:"other_files_checked"`
		Children     []string `json:"children_with_the_key"`
		Checked      int      `json:"children_checked"`
	} `json:"key_check"`
}

// gatherReal reads one real-model run's output from src, refuses a run that must not be shown,
// and writes the results file and its record log into the page's directory dir.
func gatherReal(src, dir, repo string) error {
	var s realSummary
	if err := readJSON(filepath.Join(src, "summary.json"), &s); err != nil {
		return err
	}
	switch {
	case s.Real == nil:
		return errors.New("this run has no real_model section: it was a scripted run")
	case s.Real.DryRun:
		return errors.New("this was a dry run against a scripted upstream: its scores are a script's, and are not published")
	case s.KeyCheck == nil:
		return errors.New("this run has no key check")
	case len(s.KeyCheck.Files) != 0 || len(s.KeyCheck.OtherFiles) != 0 || len(s.KeyCheck.Children) != 0:
		return fmt.Errorf("the key was found in %v and %v and in %d child processes: rotate it, and publish nothing", s.KeyCheck.Files, s.KeyCheck.OtherFiles, len(s.KeyCheck.Children))
	case s.Real.AnswerKey.Refused || len(s.Real.AnswerKey.Roles) != 0:
		return errors.New("the task's hidden answer reached a request to the model: the scores mean nothing")
	case s.Floor == nil:
		return errors.New("this run names no isolation floor")
	case len(s.Rollouts) == 0:
		return errors.New("this run has no attempts")
	}
	reached := false
	for _, row := range s.Rollouts {
		reached = reached || row.Tools > 0
	}
	if !reached {
		return errors.New("no attempt got a tool result back: this run shows the plumbing failing, not a model's score")
	}
	r := &realResults{
		Model: s.Real.Model, Upstream: s.Real.Upstream, Preset: s.Real.Preset, Tasks: s.Real.Tasks, Concurrency: s.Real.Concurrency,
		AttemptCap: s.Real.AttemptCap, AttemptBudget: s.Real.AttemptBudget, RunBudget: s.Real.RunBudget, MaxCallOut: s.Real.MaxCallOut, CostCap: s.Real.CostCap,
		PriceIn: s.Real.PriceIn, PriceCached: s.Real.PriceCached, PriceOut: s.Real.PriceOut,
		Relay: s.Real.Relay, CostUSD: s.Real.CostUSD, TraceTokens: s.Real.TraceTokens, TracesMatch: s.Real.TracesMatch,
		FilesChecked: true, ChildChecked: s.KeyCheck.Checked, OtherChecked: s.KeyCheck.OtherChecked,
	}
	home, _ := os.UserHomeDir()
	for i, row := range s.Rollouts {
		a := realAttempt{Task: i, Reward: row.Reward, Rewards: row.Rewards, Stop: row.Stop, Error: errorLine(row.Errors, home),
			Input: row.Input, Cached: row.Cached, LastFinish: row.LastFinish, CallCap: s.Real.MaxCallOut, Output: row.Output, Total: row.Total, CostUSD: row.CostUSD, Turns: row.Turns, Tools: row.Tools}
		if row.Task != nil {
			a.Task = *row.Task
		}
		if f, ok := row.Metrics["source_uuid_fraction"]; ok {
			a.Sources = &f
		}
		if row.AnswerFirst != nil {
			a.AnswerFirst = *row.AnswerFirst
		}
		if row.Stopped != nil {
			a.Stopped = *row.Stopped
		}
		r.Attempts = append(r.Attempts, a)
	}
	sort.Slice(r.Attempts, func(i, j int) bool { return r.Attempts[i].Task < r.Attempts[j].Task })
	if path := filepath.Join(src, solvableFile); fileExists(path) {
		var sv solvable
		if err := readJSON(path, &sv); err != nil {
			return err
		}
		if sv.Of != len(r.Attempts) || sv.Solved < 0 || sv.Solved > sv.Of || sv.CheckedOn == "" {
			return fmt.Errorf("%s states %+v for a run of %d attempts", solvableFile, sv, len(r.Attempts))
		}
		r.Solvable = &sv
	}
	if err := os.MkdirAll(filepath.Join(dir, realDir), 0o755); err != nil {
		return err
	}
	log := filepath.Join(dir, filepath.FromSlash(realLogFile))
	if err := copyFile(log, filepath.Join(src, "records.jsonl")); err != nil {
		return err
	}
	goCheck, calls, err := checkRecordFile(log, *s.Floor)
	if err != nil {
		return err
	}
	var py pyCheck
	if err := json.Unmarshal(s.RecordLog, &py); err != nil {
		return fmt.Errorf("the Python check's answer: %w", err)
	}
	if py.Error != "" {
		return fmt.Errorf("the Python check refused the log: %s", py.Error)
	}
	if !reflect.DeepEqual(py.logCheck(), goCheck) {
		return fmt.Errorf("the Python check says %+v, the Go check %+v", py.logCheck(), goCheck)
	}
	r.Log = publishedLog{File: realLogFile, Floor: *s.Floor, Python: py.logCheck(), Go: goCheck}
	if len(calls) == 0 {
		return errors.New("the record log holds no calls")
	}
	for _, call := range calls {
		if d := time.UnixMilli(call.Started).UTC().Format("2006-01-02"); r.Date == "" || d < r.Date {
			r.Date = d
		}
	}
	if err := checkReal(r); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := noLocalPaths(raw, repo); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, filepath.FromSlash(realFile)), raw, 0o644)
}

// maxCostCapUSD is the most a real run was approved to cost; a results file stating a higher
// cap did not run under the approved limit.
const maxCostCapUSD = 0.96

// checkReal is what must hold of a results file whatever produced it: the cost of each attempt
// is its tokens at the stated prices (cached input at the cached price), the attempts add up to
// the run, the run stayed inside its dollar cap and that cap inside the approved one, and the
// file states a real run with the record log it names rechecked.
func checkReal(r *realResults) error {
	if r.Upstream == "" || r.Upstream == "loopback" {
		return fmt.Errorf("the upstream is %q: a real run names the API it called", r.Upstream)
	}
	if !r.FilesChecked || r.ChildChecked == 0 {
		return errors.New("the results do not state the key check")
	}
	if r.CostCap <= 0 || r.CostCap > maxCostCapUSD {
		return fmt.Errorf("the run's dollar cap is $%v; the approved limit is $%v", r.CostCap, maxCostCapUSD)
	}
	if r.Relay.UsdBudget != r.CostCap || r.Relay.UsdSpent > r.CostCap+1e-9 || r.CostUSD > r.CostCap+1e-9 {
		return fmt.Errorf("the relay spent $%v and the run is stated at $%v against a dollar cap of $%v (relay budget $%v)", r.Relay.UsdSpent, r.CostUSD, r.CostCap, r.Relay.UsdBudget)
	}
	if r.Relay.Counted > r.RunBudget || r.Relay.Counted > r.Relay.Budget {
		return fmt.Errorf("the relay counted %d tokens against a budget of %d", r.Relay.Counted, r.RunBudget)
	}
	if r.Relay.Counted != r.Relay.Total+r.Relay.Unknown {
		return fmt.Errorf("the relay's %d counted is not %d used and %d unknown", r.Relay.Counted, r.Relay.Total, r.Relay.Unknown)
	}
	if r.Relay.Cached < 0 || r.Relay.Cached > r.Relay.Prompt {
		return fmt.Errorf("the relay's %d cached tokens are not within its %d prompt tokens", r.Relay.Cached, r.Relay.Prompt)
	}
	if want := r.cost(r.Relay.Prompt, r.Relay.Cached, r.Relay.Completion+r.Relay.Unknown); !closeUSD(want, r.CostUSD) {
		return fmt.Errorf("the run's cost is stated as $%f; the relay's tokens at the stated prices are $%f", r.CostUSD, want)
	}
	if !r.TracesMatch {
		return fmt.Errorf("verifiers' saved traces add up to %d tokens and the relay counted %d: some call is uncounted in one of them, so the per-attempt numbers cannot be trusted", r.TraceTokens, r.Relay.Counted)
	}
	if r.Relay.AnswerKeySeen {
		return errors.New("the task's hidden answer reached a request to the model")
	}
	var in, cached int
	var sum float64
	for _, a := range r.Attempts {
		if a.AnswerFirst == "system" || a.AnswerFirst == "user" {
			return fmt.Errorf("task %d: the answer first appears in a %s message", a.Task, a.AnswerFirst)
		}
		if a.Cached < 0 || a.Cached > a.Input {
			return fmt.Errorf("task %d: %d cached tokens are not within its %d input tokens", a.Task, a.Cached, a.Input)
		}
		if want := r.cost(a.Input, a.Cached, a.Output); !closeUSD(want, a.CostUSD) {
			return fmt.Errorf("task %d's cost is stated as $%f; its tokens at the stated prices are $%f", a.Task, a.CostUSD, want)
		}
		in, cached, sum = in+a.Input, cached+a.Cached, sum+a.CostUSD
	}
	if in != r.Relay.Prompt || cached != r.Relay.Cached {
		return fmt.Errorf("the attempts bill %d input tokens (%d cached) and the relay counted %d (%d cached)", in, cached, r.Relay.Prompt, r.Relay.Cached)
	}
	if math.Abs(sum-r.CostUSD) > 1e-6*float64(len(r.Attempts)+1) {
		return fmt.Errorf("the attempts cost $%f together and the run is stated at $%f", sum, r.CostUSD)
	}
	return nil
}

// cost is tokens at the stated prices, in dollars: input includes its cached part, which is
// charged the cached price.
func (r *realResults) cost(input, cached, output int) float64 {
	return roundUSD(float64(input-cached)*r.PriceIn + float64(cached)*r.PriceCached + float64(output)*r.PriceOut)
}

func roundUSD(perMillion float64) float64 { return math.Round(perMillion) / 1e6 }

func closeUSD(a, b float64) bool { return math.Abs(a-b) < 2e-6 }

// loadReal reads the results file beside the page, or nil if there is none.
func loadReal(dir string) (*realResults, error) {
	path := filepath.Join(dir, filepath.FromSlash(realFile))
	if !fileExists(path) {
		return nil, nil
	}
	var r realResults
	if err := readJSON(path, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// verifyReal rechecks the results file and its record log, if there are any.
func verifyReal(dir string, r *realResults) error {
	if r == nil {
		return nil
	}
	if err := checkReal(r); err != nil {
		return err
	}
	got, _, err := checkRecordFile(filepath.Join(dir, filepath.FromSlash(r.Log.File)), r.Log.Floor)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, r.Log.Go) || !reflect.DeepEqual(got, r.Log.Python) {
		return fmt.Errorf("%s rechecks to %+v; %s states %+v (Go) and %+v (Python)", r.Log.File, got, realFile, r.Log.Go, r.Log.Python)
	}
	return nil
}

// realView is what the section draws.
type realView struct {
	*realResults
	Graded      int    // attempts the task's grader scored
	Solved      int    // of those, the grader's 1.0
	Ungraded    int    // the rest: no reward at all
	Stopped     int    // ended by a relay budget, not by the model
	UngradedWhy string // why the ungraded were, in words
	Drove       bool   // at least one tool result came back to the model

	SolvedByScript bool    // a model-free script solved every instance from the corpus alone
	LongestTask    int     // the attempt that billed the most tokens
	LongestTokens  int     // and how many
	AttemptUSD     float64 // the per-attempt token budget at this run's average price per token
}

func newRealView(r *realResults) *realView {
	if r == nil {
		return nil
	}
	v := &realView{realResults: r}
	errored := 0
	for _, a := range r.Attempts {
		if a.Reward != nil {
			v.Graded++
			if *a.Reward >= 1 {
				v.Solved++
			}
		} else {
			v.Ungraded++
			if a.Stopped == "" {
				errored++
			}
		}
		if a.Stopped != "" {
			v.Stopped++
		}
		if a.Tools > 0 {
			v.Drove = true
		}
		if a.Total > v.LongestTokens {
			v.LongestTask, v.LongestTokens = a.Task, a.Total
		}
	}
	if r.Solvable != nil {
		v.SolvedByScript = r.Solvable.Of > 0 && r.Solvable.Solved == r.Solvable.Of
	}
	if r.Relay.Total > 0 {
		v.AttemptUSD = float64(r.AttemptBudget) * r.CostUSD / float64(r.Relay.Total)
	}
	var why []string
	if v.Stopped > 0 {
		why = append(why, fmt.Sprintf("%d stopped by a token budget before the grader ran", v.Stopped))
	}
	if errored > 0 {
		why = append(why, fmt.Sprintf("%d ended in an error before the grader ran", errored))
	}
	v.UngradedWhy = strings.Join(why, ", and ")
	return v
}

// thousands writes n with commas.
func thousands(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// budget writes a token budget with commas, and a budget set one over a round million (a limit
// that must not be reached by exactly that many tokens) as that million first, so it does not
// read as a typo.
func budget(n int) string {
	if n > 1000000 && n%1000000 == 1 {
		return fmt.Sprintf("%d million (%s)", n/1000000, thousands(n))
	}
	return thousands(n)
}

// endedWords says how an attempt ended, in words.
func endedWords(a realAttempt) string {
	switch {
	case a.Stopped == "dollar_budget":
		return "stopped by the run's dollar budget: says nothing about the model"
	case a.Stopped == "budget":
		return "stopped by the run's token budget: says nothing about the model"
	case a.Stopped != "":
		return "stopped by the attempt's token budget: says nothing about the model"
	case a.Error != "":
		return "an error: " + a.Error
	case a.LastFinish == "length":
		return "ended at the per-call output cap of " + thousands(a.CallCap) + " tokens, with no answer"
	case a.Stop == "agent_completed":
		return "the model finished"
	}
	return a.Stop
}

func usd(v float64) string {
	if v == 0 {
		return "$0"
	}
	return "$" + strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", v), "0"), ".")
}
