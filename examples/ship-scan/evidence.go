package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// The published files, in -out.
const (
	fileEvidence = "evidence.json"
	fileSet      = "withheld.json"
	filePage     = "index.html"
	// The clean call's exchange, request and response as sent and received, so -verify
	// recomputes its run record offline. The audit-mode call's request is not published:
	// it holds a hidden seed.
	fileCleanRequest  = "clean-call.request.json"
	fileCleanResponse = "clean-call.response.json"
	// The audit-mode call's response, which holds no seed: -verify recomputes its
	// result digest and checks the answer the page shows against it.
	fileSeedResponse = "seed-call.response.json"
)

// Evidence is what the page states, and all it states. Nothing in it is a request's
// content, a seed, or a line of the harness: the calls are described by text this
// program wrote, the daemon's lines are reduced to the fields LogLine lists, and an
// answer keeps only what the caller was told.
type Evidence struct {
	Commit    string     `json:"commit"`
	Provider  string     `json:"provider"`
	Isolation string     `json:"isolation"`
	SetSHA256 string     `json:"set_sha256"`
	Build     Command    `json:"build"`
	Entries   []SetEntry `json:"entries"`
	Calls     []Call     `json:"calls"`
	Offline   []Command  `json:"offline"`
}

// Command is a command line as a reader would type it, its exit status and what it
// printed.
type Command struct {
	Line   string   `json:"line"`
	Exit   int      `json:"exit"`
	Output []string `json:"output,omitempty"`
}

// SetEntry is one entry of the withheld set without its digest.
type SetEntry struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Mode  string `json:"mode"`
}

// Call is one call: what it was (text this program wrote), what came back, and the
// daemon's lines that carry its trace id.
type Call struct {
	Name    string    `json:"name"`
	Title   string    `json:"title"`
	Sent    string    `json:"sent"`
	Kind    string    `json:"kind"` // javascript or project
	Expect  string    `json:"expect"`
	TraceID string    `json:"trace_id"`
	Answer  Answer    `json:"answer"`
	Record  *Record   `json:"record,omitempty"`
	Log     []LogLine `json:"log"`
}

// The outcomes a call is expected to have.
const (
	expectRuns       = "runs"
	expectRefused    = "refused"
	expectRunsLogged = "runs, logged"
)

// Answer is what the caller was told: a run's exit code and output, or a refusal's
// code, mark and message.
type Answer struct {
	Ran      bool   `json:"ran"`
	ExitCode int    `json:"exit_code,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Code     string `json:"code,omitempty"`
	Mark     string `json:"mark,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Record is a run's record as the client checked it when the answer came back.
type Record struct {
	Version       int    `json:"version"`
	RequestSHA256 string `json:"request_sha256"`
	ResultSHA256  string `json:"result_sha256"`
	// Published: the whole exchange is in fileCleanRequest and fileCleanResponse, for
	// -verify; otherwise Why says what is published and why.
	Published bool   `json:"published"`
	Why       string `json:"why,omitempty"`
}

// LogLine is a daemon log line reduced to these fields: decoding into it is the
// allowlist, so a field the daemon adds later never reaches the evidence unread.
type LogLine struct {
	Msg                string   `json:"msg"`
	Op                 string   `json:"op"`
	Caller             string   `json:"caller"`
	TraceID            string   `json:"trace_id"`
	ExitCode           *int     `json:"exit_code,omitempty"`
	WithheldScan       string   `json:"withheld_scan,omitempty"`
	WithheldSet        string   `json:"withheld_set,omitempty"`
	WithheldFound      []string `json:"withheld_found,omitempty"`
	WithheldIncomplete []string `json:"withheld_incomplete,omitempty"`
	WithheldRefused    *bool    `json:"withheld_refused,omitempty"`
}

func marshalEvidence(ev *Evidence) ([]byte, error) {
	raw, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func readEvidence(dir string) (*Evidence, error) {
	raw, err := os.ReadFile(filepath.Join(dir, fileEvidence))
	if err != nil {
		return nil, err
	}
	var ev Evidence
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return nil, fmt.Errorf("%s: %w", fileEvidence, err)
	}
	return &ev, nil
}
