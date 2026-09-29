// Package runnerwire is the host side of the in-sandbox project runner protocol
// (docker/runner.mjs): the JSON plan a provider writes to the runner's stdin, the
// authenticated frame that carries the runner's report on its stdout, and the
// decoding and classification of that report. Every provider that runs runner.mjs
// goes through this package, so a plan and a report mean the same thing on each of
// them.
//
// The runner's stdout is not a private channel. Every step runs as the runner's uid,
// so any process in the sandbox can reopen the runner's stdout (/proc/<runner>/fd/1)
// and write to it, or read from it. A report is therefore trusted only if it carries
// an HMAC-SHA256 under a per-run key that reached the runner in the plan on stdin,
// before any step existed, and never appears in the environment, argv, a file or the
// output. Forged frames fail the MAC; marker text in step output is not special; a
// process that reads the pipe can steal or replay the honest frame but cannot alter
// it. Each provider's smoke test proves the other half, that a sandboxed process
// cannot read the runner's memory, where the key lives.
//
// It deliberately imports nothing from package sandbox (which imports it), so its
// types are its own; each provider copies a Report into its result types.
package runnerwire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Marker opens the runner's report frame on stdout:
//
//	\n<Marker> <body length in bytes> <hex HMAC-SHA256 of the body>\n<body>
//
// It must match MARKER in docker/runner.mjs.
const Marker = "<<<PLIMSOLL_REPORT_V2>>>"

// KeySize is the length of a run's report key.
const KeySize = 32

// NewKey returns a fresh report key for one run.
func NewKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("report key: %w", err)
	}
	return key, nil
}

// ErrUnauthenticated means frames were present but none carried a valid MAC: the
// runner's report is missing, damaged, or was never written, and what is there may
// have been written by a process in the sandbox.
var ErrUnauthenticated = errors.New("no authenticated runner report")

// StdoutCap bounds the runner's stdout a host reads: the report plus any incidental
// output before it. The runner caps each step's output at 1 MiB, its whole encoded
// result at 15 MiB, and stops on the first failure, so this is generous.
const StdoutCap = 16 << 20

// File is one project file the runner writes under its work directory.
type File struct {
	Path    string
	Content string
}

// Plan is what the runner executes: write Files, run Steps in order (stopping on the
// first failure), each under StepTimeout, then capture Artifacts. HostSDK, when set,
// is the host-API client module the runner preloads into every step. ReportKey (from
// NewKey) authenticates the report; the same key must be passed to Parse.
type Plan struct {
	Files       []File
	Steps       []string
	StepTimeout time.Duration
	Artifacts   []string
	HostSDK     string
	ReportKey   []byte
}

// Encode returns the plan as the JSON document the runner reads from stdin. A plan
// without a report key is refused: its report could not be told from a forgery.
func (p Plan) Encode() ([]byte, error) {
	if len(p.ReportKey) != KeySize {
		return nil, fmt.Errorf("plan has a %d-byte report key, want %d", len(p.ReportKey), KeySize)
	}
	type file struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	wire := struct {
		Files         []file   `json:"files"`
		Steps         []string `json:"steps"`
		StepTimeoutMs int64    `json:"stepTimeoutMs"`
		Artifacts     []string `json:"artifacts"`
		HostSDK       string   `json:"hostSDK,omitempty"`
		ReportKey     string   `json:"reportKey"`
	}{Steps: p.Steps, StepTimeoutMs: p.StepTimeout.Milliseconds(), Artifacts: p.Artifacts, HostSDK: p.HostSDK,
		ReportKey: hex.EncodeToString(p.ReportKey)}
	for _, f := range p.Files {
		wire.Files = append(wire.Files, file(f))
	}
	return json.Marshal(wire)
}

// Step is one step's result as the runner reported it. The Truncated flags say the
// runner's per-step output cap dropped bytes; the retained prefix is unmarked.
type Step struct {
	Command         string
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int
	TimedOut        bool
	Duration        time.Duration
}

// Artifact is a captured output file (binary-safe).
type Artifact struct {
	Path    string
	Content []byte
}

// Report is the decoded, authenticated report.
type Report struct {
	Steps              []Step
	Artifacts          []Artifact
	ArtifactsTruncated bool
	Err                string // runner-reported structured setup failure; "" = none
}

// Parse finds the runner's report frame in its captured stdout, verifies its MAC
// under key, and decodes it. found=false means no frame marker was present at all
// (the runner never reported). Frames whose MAC does not verify are ignored, wherever
// they are and whatever they claim; if markers were present but none verified, the
// result is (zero report, true, ErrUnauthenticated). Every verified frame carries the
// same body (only the runner holds the key and it reports once; a copy is a replay),
// so the first is taken.
func Parse(out string, key []byte) (Report, bool, error) {
	if len(key) != KeySize {
		return Report{}, false, fmt.Errorf("parse with a %d-byte report key, want %d", len(key), KeySize)
	}
	found := false
	for i := 0; ; {
		j := strings.Index(out[i:], Marker)
		if j < 0 {
			break
		}
		found = true
		start := i + j + len(Marker)
		i = start
		body, ok := frameBody(out[start:], key)
		if !ok {
			continue
		}
		rep, err := decode(body)
		if err != nil {
			// Authenticated but undecodable: the runner itself wrote bad JSON.
			return Report{}, true, err
		}
		return rep, true, nil
	}
	if found {
		return Report{}, true, ErrUnauthenticated
	}
	return Report{}, false, nil
}

// frameBody reads " <length> <mac>\n<body>" and returns the body if the header is
// well formed, the body is complete, and its MAC verifies.
func frameBody(rest string, key []byte) ([]byte, bool) {
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 || nl > 96 {
		return nil, false
	}
	fields := strings.Split(rest[:nl], " ")
	if len(fields) != 3 || fields[0] != "" {
		return nil, false
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil || n < 0 || n > StdoutCap || strconv.Itoa(n) != fields[1] {
		return nil, false
	}
	mac, err := hex.DecodeString(fields[2])
	if err != nil || len(mac) != sha256.Size {
		return nil, false
	}
	if len(rest)-(nl+1) < n {
		return nil, false
	}
	body := []byte(rest[nl+1 : nl+1+n])
	h := hmac.New(sha256.New, key)
	h.Write(body)
	if !hmac.Equal(h.Sum(nil), mac) {
		return nil, false
	}
	return body, true
}

func decode(body []byte) (Report, error) {
	var parsed struct {
		Steps []struct {
			Command         string `json:"command"`
			Stdout          string `json:"stdout"`
			Stderr          string `json:"stderr"`
			StdoutTruncated bool   `json:"stdoutTruncated"`
			StderrTruncated bool   `json:"stderrTruncated"`
			ExitCode        int    `json:"exitCode"`
			TimedOut        bool   `json:"timedOut"`
			DurationMs      int64  `json:"durationMs"`
		} `json:"steps"`
		Artifacts []struct {
			Path    string `json:"path"`
			Content []byte `json:"content"` // base64 decoded by encoding/json
		} `json:"artifacts"`
		ArtifactsTruncated bool   `json:"artifactsTruncated"`
		Error              string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Report{}, err
	}
	rep := Report{ArtifactsTruncated: parsed.ArtifactsTruncated, Err: parsed.Error}
	for _, a := range parsed.Artifacts {
		rep.Artifacts = append(rep.Artifacts, Artifact{Path: a.Path, Content: a.Content})
	}
	for _, s := range parsed.Steps {
		rep.Steps = append(rep.Steps, Step{
			Command:         s.Command,
			Stdout:          s.Stdout,
			Stderr:          s.Stderr,
			StdoutTruncated: s.StdoutTruncated,
			StderrTruncated: s.StderrTruncated,
			ExitCode:        s.ExitCode,
			TimedOut:        s.TimedOut,
			Duration:        time.Duration(s.DurationMs) * time.Millisecond,
		})
	}
	return rep, nil
}

// Outcome is how a run the runner reported on concluded. A run with no report, or an
// undecodable one, is a protocol error; that is the provider's call, because only the
// provider knows what its transport saw.
type Outcome int

const (
	// Completed: the plan ran to its normal conclusion, stop on first failure included.
	Completed Outcome = iota + 1
	// SetupFailed: the runner reported a structured failure around step execution
	// (an illegal file path, an unwritable file, an over-budget result).
	SetupFailed
	// TimedOut: a step was killed by its own time budget.
	TimedOut
)

// Outcome classifies a decoded report and returns the detail a caller sees. A
// runner-reported failure wins. Otherwise a step killed by its own time budget makes
// the run timed out, not completed: steps stop on the first failure, so a timed-out
// step is where the plan stopped, and a caller keying on the outcome alone must not
// read a hung step as a clean run.
func (r Report) Outcome() (Outcome, string) {
	if r.Err != "" {
		return SetupFailed, r.Err
	}
	for i, st := range r.Steps {
		if st.TimedOut {
			return TimedOut, fmt.Sprintf("step %d exceeded its time budget", i+1)
		}
	}
	return Completed, ""
}
