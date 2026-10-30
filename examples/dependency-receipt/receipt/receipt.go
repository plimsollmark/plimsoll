// Package receipt builds and checks the dependency behavior receipt: a signed in-toto
// statement of what the programs in one gVisor sandbox did, read from runsc's own syscall
// log outside the sandbox, and joined to the plimsoll run that sandbox served.
//
// The receipt is rebuilt, never trusted: Check reads the same log (and the same run record)
// and requires the signed predicate to be exactly what this package builds from them, so a
// signer who lists less than the log shows, or a log edited after signing, fails the check.
//
// The join to the run: runsc logs each container's OCI spec at boot, before any program in
// the sandbox runs, and the spec's io.kubernetes.cri.sandbox-uid annotation is the pod's UID.
// A plimsoll run record (version 4 on) states the instance that ran it, for a pod
// "k8s-pod-uid:" and the same UID. The receipt names the instance the log names, and refuses
// a record that names another.
package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/runsclog"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// PredicateType names the statement this package signs.
const PredicateType = "https://plimsollmark.github.io/plimsoll/dependency-behavior/v1"

// ObserverKind names the observer: runsc's strace debug log in its JSON form.
const ObserverKind = "gvisor-runsc-strace-json"

// Subject names.
const (
	LogSubject    = "runsc debug log"
	RecordSubject = "plimsoll run record"
)

// perRun lists the runsc configuration lines that name per-run paths (the log file and the
// panic log carry the container ID and the pod's name and UID). The configuration digest
// leaves them out, so two runs under one runtime handler share it: on the five fixtures every
// other line is identical.
var perRun = []string{"LogFilename", "PanicLog"}

// NotObserved is what a receipt cannot show, signed with every receipt so its limits travel
// with its claim.
var NotObserved = []string{
	"behavior the package keeps for later: one install and one import is one observation, and code that waits, or checks whether it is watched, shows nothing",
	"names looked up in DNS: a lookup shows as a datagram to port 53, not the name",
	"the destination of a datagram sent with sendmsg",
	"writes through shared memory mappings, sendfile, splice, copy_file_range and fallocate",
	"paths of calls that take no descriptor are copied from the program's memory before the call reads them, so a second thread can change them in between; files written are named from descriptors and are not affected",
	"the pod's whole life is one observation: a pod that served several calls shows all of them",
	"anything outside gVisor",
}

// Predicate is the receipt's claim.
type Predicate struct {
	Observer Observer `json:"observer"`
	Log      Log      `json:"log"`
	// Instance is the sandbox the log observed, as a plimsoll run record names it.
	Instance string `json:"instance"`
	// Run is the run record the receipt is joined to, when it is.
	Run *Run `json:"run,omitempty"`
	// Processes lists every process that made a call the reader follows and the programs
	// gVisor's loader started in it.
	Processes []*runsclog.Process `json:"processes"`
	// Effected holds the calls that returned success, and every file written.
	Effected Effected `json:"effected"`
	// Attempted holds the calls that returned an error: refused or failed, so the log shows
	// they did not do what they asked.
	Attempted Calls `json:"attempted"`
	// Undetermined holds the calls whose outcome the log does not show: a connection a
	// non-blocking connect started (EINPROGRESS: it may complete later, out of the log's
	// sight), and calls that never returned. Effected, Attempted and Undetermined partition
	// the calls; never read Attempted or Undetermined as "did not happen".
	Undetermined Calls `json:"undetermined"`
	// Unclear lists the entries the reader could not read as exactly one event.
	Unclear     []runsclog.Unclear `json:"unclear"`
	NotObserved []string           `json:"notObserved"`
}

// Observer is what watched and how it was configured.
type Observer struct {
	Kind  string `json:"kind"`
	Runsc string `json:"runsc"`
	// ConfigurationSHA256 is the SHA-256 of runsc's configuration lines as it logged them at
	// boot, in order, each followed by a newline, leaving out the per-run paths.
	ConfigurationSHA256 string   `json:"configurationSha256"`
	ConfigurationOmits  []string `json:"configurationOmits"`
	StraceSyscalls      []string `json:"straceSyscalls"`
	StraceLogSize       int      `json:"straceLogSize"`
	Network             string   `json:"network"`
}

// Log is the log the receipt was read from, as runsc wrote it.
type Log struct {
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
	Entries int    `json:"entries"`
	Calls   int    `json:"calls"`
}

// Run is the run record a receipt is joined to.
type Run struct {
	Record    string `json:"record"`
	Version   int    `json:"version"`
	Provider  string `json:"provider"`
	Isolation string `json:"isolation"`
}

// Effected holds what the log shows happened.
type Effected struct {
	Written []*runsclog.Written `json:"written"`
	Opened  []*runsclog.Opened  `json:"opened"`
	Changes []runsclog.Change   `json:"changes"`
	Network []runsclog.Net      `json:"network"`
}

// Calls holds the calls of one outcome other than success.
type Calls struct {
	Opened  []*runsclog.Opened `json:"opened"`
	Changes []runsclog.Change  `json:"changes"`
	Network []runsclog.Net     `json:"network"`
}

// The outcomes a call's result maps to.
const (
	effected = iota
	attempted
	undetermined
)

// outcome maps a call's result, as runsclog states it, to its outcome. EINPROGRESS (115 on
// every Linux architecture plimsoll runs on) is a non-blocking connect's normal answer: the
// connection was started, and whether it completed is decided later, by calls the log does
// not follow.
func outcome(result string) int {
	switch {
	case result == "ok":
		return effected
	case result == "unknown", strings.HasPrefix(result, "errno=115 "):
		return undetermined
	}
	return attempted
}

// ErrRefused means no receipt is built: the log cannot support the claim a receipt makes.
var ErrRefused = errors.New("receipt: refused")

// ErrMismatch means a signed receipt is not what its log and record rebuild.
var ErrMismatch = errors.New("receipt: the signed receipt is not what its evidence rebuilds")

var configRE = regexp.MustCompile(`^Config\.([A-Za-z0-9]+)(?: \(--[^()]*\))?: (.*)$`)

// Build reads one runsc boot log, as runsc wrote it, and returns the receipt's predicate and
// subjects. rec, when not nil, is the verified record of the run the sandbox served; its
// instance must be the log's. The caller verifies rec (attest.VerifyCall) before passing it.
func Build(log io.Reader, rec *sandbox.RunRecord) (Predicate, []attest.Subject, error) {
	h := sha256.New()
	n := &counter{}
	tee := io.TeeReader(log, io.MultiWriter(h, n))
	tr, err := runsclog.Read(tee)
	if err != nil {
		return Predicate{}, nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	// runsclog.Read reads to the end; drain anyway, so the digest is the whole input's.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return Predicate{}, nil, err
	}
	obs, err := observer(tr)
	if err != nil {
		return Predicate{}, nil, err
	}
	inst, err := instance(tr.Boot.Pods)
	if err != nil {
		return Predicate{}, nil, err
	}
	p := Predicate{
		Observer:    obs,
		Log:         Log{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n.n, Entries: tr.Entries, Calls: tr.Calls},
		Instance:    inst,
		Processes:   tr.Processes,
		Effected:    Effected{Written: tr.Written},
		Unclear:     tr.Unclear,
		NotObserved: NotObserved,
	}
	// by[outcome] is where calls of that outcome go; the effected side is Effected's.
	by := [3]*Calls{{}, &p.Attempted, &p.Undetermined}
	for _, o := range tr.Opened {
		c := by[outcome(o.Result)]
		c.Opened = append(c.Opened, o)
	}
	for _, x := range tr.Changes {
		c := by[outcome(x.Result)]
		c.Changes = append(c.Changes, x)
	}
	for _, x := range tr.Network {
		c := by[outcome(x.Result)]
		c.Network = append(c.Network, x)
	}
	p.Effected.Opened, p.Effected.Changes, p.Effected.Network = by[effected].Opened, by[effected].Changes, by[effected].Network
	// Empty lists encode as [], never null, so a reader sees the field and that it is empty.
	p.Effected.Opened = orEmpty(p.Effected.Opened)
	p.Effected.Changes = orEmpty(p.Effected.Changes)
	p.Effected.Network = orEmpty(p.Effected.Network)
	for _, c := range by[1:] {
		c.Opened, c.Changes, c.Network = orEmpty(c.Opened), orEmpty(c.Changes), orEmpty(c.Network)
	}
	subjects := []attest.Subject{{Name: LogSubject, Digest: map[string]string{"sha256": p.Log.SHA256}}}
	if rec != nil {
		if rec.Instance != inst {
			return Predicate{}, nil, fmt.Errorf("%w: the run record names instance %q, the log names %q", ErrRefused, rec.Instance, inst)
		}
		p.Run = &Run{Record: rec.SHA256, Version: rec.Version, Provider: rec.Provider, Isolation: rec.Isolation}
		subjects = append(subjects, attest.Subject{Name: RecordSubject, Digest: map[string]string{"sha256": rec.SHA256}})
	}
	return p, subjects, nil
}

// observer reads runsc's configuration from its boot lines and refuses a log whose tracing
// could leave out a call the reader follows.
func observer(tr *runsclog.Trace) (Observer, error) {
	cfg := map[string]string{}
	h := sha256.New()
	for _, line := range tr.Boot.Config {
		m := configRE.FindStringSubmatch(line)
		if m == nil {
			return Observer{}, fmt.Errorf("%w: a configuration line runsc logged is not in its usual form: %q", ErrRefused, line)
		}
		if _, dup := cfg[m[1]]; dup {
			return Observer{}, fmt.Errorf("%w: runsc logged its %s setting twice", ErrRefused, m[1])
		}
		cfg[m[1]] = m[2]
		if !slices.Contains(perRun, m[1]) {
			h.Write([]byte(line + "\n"))
		}
	}
	for name, want := range map[string]string{"Debug": "true", "Strace": "true", "DebugLogFormat": "json", "IOUring": "false"} {
		if got, ok := cfg[name]; !ok || got != want {
			return Observer{}, fmt.Errorf("%w: runsc's %s setting is %q, and a receipt needs %q", ErrRefused, name, got, want)
		}
	}
	// An empty list means every call is traced. Only explicit lists have been checked, so an
	// empty one is refused too, until a log made that way is.
	traced := strings.Split(cfg["StraceSyscalls"], ",")
	for _, call := range runsclog.Syscalls() {
		if !slices.Contains(traced, call) {
			return Observer{}, fmt.Errorf("%w: runsc did not trace %s, so the log cannot show it (its --strace-syscalls: %q)", ErrRefused, call, cfg["StraceSyscalls"])
		}
	}
	size, err := strconv.Atoi(cfg["StraceLogSize"])
	if err != nil {
		return Observer{}, fmt.Errorf("%w: runsc's StraceLogSize setting %q is not a number", ErrRefused, cfg["StraceLogSize"])
	}
	network, ok := cfg["Network"]
	if !ok {
		return Observer{}, fmt.Errorf("%w: runsc logged no network setting", ErrRefused)
	}
	slices.Sort(traced)
	return Observer{Kind: ObserverKind, Runsc: tr.Runsc, ConfigurationSHA256: hex.EncodeToString(h.Sum(nil)),
		ConfigurationOmits: perRun, StraceSyscalls: traced, StraceLogSize: size, Network: network}, nil
}

// instance is the one pod every container spec in the log names.
func instance(pods []string) (string, error) {
	if len(pods) == 0 {
		return "", fmt.Errorf("%w: the log holds no container spec, so it names no sandbox", ErrRefused)
	}
	if slices.Contains(pods, "") {
		return "", fmt.Errorf("%w: a container spec in the log names no pod", ErrRefused)
	}
	for _, uid := range pods[1:] {
		if uid != pods[0] {
			return "", fmt.Errorf("%w: the log's container specs name two pods, %q and %q", ErrRefused, pods[0], uid)
		}
	}
	inst := sandbox.PodInstance(pods[0])
	if inst == "" {
		return "", fmt.Errorf("%w: the pod UID %q is not one a run record can name", ErrRefused, pods[0])
	}
	return inst, nil
}

// Sign signs a receipt built by Build.
func Sign(s *attest.Signer, p Predicate, subjects []attest.Subject) (attest.Envelope, error) {
	return s.SignStatement(PredicateType, subjects, p)
}

// Check opens env under pub and confirms it is exactly the receipt log and rec rebuild. rec
// is the verified record the receipt names, or nil when it names none. It returns the
// rebuilt predicate. It proves who signed which receipt and that the receipt says no more
// and no less than the log; whether the log is the one runsc wrote for that pod is the
// signer's word, as the receipt's NotObserved and the documentation state.
func Check(env attest.Envelope, pub ed25519.PublicKey, log io.Reader, rec *sandbox.RunRecord) (Predicate, error) {
	var stated Predicate
	subs, err := attest.NewVerifier(pub).OpenStatement(env, PredicateType, &stated)
	if err != nil {
		return Predicate{}, err
	}
	switch {
	case stated.Run != nil && rec == nil:
		return Predicate{}, fmt.Errorf("%w: the receipt names run record %s; check it with that record", ErrMismatch, stated.Run.Record)
	case stated.Run == nil && rec != nil:
		return Predicate{}, fmt.Errorf("%w: the receipt names no run record, and one was given", ErrMismatch)
	case stated.Run != nil && stated.Run.Record != rec.SHA256:
		return Predicate{}, fmt.Errorf("%w: the receipt names run record %s, the record given is %s", ErrMismatch, stated.Run.Record, rec.SHA256)
	}
	rebuilt, want, err := Build(log, rec)
	if err != nil {
		return Predicate{}, err
	}
	if stated.Log.SHA256 != rebuilt.Log.SHA256 {
		return Predicate{}, fmt.Errorf("%w: the receipt is about log %s, the log given is %s", ErrMismatch, stated.Log.SHA256, rebuilt.Log.SHA256)
	}
	a, err := json.Marshal(stated)
	if err != nil {
		return Predicate{}, err
	}
	b, err := json.Marshal(rebuilt)
	if err != nil {
		return Predicate{}, err
	}
	if !bytes.Equal(a, b) {
		return Predicate{}, fmt.Errorf("%w: the log shows something other than the receipt states", ErrMismatch)
	}
	if fmt.Sprint(subs) != fmt.Sprint(want) {
		return Predicate{}, fmt.Errorf("%w: the receipt's subjects are not its log and record", ErrMismatch)
	}
	return rebuilt, nil
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

type counter struct{ n int64 }

func (c *counter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }
