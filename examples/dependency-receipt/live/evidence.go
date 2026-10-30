package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/receipt"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/runsclog"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The published files, relative to the page's directory.
const (
	evidenceFile = "evidence.json"
	pageFile     = "index.html"
	bundleFile   = "bundle.jsonl"
	keyFile      = "harness.pub"
	droppedFile  = "tampered/network-connection-deleted.intoto.json.gz"
)

func logFile(fixture string) string     { return "logs/" + fixture + ".boot.json.gz" }
func receiptFile(fixture string) string { return "receipts/" + fixture + ".intoto.json.gz" }

// compileCache is where node keeps its compile cache when npm turns it on: the guest's
// temporary directory, under the node version and the uid.
const compileCache = "/tmp/node-compile-cache/"

// evidence is everything the page states, gathered from one live run and written beside
// the page as evidence.json. The page renders from it alone, and -verify rebuilds every
// part of it that comes from the bundle, the receipts and the logs published with it.
type evidence struct {
	Date        string            `json:"date"` // the first run's start, UTC
	Cluster     cluster           `json:"cluster"`
	Daemon      map[string]string `json:"daemon"` // plimsolld's settings, but the paths of its secret files
	Smoke       smoke             `json:"smoke"`  // the daemon's startup smoke test, as its log states it
	Build       build             `json:"build"`  // what plimsolld and the receipt command were built from
	Key         string            `json:"key"`    // the key ID of harness.pub, which signed the bundle and the receipts
	Bundle      bundleFacts       `json:"bundle"`
	Runs        []runFacts        `json:"runs"`
	Dropped     droppedFacts      `json:"dropped"`
	Edit        editFacts         `json:"edit"`
	NotObserved []string          `json:"not_observed"` // the list every receipt signs
	Transcripts []transcript      `json:"transcripts"`  // the receipt command, as it ran on the live run's files
}

// cluster is what the run read about the cluster, and what the receipts say of the observer.
type cluster struct {
	Kubernetes     string `json:"kubernetes"`
	Runtime        string `json:"container_runtime"`
	AgentSandbox   string `json:"agent_sandbox"`
	RuntimeClass   string `json:"runtime_class"`
	Handler        string `json:"handler"`
	Image          string `json:"image"`
	Runsc          string `json:"runsc"`
	Configuration  string `json:"runsc_configuration_sha256"`
	StraceSyscalls int    `json:"strace_syscalls"`
	StraceLogSize  int    `json:"strace_log_size"`
	Network        string `json:"runsc_network"`
}

// smoke is the line plimsolld logged when its startup smoke test passed on two pods of the
// pool: a transcript of the daemon's own words, which nothing published here re-derives.
type smoke struct {
	Tier     string            `json:"tier"`
	Kernel   string            `json:"kernel"`   // the first line of the guest's kernel log
	Swept    int               `json:"swept"`    // paths a write was tried at
	Writable []string          `json:"writable"` // where one succeeded
	Egress   map[string]string `json:"egress"`   // each outbound connection tried, and what came of it
}

// readSmoke finds the smoke test's line in plimsolld's log.
func readSmoke(path string) (smoke, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return smoke{}, err
	}
	for _, l := range strings.Split(string(raw), "\n") {
		var line struct {
			Msg string `json:"msg"`
			smoke
		}
		if json.Unmarshal([]byte(l), &line) == nil && line.Msg == "agentsandbox smoke passed" {
			return line.smoke, nil
		}
	}
	return smoke{}, fmt.Errorf("%s holds no line saying the startup smoke test passed", path)
}

type bundleFacts struct {
	SHA256 string `json:"sha256"`
	Lines  int    `json:"lines"`
	Runs   int    `json:"runs"`
}

// runFacts is one run: what plimsoll's record and the bundle say of it, and what its receipt
// says the programs in its pod did.
type runFacts struct {
	Fixture     string            `json:"fixture"`
	Line        int               `json:"line"`              // in the bundle, from 1
	Scripts     map[string]string `json:"scripts"`           // the package's install scripts, from the package.json the run sent
	Floor       string            `json:"minimum_isolation"` // the tier the request asked for at least
	Request     string            `json:"request_sha256"`
	Record      string            `json:"record_sha256"`
	Version     int               `json:"record_version"`
	Instance    string            `json:"instance"`
	Provider    string            `json:"provider"`
	Isolation   string            `json:"isolation"`
	Environment string            `json:"environment"`
	Started     string            `json:"started"`
	Millis      int64             `json:"ms"`
	Outcome     string            `json:"outcome"`
	Steps       []stepFacts       `json:"steps"`
	Log         logFacts          `json:"log"`
	Receipt     fileFacts         `json:"receipt"`
	Seen        seen              `json:"seen"`
}

type stepFacts struct {
	Command string `json:"command"`
	Exit    int32  `json:"exit"`
	Millis  int64  `json:"ms"`
	Stdout  string `json:"stdout"`
	Stderr  string `json:"stderr"`
}

type logFacts struct {
	File      string `json:"file"`
	GzipBytes int    `json:"gzip_bytes"`
	SHA256    string `json:"sha256"`   // of the log as runsc wrote it
	Instance  string `json:"instance"` // the pod the log's container specs name, as the receipt states it
	Bytes     int64  `json:"bytes"`
	Entries   int    `json:"entries"`
	Calls     int    `json:"calls"`
}

type fileFacts struct {
	File      string `json:"file"`
	GzipBytes int    `json:"gzip_bytes"`
	Bytes     int    `json:"bytes"`  // uncompressed, as the receipt command wrote it
	SHA256    string `json:"sha256"` // of those bytes
}

// seen is what one receipt states, as the page shows it: totals, and the processes grouped
// by who started them.
type seen struct {
	Processes int     `json:"processes"`
	Programs  int     `json:"programs"`
	Written   int     `json:"written"`
	Totals    sides   `json:"totals"`
	Unclear   int     `json:"unclear"`
	Groups    []group `json:"groups"`
}

type sides struct {
	Effected     counts `json:"effected"`
	Attempted    counts `json:"attempted"`
	Undetermined counts `json:"undetermined"`
}

type counts struct {
	Opened  int `json:"opened"`  // opens for writing
	Changes int `json:"changes"` // mkdir, rename, unlink and the rest
	Network int `json:"network"` // socket, connect, bind, listen, send
}

func (c counts) Sum() int { return c.Opened + c.Changes + c.Network }

// group is the processes one command started, with their calls.
type group struct {
	Kind         string `json:"kind"`             // sandbox, check, runner, step, script
	Step         int    `json:"step,omitempty"`   // a step's number, from 1
	Script       string `json:"script,omitempty"` // an install script's name in package.json
	Processes    []proc `json:"processes"`
	Written      int    `json:"written"`
	CompileCache int    `json:"compile_cache"` // of those, files under node's compile cache
	Counts       sides  `json:"counts"`
	Calls        []call `json:"calls"` // every call of the package's own groups; the others' calls but the effected opens, changes and new sockets
	Exit         *int   `json:"exit,omitempty"`
}

type proc struct {
	PID     int    `json:"pid"`
	Parent  int    `json:"parent,omitempty"`
	Exit    *int   `json:"exit,omitempty"`
	Command string `json:"command"` // the last program loaded into it, as its arguments; "" when none was
	Loaded  int    `json:"loaded"`  // programs loaded into it
}

type call struct {
	Side   string `json:"side"`
	Kind   string `json:"kind"`
	What   string `json:"what"`             // the path, or the address and port
	Detail string `json:"detail,omitempty"` // the address family, the socket type, the reader's note
	Result string `json:"result"`
	PID    int    `json:"pid"`
}

// Package reports whether the group is the package's own code: its install script, or the
// step that imports it.
func (g group) Package() bool { return g.Kind == "script" || (g.Kind == "step" && g.Step == 2) }

type droppedFacts struct {
	File      string       `json:"file"`
	GzipBytes int          `json:"gzip_bytes"`
	Fixture   string       `json:"fixture"`
	Side      string       `json:"side"`
	Call      runsclog.Net `json:"call"`
}

type editFacts struct {
	Fixture string `json:"fixture"`
	byteEdit
	SHA256 string `json:"sha256"` // of the changed log
}

// assembleAndPublish reads the last live run's scratch, checks every receipt against its
// log and run record, gathers what the page states and writes the page's directory.
func assembleAndPublish(c config) error {
	var setup rawSetup
	if err := readJSON(filepath.Join(c.work, "setup.json"), &setup); err != nil {
		return err
	}
	var transcripts []transcript
	if err := readJSON(filepath.Join(c.work, "transcripts.json"), &transcripts); err != nil {
		return err
	}
	var gone dropped
	if err := readJSON(filepath.Join(c.work, "tampered", "dropped.json"), &gone); err != nil {
		return err
	}
	var edit byteEdit
	if err := readJSON(filepath.Join(c.work, "tampered", "edit.json"), &edit); err != nil {
		return err
	}
	sm, err := readSmoke(filepath.Join(c.work, "plimsolld.log"))
	if err != nil {
		return err
	}
	if err := clearPublished(c.out); err != nil {
		return err
	}
	for _, d := range []string{"logs", "receipts", "tampered"} {
		if err := os.MkdirAll(filepath.Join(c.out, d), 0o755); err != nil {
			return err
		}
	}
	for _, f := range []string{bundleFile, keyFile} {
		b, err := os.ReadFile(filepath.Join(c.work, f))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(c.out, f), b, 0o644); err != nil {
			return err
		}
	}
	for _, r := range setup.Runs {
		b, err := os.ReadFile(filepath.Join(c.work, "logs", r.Fixture+".boot.json.gz"))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(c.out, logFile(r.Fixture)), b, 0o644); err != nil {
			return err
		}
		if err := gzipFile(filepath.Join(c.out, receiptFile(r.Fixture)), filepath.Join(c.work, "receipts", r.Fixture+".intoto.json")); err != nil {
			return err
		}
	}
	if err := gzipFile(filepath.Join(c.out, droppedFile), filepath.Join(c.work, "tampered", "network-connection-deleted.intoto.json")); err != nil {
		return err
	}

	ev := &evidence{
		Cluster: cluster{Kubernetes: setup.Kubernetes, Runtime: setup.Runtime, AgentSandbox: setup.AgentSandbox,
			RuntimeClass: setup.RuntimeClass, Handler: setup.Handler, Image: setup.Image},
		Daemon:      setup.Daemon,
		Smoke:       sm,
		Build:       setup.Build,
		Transcripts: transcripts,
		Dropped:     droppedFacts{File: droppedFile, Fixture: "network", Side: gone.Side, Call: gone.Call},
		Edit:        editFacts{Fixture: "network", byteEdit: edit},
	}
	for _, r := range setup.Runs {
		ev.Runs = append(ev.Runs, runFacts{Fixture: r.Fixture, Line: r.Line})
	}
	if err := gather(c.out, ev); err != nil {
		return err
	}
	return publish(c, ev)
}

// gather fills in, from the published bundle, receipts and logs, every part of ev those
// files decide, checking each receipt against its log and its run record as it goes, and
// both tampered copies, which must fail. assemble and -verify both call it: -verify on a
// copy of the published evidence, which must come out unchanged.
func gather(dir string, ev *evidence) error {
	pubPEM, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return err
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		return err
	}
	ev.Key = attest.KeyID(pub)
	verifier := attest.NewVerifier(pub)
	rawBundle, err := os.ReadFile(filepath.Join(dir, bundleFile))
	if err != nil {
		return err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(rawBundle))
	if err != nil {
		return fmt.Errorf("%s: %w", bundleFile, err)
	}
	report, err := attest.VerifyBundle(entries, verifier)
	if err != nil {
		return fmt.Errorf("%s: %w", bundleFile, err)
	}
	sum := sha256.Sum256(rawBundle)
	ev.Bundle = bundleFacts{SHA256: hex.EncodeToString(sum[:]), Lines: len(entries), Runs: report.Runs}
	if report.Runs != len(ev.Runs) || len(report.Sessions) != 0 {
		return fmt.Errorf("%s holds %d single runs and %d sessions; the evidence names %d runs", bundleFile, report.Runs, len(report.Sessions), len(ev.Runs))
	}

	var first time.Time
	records := map[string]*sandbox.RunRecord{}
	instances := map[string]bool{}
	for i := range ev.Runs {
		r := &ev.Runs[i]
		if r.Line < 1 || r.Line > len(entries) {
			return fmt.Errorf("the %s run names line %d of a %d-line bundle", r.Fixture, r.Line, len(entries))
		}
		e := entries[r.Line-1]
		rec, err := attest.VerifyCall(verifier, e)
		if err != nil {
			return fmt.Errorf("line %d: %w", r.Line, err)
		}
		req, resp := &plimsollv1.RunRequest{}, &plimsollv1.RunResponse{}
		if err := proto.Unmarshal(e.Request, req); err != nil {
			return err
		}
		if err := proto.Unmarshal(e.Response, resp); err != nil {
			return err
		}
		if instances[rec.Instance] {
			return fmt.Errorf("two runs name instance %s", rec.Instance)
		}
		instances[rec.Instance] = true
		records[r.Fixture] = &rec
		if first.IsZero() || rec.Started.Before(first) {
			first = rec.Started
		}
		r.Scripts, err = scriptsOf(req, r.Fixture)
		if err != nil {
			return err
		}
		r.Floor = req.GetMinimumIsolation()
		r.Request, r.Record, r.Version, r.Instance = rec.RequestSHA256, rec.SHA256, rec.Version, rec.Instance
		r.Provider, r.Isolation, r.Environment = rec.Provider, rec.Isolation, rec.Environment
		r.Started, r.Millis = rec.Started.UTC().Format(time.RFC3339Nano), rec.Ended.Sub(rec.Started).Milliseconds()
		r.Outcome = strings.ToLower(strings.TrimPrefix(resp.GetProject().GetOutcome().String(), "PROJECT_OUTCOME_"))
		r.Steps = nil
		for _, s := range resp.GetProject().GetSteps() {
			r.Steps = append(r.Steps, stepFacts{Command: s.GetCommand(), Exit: s.GetExitCode(), Millis: s.GetDurationMs(), Stdout: string(s.GetStdout()), Stderr: string(s.GetStderr())})
		}

		rawLog, gzLen, err := readPublishedLog(dir, logFile(r.Fixture))
		if err != nil {
			return err
		}
		env, rf, err := readReceipt(dir, receiptFile(r.Fixture))
		if err != nil {
			return err
		}
		p, err := receipt.Check(env, pub, bytes.NewReader(rawLog), &rec)
		if err != nil {
			return fmt.Errorf("the %s receipt: %w", r.Fixture, err)
		}
		r.Log = logFacts{File: logFile(r.Fixture), GzipBytes: gzLen, SHA256: p.Log.SHA256, Instance: p.Instance, Bytes: p.Log.Bytes, Entries: p.Log.Entries, Calls: p.Log.Calls}
		r.Receipt = rf
		if r.Seen, err = see(p, req, r.Scripts); err != nil {
			return fmt.Errorf("the %s receipt: %w", r.Fixture, err)
		}
		obs := cluster{Runsc: p.Observer.Runsc, Configuration: p.Observer.ConfigurationSHA256, StraceSyscalls: len(p.Observer.StraceSyscalls),
			StraceLogSize: p.Observer.StraceLogSize, Network: p.Observer.Network}
		if i == 0 {
			ev.Cluster.Runsc, ev.Cluster.Configuration, ev.Cluster.StraceSyscalls = obs.Runsc, obs.Configuration, obs.StraceSyscalls
			ev.Cluster.StraceLogSize, ev.Cluster.Network = obs.StraceLogSize, obs.Network
			ev.NotObserved = p.NotObserved
		} else if obs.Runsc != ev.Cluster.Runsc || obs.Configuration != ev.Cluster.Configuration || !slices.Equal(p.NotObserved, ev.NotObserved) {
			return fmt.Errorf("the %s receipt names another observer than the first run's", r.Fixture)
		}
	}
	ev.Date = first.UTC().Format("2006-01-02")

	// The receipt with a connection deleted: signed by the same key, and refused.
	rec := records[ev.Dropped.Fixture]
	if rec == nil {
		return fmt.Errorf("no %s run for the tampered receipt", ev.Dropped.Fixture)
	}
	rawLog, _, err := readPublishedLog(dir, logFile(ev.Dropped.Fixture))
	if err != nil {
		return err
	}
	env, df, err := readReceipt(dir, droppedFile)
	if err != nil {
		return err
	}
	ev.Dropped.GzipBytes = df.GzipBytes
	var stated receipt.Predicate
	if _, err := verifier.OpenStatement(env, receipt.PredicateType, &stated); err != nil {
		return fmt.Errorf("the tampered receipt's signature: %w", err)
	}
	if _, err := receipt.Check(env, pub, bytes.NewReader(rawLog), rec); !errors.Is(err, receipt.ErrMismatch) {
		return fmt.Errorf("the receipt with a connection deleted: the check said %v, want a mismatch", err)
	}
	honest, _, err := receipt.Build(bytes.NewReader(rawLog), rec)
	if err != nil {
		return err
	}
	missing, extra := missingNet(honest, stated)
	if len(missing) != 1 || extra || missing[0] != (dropped{Side: ev.Dropped.Side, Call: ev.Dropped.Call}) {
		return fmt.Errorf("the tampered receipt leaves out %v (and adds a call: %v), not the one connection the evidence names", missing, extra)
	}
	// Apart from that call it is the honest receipt, so the check's refusal is about the call.
	stated.Effected.Network, stated.Attempted.Network, stated.Undetermined.Network = honest.Effected.Network, honest.Attempted.Network, honest.Undetermined.Network
	if !bytes.Equal(mustJSON(honest), mustJSON(stated)) {
		return errors.New("the tampered receipt differs from the honest one in more than one network call")
	}

	// The log with one byte changed: still a log the reader reads, and refused.
	changed, err := applyEdit(rawLog, ev.Edit.byteEdit)
	if err != nil {
		return err
	}
	if _, _, err := receipt.Build(bytes.NewReader(changed), rec); err != nil {
		return fmt.Errorf("the changed log no longer reads as a log, so it shows a refusal, not a mismatch: %w", err)
	}
	cs := sha256.Sum256(changed)
	ev.Edit.SHA256 = hex.EncodeToString(cs[:])
	envNet, _, err := readReceipt(dir, receiptFile(ev.Edit.Fixture))
	if err != nil {
		return err
	}
	if _, err := receipt.Check(envNet, pub, bytes.NewReader(changed), rec); !errors.Is(err, receipt.ErrMismatch) {
		return fmt.Errorf("the log with one byte changed: the check said %v, want a mismatch", err)
	}

	// The join: the network log, with the quiet run's record, is refused before anything is
	// signed, since the record names another pod.
	if quiet := records["quiet"]; quiet == nil {
		return errors.New("no quiet run for the join's refusal")
	} else if _, _, err := receipt.Build(bytes.NewReader(rawLog), quiet); !errors.Is(err, receipt.ErrRefused) {
		return fmt.Errorf("the network log joined to the quiet run's record: %v, want a refusal", err)
	}
	return checkTranscripts(ev)
}

// missingNet lists the network calls honest states and stated does not, side by side, and
// whether stated holds any that honest does not.
func missingNet(honest, stated receipt.Predicate) (out []dropped, extra bool) {
	pairs := []struct {
		side           string
		honest, stated []runsclog.Net
	}{{"effected", honest.Effected.Network, stated.Effected.Network}, {"attempted", honest.Attempted.Network, stated.Attempted.Network},
		{"undetermined", honest.Undetermined.Network, stated.Undetermined.Network}}
	for _, p := range pairs {
		left := slices.Clone(p.stated)
		for _, n := range p.honest {
			if i := slices.Index(left, n); i >= 0 {
				left = slices.Delete(left, i, i+1)
			} else {
				out = append(out, dropped{Side: p.side, Call: n})
			}
		}
		extra = extra || len(left) > 0
	}
	return out, extra
}

// checkTranscripts holds what the receipt command printed on the live run to the evidence:
// each sign and check names its run's pod, log and record, and the two tampered checks
// exited 1 with the mismatch, the second naming the changed log.
func checkTranscripts(ev *evidence) error {
	want := map[string]func(t transcript) bool{}
	for _, r := range ev.Runs {
		says := func(t transcript) bool {
			return t.Exit == 0 && t.Stderr == "" && strings.Contains(t.Stdout, "sandbox "+r.Instance+",") &&
				strings.Contains(t.Stdout, "log sha256 "+r.Log.SHA256+";") && strings.Contains(t.Stdout, "joined to run record "+r.Record+" (")
		}
		want["sign "+r.Fixture], want["check "+r.Fixture] = says, says
	}
	const mismatch = "dependency-receipt: receipt: the signed receipt is not what its evidence rebuilds: "
	want["check a receipt with a connection deleted"] = func(t transcript) bool {
		return t.Exit == 1 && t.Stdout == "" && t.Stderr == mismatch+"the log shows something other than the receipt states\n"
	}
	var netLog, netPod, quietPod string
	for _, r := range ev.Runs {
		switch r.Fixture {
		case ev.Edit.Fixture:
			netLog, netPod = r.Log.SHA256, r.Instance
		case "quiet":
			quietPod = r.Instance
		}
	}
	want["sign the network log joined to the quiet run's record"] = func(t transcript) bool {
		return t.Exit == 1 && t.Stdout == "" && t.Stderr == fmt.Sprintf("dependency-receipt: receipt: refused: the run record names instance %q, the log names %q\n", quietPod, netPod)
	}
	want["check the receipt against the log with one byte changed"] = func(t transcript) bool {
		return t.Exit == 1 && t.Stdout == "" && t.Stderr == mismatch+"the receipt is about log "+netLog+", the log given is "+ev.Edit.SHA256+"\n"
	}
	if len(ev.Transcripts) != len(want) {
		return fmt.Errorf("%d transcripts of the receipt command, want %d", len(ev.Transcripts), len(want))
	}
	for _, t := range ev.Transcripts {
		ok := want[t.Name]
		if ok == nil || !ok(t) {
			return fmt.Errorf("the transcript %q is not what the evidence says it shows", t.Name)
		}
		delete(want, t.Name)
	}
	return nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// scriptsOf reads the install scripts of the fixture's package.json, as the run sent it.
func scriptsOf(req *plimsollv1.RunRequest, fixture string) (map[string]string, error) {
	want := "packages/" + fixture + "/package.json"
	for _, f := range req.GetProject().GetFiles() {
		if f.GetPath() != want {
			continue
		}
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal([]byte(f.GetContent()), &pkg); err != nil {
			return nil, fmt.Errorf("%s: %w", want, err)
		}
		out := map[string]string{}
		for _, name := range lifecycle {
			if s, ok := pkg.Scripts[name]; ok {
				out[name] = s
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("the run sent no %s", want)
}

// lifecycle are the scripts npm runs when it installs a package, in the order it runs them.
var lifecycle = []string{"preinstall", "install", "postinstall", "prepare"}

// checkPrefix starts the shell command plimsoll's agent-sandbox provider runs in each pod
// before any of a run's code: the kernel's boot line, the boot ID, the seccomp mode and the
// mount table (docs/agentsandbox.md, "What each run does", step 4).
const checkPrefix = "printf 'kernel %s\\n'"

// see groups a receipt's processes by the command that started them, and counts each
// group's calls on each side. A process belongs to its nearest ancestor (or itself) that
// is the root of a group: a step of the run (a shell running the step's exact command), an
// install script of the package (a shell running the script's exact command), plimsoll's
// runner (node /runner.mjs) or plimsoll's per-pod check; the processes under none of them
// are runsc's start of the pod and sandboxd.
func see(p receipt.Predicate, req *plimsollv1.RunRequest, scripts map[string]string) (seen, error) {
	s := seen{Processes: len(p.Processes), Written: len(p.Effected.Written), Unclear: len(p.Unclear)}
	byPID := map[int]*runsclog.Process{}
	for _, pr := range p.Processes {
		if byPID[pr.PID] != nil {
			// PIDs are per container, so two containers' processes can share one; the
			// receipt's calls name a PID alone, and could not be told apart.
			return s, fmt.Errorf("two processes have PID %d, so their calls cannot be told apart", pr.PID)
		}
		byPID[pr.PID] = pr
		s.Programs += len(pr.Programs)
	}
	steps := req.GetProject().GetSteps()
	type root struct {
		kind, script string
		step         int
	}
	roots := map[int]root{}
	for _, pr := range p.Processes {
		for _, g := range pr.Programs {
			a := g.Argv
			switch {
			case len(a) == 2 && a[0] == "node" && a[1] == "/runner.mjs":
				roots[pr.PID] = root{kind: "runner"}
			case len(a) == 3 && a[0] == "sh" && a[1] == "-c" && strings.HasPrefix(a[2], checkPrefix):
				roots[pr.PID] = root{kind: "check"}
			}
		}
		if len(pr.Programs) == 0 {
			continue
		}
		a := pr.Programs[0].Argv
		if len(a) != 3 || a[0] != "sh" || a[1] != "-c" {
			continue
		}
		if i := slices.Index(steps, a[2]); i >= 0 {
			roots[pr.PID] = root{kind: "step", step: i + 1}
		}
		for _, name := range lifecycle {
			if cmd, ok := scripts[name]; ok && cmd == a[2] {
				roots[pr.PID] = root{kind: "script", script: name}
			}
		}
	}
	key := func(r root) string { return fmt.Sprintf("%s/%d/%s", r.kind, r.step, r.script) }
	groups := map[string]*group{}
	var order []string
	groupOf := map[int]*group{}
	for _, pr := range p.Processes {
		r := root{kind: "sandbox"}
		for pid, hops := pr.PID, 0; pid != 0 && hops <= len(p.Processes); hops++ {
			if rr, ok := roots[pid]; ok {
				r = rr
				break
			}
			anc := byPID[pid]
			if anc == nil {
				break
			}
			pid = anc.Parent
		}
		k := key(r)
		g := groups[k]
		if g == nil {
			g = &group{Kind: r.kind, Step: r.step, Script: r.script, Calls: []call{}}
			groups[k] = g
			order = append(order, k)
		}
		cmd := ""
		if n := len(pr.Programs); n > 0 {
			cmd = strings.Join(pr.Programs[n-1].Argv, " ")
		}
		g.Processes = append(g.Processes, proc{PID: pr.PID, Parent: pr.Parent, Exit: pr.Exit, Command: cmd, Loaded: len(pr.Programs)})
		if _, isRoot := roots[pr.PID]; isRoot {
			g.Exit = pr.Exit
		}
		groupOf[pr.PID] = g
	}
	find := func(pid int) (*group, error) {
		if g := groupOf[pid]; g != nil {
			return g, nil
		}
		return nil, fmt.Errorf("a call names PID %d, which is in no process the receipt lists", pid)
	}
	for _, w := range p.Effected.Written {
		g, err := find(w.PID)
		if err != nil {
			return s, err
		}
		g.Written++
		if strings.HasPrefix(w.Path, compileCache) {
			g.CompileCache++
		}
		if g.Package() {
			g.Calls = append(g.Calls, call{Side: "effected", Kind: "write", What: fmt.Sprintf("%s (%d bytes)", w.Path, w.Bytes), Result: "ok", PID: w.PID})
		}
	}
	for _, side := range []struct {
		name string
		c    *counts
		of   func(*group) *counts
		set  []*runsclog.Opened
		ch   []runsclog.Change
		net  []runsclog.Net
	}{
		{"effected", &s.Totals.Effected, func(g *group) *counts { return &g.Counts.Effected }, p.Effected.Opened, p.Effected.Changes, p.Effected.Network},
		{"attempted", &s.Totals.Attempted, func(g *group) *counts { return &g.Counts.Attempted }, p.Attempted.Opened, p.Attempted.Changes, p.Attempted.Network},
		{"undetermined", &s.Totals.Undetermined, func(g *group) *counts { return &g.Counts.Undetermined }, p.Undetermined.Opened, p.Undetermined.Changes, p.Undetermined.Network},
	} {
		listed := func(g *group) bool { return g.Package() || side.name != "effected" }
		for _, o := range side.set {
			g, err := find(o.PID)
			if err != nil {
				return s, err
			}
			side.c.Opened++
			side.of(g).Opened++
			if listed(g) {
				what := o.Path
				if o.Reached != "" && o.Reached != o.Path {
					what += " (reached " + o.Reached + ")"
				}
				g.Calls = append(g.Calls, call{Side: side.name, Kind: openKind(o), What: what, Result: o.Result, PID: o.PID})
			}
		}
		for _, x := range side.ch {
			g, err := find(x.PID)
			if err != nil {
				return s, err
			}
			side.c.Changes++
			side.of(g).Changes++
			if listed(g) {
				what := x.Path
				if x.Path2 != "" {
					what += " to " + x.Path2
				}
				g.Calls = append(g.Calls, call{Side: side.name, Kind: x.Kind, What: what, Result: x.Result, PID: x.PID})
			}
		}
		for _, n := range side.net {
			g, err := find(n.PID)
			if err != nil {
				return s, err
			}
			side.c.Network++
			side.of(g).Network++
			if listed(g) || n.Kind != "socket" {
				what, detail := netWhat(n)
				g.Calls = append(g.Calls, call{Side: side.name, Kind: n.Kind, What: what, Detail: detail, Result: n.Result, PID: n.PID})
			}
		}
	}
	rank := map[string]int{"sandbox": 0, "check": 1, "runner": 2, "step": 3, "script": 3}
	slices.SortStableFunc(order, func(a, b string) int {
		ga, gb := groups[a], groups[b]
		if ra, rb := rank[ga.Kind], rank[gb.Kind]; ra != rb {
			return ra - rb
		}
		// Steps in order, each install script after the step that ran it (step 1).
		pos := func(g *group) int {
			if g.Kind == "script" {
				return 1*10 + 1 + slices.Index(lifecycle, g.Script)
			}
			return g.Step * 10
		}
		return pos(ga) - pos(gb)
	})
	for _, k := range order {
		s.Groups = append(s.Groups, *groups[k])
	}
	return s, nil
}

func openKind(o *runsclog.Opened) string {
	switch {
	case o.Create && o.Truncate:
		return "open to create or empty"
	case o.Create:
		return "open to create"
	case o.Truncate:
		return "open to empty"
	}
	return "open for writing"
}

// netWhat is a network call's destination (or, for a new socket, its family and type), and
// the rest the receipt says of it.
func netWhat(n runsclog.Net) (what, detail string) {
	var d []string
	switch {
	case n.Addr != "" && n.Port != 0:
		what = fmt.Sprintf("%s port %d", n.Addr, n.Port)
	case n.Addr != "":
		what = n.Addr
	case n.Port != 0:
		what = fmt.Sprintf("port %d", n.Port)
	}
	if what == "" && n.Kind == "socket" {
		what = strings.TrimSpace(n.Family + " " + n.Type)
	} else if n.Family != "" {
		d = append(d, n.Family)
	}
	if n.Note != "" {
		if what == "" {
			what = n.Note
		} else {
			d = append(d, n.Note)
		}
	}
	return what, strings.Join(d, ", ")
}

// readPublishedLog reads a published gzip log whole, and its compressed size.
func readPublishedLog(dir, rel string) ([]byte, int, error) {
	gz, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return nil, 0, err
	}
	raw, err := gunzip(gz, runsclog.MaxLogBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", rel, err)
	}
	return raw, len(gz), nil
}

// readReceipt reads a published gzip receipt and decodes its envelope as the receipt
// command does, refusing unknown fields.
func readReceipt(dir, rel string) (attest.Envelope, fileFacts, error) {
	gz, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return attest.Envelope{}, fileFacts{}, err
	}
	raw, err := gunzip(gz, attest.MaxLineBytes)
	if err != nil {
		return attest.Envelope{}, fileFacts{}, fmt.Errorf("%s: %w", rel, err)
	}
	var env attest.Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return attest.Envelope{}, fileFacts{}, fmt.Errorf("%s: %w", rel, err)
	}
	sum := sha256.Sum256(raw)
	return env, fileFacts{File: rel, GzipBytes: len(gz), Bytes: len(raw), SHA256: hex.EncodeToString(sum[:])}, nil
}

func gunzip(gz []byte, limit int64) ([]byte, error) {
	z, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer z.Close()
	raw, err := io.ReadAll(io.LimitReader(z, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("larger than %d bytes uncompressed", limit)
	}
	return raw, nil
}

// clearPublished removes what this program publishes in dir, and nothing else: -out may
// name a directory that holds other files.
func clearPublished(dir string) error {
	for _, name := range []string{evidenceFile, pageFile, bundleFile, keyFile, "logs", "receipts", "tampered"} {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// gzipFile writes src gzip-compressed at dst, with no name or time in the header.
func gzipFile(dst, src string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeGzip(dst, b)
}

// publish writes evidence.json and the page, refusing output that holds a path or name of
// the machine that ran it.
func publish(c config, ev *evidence) error {
	raw, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := noLocalPaths(raw, c.repo); err != nil {
		return err
	}
	page, err := render(ev)
	if err != nil {
		return err
	}
	if err := noLocalPaths(page, c.repo); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.out, evidenceFile), raw, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.out, pageFile), page, 0o644)
}

func noLocalPaths(b []byte, repo string) error {
	home, _ := os.UserHomeDir()
	for _, s := range []string{home, repo, os.Getenv("USER")} {
		if len(s) > 2 && bytes.Contains(b, []byte(s)) {
			return fmt.Errorf("the published output would hold %q, a path or name of this machine", s)
		}
	}
	return nil
}

func loadEvidence(dir string) (*evidence, error) {
	raw, err := os.ReadFile(filepath.Join(dir, evidenceFile))
	if err != nil {
		return nil, err
	}
	var ev evidence
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return nil, fmt.Errorf("%s: %w", evidenceFile, err)
	}
	return &ev, nil
}

// verifyPublished checks the published directory offline: gather, run again over the
// published files, must give exactly the evidence published (the bundle verifies, every
// receipt checks against its log and record, both tampered copies fail), and index.html
// must be exactly what evidence.json renders.
func verifyPublished(dir string) error {
	ev, err := loadEvidence(dir)
	if err != nil {
		return err
	}
	// The page first: it is cheap to render, and the rest reads every log several times.
	page, err := render(ev)
	if err != nil {
		return err
	}
	published, err := os.ReadFile(filepath.Join(dir, pageFile))
	if err != nil {
		return err
	}
	if !bytes.Equal(page, published) {
		return errors.New("index.html is not what evidence.json renders: run go run ./examples/dependency-receipt/live -render")
	}
	again, err := loadEvidence(dir)
	if err != nil {
		return err
	}
	if err := gather(dir, again); err != nil {
		return err
	}
	if !reflect.DeepEqual(ev, again) {
		a, _ := json.MarshalIndent(ev, "", " ")
		b, _ := json.MarshalIndent(again, "", " ")
		return fmt.Errorf("%s is not what the published files give: %s", evidenceFile, firstDiff(a, b))
	}
	return nil
}

// firstDiff names the first line where two renderings differ.
func firstDiff(a, b []byte) string {
	al, bl := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	for i := 0; i < len(al) && i < len(bl); i++ {
		if al[i] != bl[i] {
			return fmt.Sprintf("line %d states %s, the files give %s", i+1, strings.TrimSpace(al[i]), strings.TrimSpace(bl[i]))
		}
	}
	return fmt.Sprintf("%d lines against %d", len(al), len(bl))
}

// renderPublished rewrites index.html from the published evidence.json.
func renderPublished(dir string) error {
	ev, err := loadEvidence(dir)
	if err != nil {
		return err
	}
	page, err := render(ev)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, pageFile), page, 0o644)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
