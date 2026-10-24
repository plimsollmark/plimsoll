// Package fanjob is the fan-out engine the fan-out examples share: one job cut into pieces,
// every piece sent twice, to two different rooms (a room is one daemon serving one provider at
// one isolation tier), reached through package placement as one pool, every call signed into
// one bundle; and the reading of a published bundle back into who ran what, checked.
//
// A Job supplies its pieces, each piece's program (a JavaScript snippet, so every room, the
// WebAssembly one included, can run it) and the prefix of its trace IDs. Everything else, the
// rooms and daemons files, the spread of pieces over rooms, retrying a refusal for capacity,
// the signing harness, verifying a bundle and attributing each run to its room, is here.
package fanjob

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/client"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/placement"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Room is one place the job can run: one daemon, one provider, one tier.
type Room struct {
	ID           string  `json:"id"`
	Label        string  `json:"label"`
	Where        string  `json:"where"`
	Provider     string  `json:"provider"`
	Tier         string  `json:"tier"`
	Engine       string  `json:"engine"` // the JavaScript engine the room runs snippets in
	Cloud        bool    `json:"cloud,omitempty"`
	USDPerSecond float64 `json:"usd_per_second,omitempty"`
}

// Daemon is how to reach a room on one run, or why it sits the run out.
type Daemon struct {
	URL         string `json:"url"`
	TokenFile   string `json:"token_file"`
	Concurrency int    `json:"concurrency"`
	Skip        string `json:"skip,omitempty"`
}

// RunFile is the run's own account of what the bundle cannot hold: when it started and
// ended, which rooms did not take part and why, and calls that came back with no record.
type RunFile struct {
	Started  time.Time         `json:"started"`
	Ended    time.Time         `json:"ended"`
	NotRun   map[string]string `json:"not_run"`
	Failures []Failure         `json:"failures"`
}

// Failure is a call that came back with no record.
type Failure struct {
	Room  string `json:"room"`
	Piece [2]int `json:"piece"`
	Error string `json:"error"`
}

// Job is what a fan-out runs.
type Job interface {
	// Prefix starts every trace ID of the job's calls.
	Prefix() string
	// Pieces are the job's pieces, by two coordinates each, in the order they are sent.
	Pieces() [][2]int
	// Program is the JavaScript one piece runs.
	Program(p [2]int) string
}

// CheckRooms refuses rooms a record could not tell apart: ids, and provider and tier pairs,
// must be unique, and each room names its engine and a real tier.
func CheckRooms(rooms []Room) error {
	seen := map[string]bool{}
	for _, r := range rooms {
		key := r.Provider + "/" + r.Tier
		if r.ID == "" || seen[r.ID] || seen[key] {
			return fmt.Errorf("rooms.json: room %q: ids, and provider and tier pairs, must be unique (a record names its provider and tier, which must tell its room from the others)", r.ID)
		}
		if r.Engine == "" {
			return fmt.Errorf("rooms.json: room %q names no JavaScript engine", r.ID)
		}
		if sandbox.ParseIsolationClass(r.Tier).String() != r.Tier || r.Tier == "none" {
			return fmt.Errorf("rooms.json: room %q: tier %q is not process, container, kernel or vm", r.ID, r.Tier)
		}
		seen[r.ID], seen[key] = true, true
	}
	return nil
}

// Assign gives piece i two different rooms, spreading both copies evenly: the first copy goes
// round the rooms in order, the second a rotating distance ahead.
func Assign(pieces int, rooms []string) [][2]string {
	n := len(rooms)
	out := make([][2]string, pieces)
	for i := range out {
		off := 1 + (i/n)%(n-1)
		out[i] = [2]string{rooms[i%n], rooms[(i+off)%n]}
	}
	return out
}

// Trace names one call: the room it was sent to, the piece and which of its two copies. The
// client sends it with the request, and the harness signs the stored request whole, so the
// bundle says which room each run was sent to.
func Trace(prefix, room string, p [2]int, which int) string {
	return fmt.Sprintf("%s.%s.%d.%d.%d", prefix, room, p[0], p[1], which)
}

// RunAndPublish runs the job into a staging directory beside dir and replaces the published
// bundle, key and run file only when the staged run loads (verifies and attributes), so a run
// that fails leaves the published files as they were.
func RunAndPublish(ctx context.Context, dir string, rooms []Room, ds map[string]Daemon, job Job) error {
	stage, err := os.MkdirTemp(filepath.Dir(dir), ".fanout-staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := Run(ctx, stage, rooms, ds, job); err != nil {
		return err
	}
	if _, err := Load(stage, rooms, job); err != nil {
		return fmt.Errorf("the new run does not load, so nothing was published: %w", err)
	}
	for _, name := range []string{"bundle.jsonl", "harness.pub", "run.json"} {
		if err := os.Rename(filepath.Join(stage, name), filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// Run sends every piece twice and signs every call into dir/bundle.jsonl with a key made for
// the run, whose public half goes to dir/harness.pub; the private half is never written.
func Run(ctx context.Context, dir string, rooms []Room, ds map[string]Daemon, job Job) error {
	privPEM, pubPEM, err := attest.GenerateKey()
	if err != nil {
		return err
	}
	key, err := attest.ParsePrivateKey(privPEM)
	if err != nil {
		return err
	}
	bundle, err := os.Create(filepath.Join(dir, "bundle.jsonl"))
	if err != nil {
		return err
	}
	defer bundle.Close()
	harness := attest.NewHarness(attest.NewSigner(key), bundle)

	out := RunFile{Started: time.Now().UTC().Truncate(time.Second), NotRun: map[string]string{}, Failures: []Failure{}}
	var backends []placement.Backend
	var ids []string
	sems := map[string]chan struct{}{}
	byID := map[string]Room{}
	for _, r := range rooms {
		byID[r.ID] = r
		d, ok := ds[r.ID]
		if !ok {
			out.NotRun[r.ID] = "no daemon was given for it on this run"
			continue
		}
		if d.Skip != "" {
			out.NotRun[r.ID] = d.Skip
			continue
		}
		c, reason := dial(ctx, r, d, harness)
		if reason != "" {
			out.NotRun[r.ID] = reason
			continue
		}
		backends = append(backends, placement.Backend{Name: r.ID, Client: c})
		ids = append(ids, r.ID)
		sems[r.ID] = make(chan struct{}, max(1, d.Concurrency))
		fmt.Printf("room %-18s ready\n", r.ID)
	}
	if len(ids) < 2 {
		return fmt.Errorf("only %d rooms answered; two copies of each piece need at least two: %v", len(ids), out.NotRun)
	}
	pool, err := placement.New(backends, time.Hour)
	if err != nil {
		return err
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	done := 0
	pieces := job.Pieces()
	pairs := Assign(len(pieces), ids)
	for i, pair := range pairs {
		p := pieces[i]
		code := job.Program(p)
		for which, id := range pair {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := call(ctx, sems[id], func() error {
					req := sandbox.Request{Code: code, Timeout: time.Minute, MinimumIsolation: sandbox.ParseIsolationClass(byID[id].Tier)}
					_, _, err := pool.RunJavaScript(client.NewTraceContext(ctx, Trace(job.Prefix(), id, p, which)), req, placement.Requirement{Backend: id})
					return err
				})
				mu.Lock()
				defer mu.Unlock()
				done++
				if err != nil {
					out.Failures = append(out.Failures, Failure{Room: id, Piece: p, Error: failureClass(err)})
					fmt.Printf("%-18s piece %d,%d: %v\n", id, p[0], p[1], err)
				}
				if done%32 == 0 {
					fmt.Printf("%d of %d runs\n", done, 2*len(pairs))
				}
			}()
		}
	}
	wg.Wait()
	if err := harness.Checkpoint(); err != nil {
		return err
	}
	out.Ended = time.Now().UTC().Truncate(time.Second)
	slices.SortFunc(out.Failures, func(a, b Failure) int {
		return cmp.Or(cmp.Compare(a.Room, b.Room), cmp.Compare(a.Piece[1], b.Piece[1]), cmp.Compare(a.Piece[0], b.Piece[0]))
	})
	if err := bundle.Sync(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "harness.pub"), pubPEM, 0o644); err != nil {
		return err
	}
	return WriteJSON(filepath.Join(dir, "run.json"), out)
}

// call runs one request within its room's limit. A refusal made before anything ran for
// capacity (a room whose warm pods are all in use) or the environment (a pod that could not
// be claimed in time) is tried again with a growing wait until two minutes have passed; a
// refusal of the request itself (request, permission, protocol, unsupported, isolation), any
// other error, and a cancelled run end it.
func call(ctx context.Context, sem chan struct{}, send func() error) error {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-sem }()
	deadline := time.Now().Add(2 * time.Minute)
	err := send()
	for wait := time.Second; err != nil; wait *= 2 {
		reason, ok := sandbox.NotDispatchedReason(err)
		if !ok || (reason != sandbox.RefusalCapacity && reason != sandbox.RefusalEnvironment) || time.Now().Add(wait).After(deadline) {
			return err
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
		err = send()
	}
	return nil
}

// dial makes the room's client, recording into the harness, and checks that the daemon
// states the provider and tier the room claims. A non-empty reason means the room sits out.
func dial(ctx context.Context, r Room, d Daemon, rec client.Recorder) (*client.Remote, string) {
	tok, err := os.ReadFile(d.TokenFile)
	if err != nil {
		return nil, "its token could not be read"
	}
	c, err := client.New(d.URL, client.WithToken(strings.TrimSpace(string(tok))), client.WithRecorder(rec))
	if err != nil {
		return nil, "its daemon address was refused by the client"
	}
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	info, err := c.Describe(dctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "room %s: describe: %v\n", r.ID, err)
		return nil, "its daemon did not answer"
	}
	if info.Sandbox != r.Provider || info.Isolation.String() != r.Tier {
		return nil, fmt.Sprintf("its daemon states provider %s at the %s tier, not %s at %s", info.Sandbox, info.Isolation, r.Provider, r.Tier)
	}
	return c, ""
}

// failureClass names a failed call without echoing what the daemon said.
func failureClass(err error) string {
	if reason, ok := sandbox.NotDispatchedReason(err); ok {
		return "refused before dispatch (" + reason.String() + "), so nothing ran"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "ran out of time with no record"
	}
	return "failed with no record, so the code may have run"
}

// RoomRun is a room as a published run shows it.
type RoomRun struct {
	Room
	Runs     int
	MedianMs int64
	Cost     float64
	NotRun   string
}

// PieceRun is one piece as a published run shows it: the rooms that ran its copies, in bundle
// order, how long each took, and each copy's output (nil when the run did not finish cleanly).
type PieceRun struct {
	P       [2]int
	Rooms   []string
	Ms      []int64
	Outputs [][]byte
}

// Loaded is a published run, read back from its files and checked.
type Loaded struct {
	Rooms    []RoomRun
	NotRun   map[string]string
	Pieces   []PieceRun
	Runs     int
	Tiers    int
	Clouds   int // cloud rooms that ran
	Failures []Failure
	Started  time.Time
	Ended    time.Time
	Harness  string // the harness key's ID
}

// Load verifies dir's bundle under dir/harness.pub, refuses session calls and closes, and
// attributes every run: its program says which piece it is, its trace ID which room it was
// sent to and which copy, and its signed record must state that room's provider and tier. A
// trace may run once.
func Load(dir string, rooms []Room, job Job) (*Loaded, error) {
	var rn RunFile
	if err := ReadJSON(filepath.Join(dir, "run.json"), &rn); err != nil {
		return nil, err
	}
	pubPEM, err := os.ReadFile(filepath.Join(dir, "harness.pub"))
	if err != nil {
		return nil, err
	}
	pub, err := attest.ParsePublicKey(pubPEM)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, "bundle.jsonl"))
	if err != nil {
		return nil, err
	}
	entries, err := attest.ReadBundle(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	v := attest.NewVerifier(pub)
	rep, err := attest.VerifyBundle(entries, v)
	if err != nil {
		return nil, fmt.Errorf("bundle.jsonl does not verify under harness.pub: %w", err)
	}
	if len(rep.Sessions) > 0 {
		return nil, errors.New("bundle.jsonl holds session calls; every fan-out run is a single run")
	}

	pieces := job.Pieces()
	l := &Loaded{NotRun: rn.NotRun, Failures: rn.Failures, Started: rn.Started, Ended: rn.Ended,
		Harness: attest.KeyID(pub), Pieces: make([]PieceRun, len(pieces))}
	pieceOf := map[string]int{}
	for i, p := range pieces {
		l.Pieces[i].P = p
		pieceOf[job.Program(p)] = i
	}
	roomOf := map[string]int{}
	for i, r := range rooms {
		roomOf[r.ID] = i
		l.Rooms = append(l.Rooms, RoomRun{Room: r, NotRun: rn.NotRun[r.ID]})
	}
	seen := map[string]bool{}
	ms := make([][]int64, len(rooms))
	prefix := job.Prefix()
	for n, e := range entries {
		if e.Request == nil {
			if len(e.Envelope.Signatures) > 0 {
				return nil, fmt.Errorf("line %d: a session close; every fan-out run is a single run", n+1)
			}
			continue // a checkpoint
		}
		rec, err := v.Verify(e.Envelope)
		if err != nil {
			return nil, err
		}
		var req plimsollv1.RunRequest
		var resp plimsollv1.RunResponse
		if err := proto.Unmarshal(e.Request, &req); err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		if err := proto.Unmarshal(e.Response, &resp); err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		pi, ok := pieceOf[req.GetJavascript().GetCode()]
		if !ok {
			return nil, fmt.Errorf("line %d: a request that is no piece's program", n+1)
		}
		// The room comes from the trace ID the harness signed with the request; the record
		// must then state that room's provider and tier.
		var id string
		var a, b, which int
		trace := req.GetTraceId()
		if k, err := fmt.Sscanf(strings.ReplaceAll(strings.TrimPrefix(trace, prefix+"."), ".", " "), "%s %d %d %d", &id, &a, &b, &which); err != nil || k != 4 ||
			Trace(prefix, id, [2]int{a, b}, which) != trace || which < 0 || which > 1 {
			return nil, fmt.Errorf("line %d: trace id %q does not name a room, a piece and a copy", n+1, trace)
		}
		ri, ok := roomOf[id]
		if !ok {
			return nil, fmt.Errorf("line %d: sent to room %q, which rooms.json does not list", n+1, id)
		}
		if p := pieces[pi]; p != [2]int{a, b} {
			return nil, fmt.Errorf("line %d: the trace names piece %d,%d but the request is piece %d,%d's program", n+1, a, b, p[0], p[1])
		}
		if got := rec.Provider + "/" + sandbox.ParseIsolationClass(rec.Isolation).String(); got != l.Rooms[ri].Provider+"/"+l.Rooms[ri].Tier {
			return nil, fmt.Errorf("line %d: sent to room %s, but the record states %s", n+1, id, got)
		}
		if seen[trace] {
			return nil, fmt.Errorf("line %d: a second run of %s", n+1, trace)
		}
		seen[trace] = true
		took := rec.Ended.Sub(rec.Started).Milliseconds()
		l.Runs++
		l.Rooms[ri].Runs++
		ms[ri] = append(ms[ri], took)
		l.Rooms[ri].Cost += float64(took) / 1000 * l.Rooms[ri].USDPerSecond
		pc := &l.Pieces[pi]
		pc.Rooms = append(pc.Rooms, l.Rooms[ri].ID)
		pc.Ms = append(pc.Ms, took)
		js := resp.GetJavascript()
		if js.GetExitCode() != 0 || js.GetTimedOut() || js.GetStdoutTruncated() {
			pc.Outputs = append(pc.Outputs, nil)
			continue
		}
		pc.Outputs = append(pc.Outputs, js.GetStdout())
	}
	tiers := map[string]bool{}
	for i := range l.Rooms {
		if l.Rooms[i].Runs > 0 {
			tiers[l.Rooms[i].Tier] = true
			l.Rooms[i].MedianMs = median(ms[i])
			if l.Rooms[i].Cloud {
				l.Clouds++
			}
		}
	}
	l.Tiers = len(tiers)
	return l, nil
}

// Disagreement says why a piece's two copies do not count as one answer, or "" when they
// do: exactly two runs, in two rooms, both finished cleanly, the same bytes.
func (p PieceRun) Disagreement() string {
	switch {
	case len(p.Outputs) != 2:
		return fmt.Sprintf("%d signed runs, not 2", len(p.Outputs))
	case p.Rooms[0] == p.Rooms[1]:
		return "both runs in one room"
	case p.Outputs[0] == nil || p.Outputs[1] == nil:
		return "a run did not finish cleanly"
	case !bytes.Equal(p.Outputs[0], p.Outputs[1]):
		return "the two answers differ"
	}
	return ""
}

func median(xs []int64) int64 {
	s := slices.Clone(xs)
	slices.Sort(s)
	return s[len(s)/2]
}

// TierColor is one blue ramp, light to dark as isolation gets stronger (an ordinal scale,
// checked for step contrast on the light page).
var TierColor = map[string]string{"process": "#86b6ef", "container": "#3987e5", "kernel": "#1c5cab", "vm": "#0d366b"}

// ReadJSON decodes one JSON file into v.
func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// WriteJSON writes v as indented JSON with a final newline.
func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
