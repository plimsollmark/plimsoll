package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// smokeScript is a session whose calls answer from a script: what each snippet
// prints and what each cell answers, in order.
type smokeScript struct {
	langs  []Language
	js     []string
	jsExit map[int]int   // the exit code of the nth snippet, when not 0
	jsErr  map[int]error // the error the nth snippet returns instead of a result
	cells  []CellResult
	mu     sync.Mutex
	nJS    int
	nCells int
	done   chan struct{}
	once   sync.Once
}

func (s *smokeScript) OpenSession(context.Context, SessionOptions) (Session, error) { return s, nil }
func (s *smokeScript) SupportsSessions() bool                                       { return true }
func (s *smokeScript) SessionEnvironments() Environments {
	return Environments{Project: PayloadEnvironment{Languages: s.langs}}
}
func (s *smokeScript) Isolation() IsolationClass             { return IsolationContainer }
func (s *smokeScript) Environments() Environments            { return Environments{} }
func (s *smokeScript) ExpiresAt() time.Time                  { return time.Now().Add(time.Hour) }
func (s *smokeScript) Suspend(context.Context) (bool, error) { return true, nil }
func (s *smokeScript) Done() <-chan struct{}                 { return s.done }

func (s *smokeScript) RunProject(context.Context, ProjectRequest) (ProjectResult, error) {
	return ProjectResult{}, ErrUnsupported
}

func (s *smokeScript) RunJavaScript(context.Context, Request) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.nJS
	s.nJS++
	if err := s.jsErr[n]; err != nil {
		return Result{}, err
	}
	return Result{Stdout: s.js[n] + "\n", ExitCode: s.jsExit[n]}, nil
}

func (s *smokeScript) RunCell(context.Context, CellRequest) (CellResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := s.cells[s.nCells]
	s.nCells++
	return res, nil
}

func (s *smokeScript) Close(context.Context) error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *smokeScript) Err() error {
	select {
	case <-s.done:
		return &SessionEndedError{Reason: SessionClosed}
	default:
		return nil
	}
}

// Each check the startup smoke test makes fails it when the session breaks that
// promise, and a session that keeps them all passes.
func TestSessionSmokeTestChecks(t *testing.T) {
	t.Parallel()
	good := func() *smokeScript {
		return &smokeScript{
			js:     []string{"4242", "gone kept", "1 ", "kept", ""},
			jsExit: map[int]int{4: 3},
			cells: []CellResult{
				{},
				{Stdout: "42\n"},
				{Stdout: "'number'\n"},
			},
			done: make(chan struct{}),
		}
	}
	for _, c := range []struct {
		name  string
		spoil func(*smokeScript)
		want  string
	}{
		{"keeps every promise", func(*smokeScript) {}, ""},
		{"a process outlives the sweep", func(s *smokeScript) { s.js[1] = "alive kept" }, "want the process gone"},
		{"a file is lost between calls", func(s *smokeScript) { s.js[1] = "gone " }, "want the process gone and the file kept"},
		{"the interpreter forgets", func(s *smokeScript) { s.cells[1] = CellResult{Stdout: "NaN\n"} }, "want 42"},
		{"a call opens a relay's pipes", func(s *smokeScript) { s.js[2] = "1 31/0,31/1" }, "want relays found and none opened"},
		{"no relay to check", func(s *smokeScript) { s.js[2] = "0 " }, "want relays found and none opened"},
		{"a suspend loses the file", func(s *smokeScript) { s.js[3] = "" }, "want it kept"},
		{"a fresh interpreter not said", func(s *smokeScript) { s.cells[2] = CellResult{Stdout: "'undefined'\n"} }, "saying its interpreter is fresh: false"},
		{"a fresh interpreter said", func(s *smokeScript) { s.cells[2] = CellResult{Stdout: "'undefined'\n", InterpreterStarted: true} }, ""},
		{"a failing call is an error", func(s *smokeScript) { s.jsErr = map[int]error{4: errors.New("docker could not run the call")} }, "came back as an error, not a result"},
		{"a failing call's exit is lost", func(s *smokeScript) { s.jsExit = nil }, "came back with exit 0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := good()
			c.spoil(s)
			err := SessionSmokeTest(context.Background(), s, SessionOptions{})
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("want a pass, got %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
		})
	}
}

// The smoke test runs a keep-state check in every cell language the provider states,
// and refuses a stated language it has no check for.
func TestSessionSmokeTestRunsEveryStatedLanguage(t *testing.T) {
	t.Parallel()
	script := func(langs []Language, cells ...CellResult) *smokeScript {
		return &smokeScript{langs: langs, js: []string{"4242", "gone kept", "2 ", "kept", ""}, jsExit: map[int]int{4: 3}, cells: cells, done: make(chan struct{})}
	}
	both := []Language{LanguageJavaScript, LanguagePython}
	for _, c := range []struct {
		name string
		s    *smokeScript
		want string
	}{
		{"both keep state", script(both, CellResult{}, CellResult{Stdout: "42\n"}, CellResult{}, CellResult{Stdout: "42\n"}, CellResult{Stdout: "'number'\n"}), ""},
		{"python forgets", script(both, CellResult{}, CellResult{Stdout: "42\n"}, CellResult{}, CellResult{Stdout: "NameError\n", InterpreterStarted: true}), "the next python cell"},
		{"a language without a check", script([]Language{LanguageJavaScript, "ruby"}, CellResult{}, CellResult{Stdout: "42\n"}), `cell language "ruby", which has no startup check`},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := SessionSmokeTest(context.Background(), c.s, SessionOptions{})
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("want a pass, got %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
		})
	}
}

// A deadline before a cell's code was sent is a refusal marked not dispatched, read
// as DeadlineExceeded (v0.15.0 review, L3).
func TestUnsentCellIsARefusal(t *testing.T) {
	err, ok := RefuseCell(context.Background(), fmt.Errorf("x: %w", sessionkit.ErrUnsent), nil)
	if !ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RefuseCell = %v, %v", err, ok)
	}
	if reason, marked := NotDispatchedReason(err); !marked || reason != RefusalCapacity {
		t.Fatalf("not marked: %v %v", reason, marked)
	}
}
