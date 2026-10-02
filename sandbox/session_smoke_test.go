package sandbox

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// smokeScript is a session whose calls answer from a script: what each snippet
// prints and what each cell answers, in order.
type smokeScript struct {
	langs  []Language
	js     []string
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
func (s *smokeScript) ExpiresAt() time.Time                  { return time.Now().Add(time.Hour) }
func (s *smokeScript) Suspend(context.Context) (bool, error) { return true, nil }
func (s *smokeScript) Done() <-chan struct{}                 { return s.done }

func (s *smokeScript) RunProject(context.Context, ProjectRequest) (ProjectResult, error) {
	return ProjectResult{}, ErrUnsupported
}

func (s *smokeScript) RunJavaScript(context.Context, Request) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.js[s.nJS]
	s.nJS++
	return Result{Stdout: out + "\n"}, nil
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
	good := func() *smokeScript {
		return &smokeScript{
			js: []string{"4242", "gone kept", "kept"},
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
		{"a suspend loses the file", func(s *smokeScript) { s.js[2] = "" }, "want it kept"},
		{"a fresh interpreter not said", func(s *smokeScript) { s.cells[2] = CellResult{Stdout: "'undefined'\n"} }, "saying its interpreter is fresh: false"},
		{"a fresh interpreter said", func(s *smokeScript) { s.cells[2] = CellResult{Stdout: "'undefined'\n", InterpreterStarted: true} }, ""},
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
	script := func(langs []Language, cells ...CellResult) *smokeScript {
		return &smokeScript{langs: langs, js: []string{"4242", "gone kept", "kept"}, cells: cells, done: make(chan struct{})}
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
