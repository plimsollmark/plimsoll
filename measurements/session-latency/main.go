// Command session-latency times what an agent's code tool pays per call on each
// provider with sessions: a fresh run, a session's snippet call, a cell in a warm
// interpreter (JavaScript and Python), the first cell (which starts the
// interpreter), a call after an idle suspend, and the data-reload case (a fresh run
// that rebuilds an array every call against a cell that keeps it). It calls the
// providers directly, not through plimsolld; the TypeScript client's tests measured
// the daemon and client overhead at about 3 to 4 ms a round trip.
//
//	go run ./measurements/session-latency -provider docker            # runc
//	go run ./measurements/session-latency -provider docker -runtime runsc
//	go run ./measurements/session-latency -provider openshell         # SANDBOX_OPENSHELL_* set
//
// It writes docs/measurements/session-latency/<provider>[-<runtime>].json; the
// report command renders the page from those files.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/openshell"
)

// Sample is one measured operation: every repetition's wall time.
type Sample struct {
	Name   string    `json:"name"`
	Detail string    `json:"detail"`
	Ms     []float64 `json:"ms"`
}

// Run is one provider's measurements.
type Run struct {
	Provider  string    `json:"provider"`
	Runtime   string    `json:"runtime,omitempty"`
	Tier      string    `json:"tier"`
	Image     string    `json:"image"`
	Machine   string    `json:"machine"`
	When      time.Time `json:"when"`
	Reps      int       `json:"reps"`
	GapMs     int64     `json:"gapMs"`
	Samples   []Sample  `json:"samples"`
	Languages []string  `json:"languages"`
}

func main() {
	provider := flag.String("provider", "docker", "docker or openshell")
	rt := flag.String("runtime", "", "docker runtime (runsc for gVisor)")
	reps := flag.Int("reps", 15, "repetitions per operation")
	gap := flag.Duration("gap", 250*time.Millisecond, "untimed pause before each repetition: an agent's calls are seconds apart, and a docker session sweeps after answering")
	flag.Parse()
	ctx := context.Background()

	var sb sandbox.Sandbox
	image := "plimsoll/sandbox-python:latest"
	switch *provider {
	case "docker":
		d := sandbox.DefaultDocker("")
		d.Runtime = *rt
		d.ProjectImage = image
		sb = d
	case "openshell":
		p, err := openshell.FromEnv(os.Getenv)
		if err != nil {
			log.Fatal(err)
		}
		sb = p.Sandbox
		image = os.Getenv("SANDBOX_OPENSHELL_IMAGE")
	default:
		log.Fatalf("unknown provider %q", *provider)
	}
	if err := (sandbox.Provider{Sandbox: sb}).EnsureReady(ctx); err != nil {
		log.Fatalf("EnsureReady: %v", err)
	}
	sp := sb.(sandbox.SessionProvider)
	run := Run{Provider: *provider, Runtime: *rt, Tier: sb.IsolationClass().String(), Image: image,
		Machine: machine(), When: time.Now().UTC(), Reps: *reps, GapMs: gap.Milliseconds()}
	for _, l := range sp.SessionEnvironments().Project.Languages {
		run.Languages = append(run.Languages, string(l))
	}

	// timeWith runs setup untimed before each repetition, then times f.
	timeWith := func(name, detail string, setup func() error, f func() error) {
		s := Sample{Name: name, Detail: detail}
		for i := 0; i < *reps; i++ {
			if setup != nil {
				if err := setup(); err != nil {
					log.Fatalf("%s setup: %v", name, err)
				}
			}
			time.Sleep(*gap)
			start := time.Now()
			if err := f(); err != nil {
				log.Fatalf("%s: %v", name, err)
			}
			s.Ms = append(s.Ms, float64(time.Since(start).Microseconds())/1000)
		}
		run.Samples = append(run.Samples, s)
		fmt.Printf("%-34s median %7.1f ms\n", name, median(s.Ms))
	}
	time1 := func(name, detail string, f func() error) { timeWith(name, detail, nil, f) }
	ok := func(code int, err error, what string) error {
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("%s exited %d", what, code)
		}
		return nil
	}

	time1("fresh snippet", "a new sandbox per call: console.log(1)", func() error {
		r, err := sb.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)"})
		return ok(r.ExitCode, err, "snippet")
	})
	time1("fresh Python run", "a new sandbox per call: project, python3 main.py", func() error {
		r, err := sb.RunProject(ctx, sandbox.ProjectRequest{
			Files: []sandbox.File{{Path: "main.py", Content: "print(1)"}}, Steps: []string{"python3 main.py"}})
		if err == nil && r.Outcome != sandbox.ProjectOutcomeCompleted {
			err = fmt.Errorf("outcome %s", r.Outcome)
		}
		return err
	})
	var sessions []sandbox.Session
	open := func() (sandbox.Session, error) {
		s, err := sp.OpenSession(ctx, sandbox.SessionOptions{Lifetime: 10 * time.Minute, DiskBytes: 256 << 20})
		if err == nil {
			sessions = append(sessions, s)
		}
		return s, err
	}
	defer func() {
		for _, s := range sessions {
			_ = s.Close(ctx)
		}
		if d, ok := sb.(sandbox.Drainer); ok {
			_ = d.Drain(ctx)
		}
	}()
	time1("session open", "create, verify and list a session's sandbox", func() error {
		s, err := open()
		if err == nil {
			_ = s.Close(ctx)
		}
		return err
	})
	s, err := open()
	if err != nil {
		log.Fatal(err)
	}
	time1("session snippet call", "console.log(1) in an open session (openshell sweeps before answering, docker after)", func() error {
		r, err := s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)"})
		return ok(r.ExitCode, err, "snippet")
	})
	cell := func(lang sandbox.Language, code string) error {
		r, err := s.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: code, Timeout: 60 * time.Second})
		return ok(r.ExitCode, err, string(lang)+" cell: "+r.Stderr)
	}
	var fresh sandbox.Session
	openFresh := func() (err error) {
		if fresh != nil {
			_ = fresh.Close(ctx)
		}
		fresh, err = open()
		return err
	}
	timeWith("first JavaScript cell", "starts the interpreter (a new session, opened untimed)", openFresh, func() error {
		r, err := fresh.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: "1"})
		return ok(r.ExitCode, err, "first cell")
	})
	time1("warm JavaScript cell", "n = (globalThis.n ?? 0) + 1 in a live interpreter", func() error {
		return cell(sandbox.LanguageJavaScript, "globalThis.n = (globalThis.n ?? 0) + 1")
	})
	if slices.Contains(run.Languages, "python") {
		timeWith("first Python cell", "starts the interpreter (a new session, opened untimed)", openFresh, func() error {
			r, err := fresh.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguagePython, Code: "1"})
			return ok(r.ExitCode, err, "first cell")
		})
		time1("warm Python cell", "n = globals().get('n', 0) + 1 in a live interpreter", func() error {
			return cell(sandbox.LanguagePython, "n = globals().get('n', 0) + 1")
		})
		const build = "import numpy as np\na = np.random.default_rng(0).random(10_000_000)\n"
		time1("reload: fresh run per call", "every call builds a 10-million-value array (80 MB) and takes its mean", func() error {
			r, err := sb.RunProject(ctx, sandbox.ProjectRequest{
				Files: []sandbox.File{{Path: "main.py", Content: build + "print(a.mean())"}}, Steps: []string{"python3 main.py"},
				Timeout: 60 * time.Second})
			if err == nil && (r.Outcome != sandbox.ProjectOutcomeCompleted || r.Steps[0].ExitCode != 0) {
				err = fmt.Errorf("outcome %s: %+v", r.Outcome, r.Steps)
			}
			return err
		})
		if err := cell(sandbox.LanguagePython, build); err != nil {
			log.Fatal(err)
		}
		time1("reload: kept in the interpreter", "the array from an earlier cell: a.mean()", func() error {
			return cell(sandbox.LanguagePython, "a.mean()")
		})
	}
	time1("call after a suspend", "Suspend, then console.log(1): the resume is in the call", func() error {
		if _, err := s.Suspend(ctx); err != nil {
			return err
		}
		r, err := s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)"})
		return ok(r.ExitCode, err, "snippet")
	})

	name := *provider
	if *rt != "" {
		name += "-" + *rt
	}
	out := filepath.Join("docs", "measurements", "session-latency", name+".json")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		log.Fatal(err)
	}
	b, _ := json.MarshalIndent(run, "", "  ")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote", out)
}

func median(ms []float64) float64 {
	s := slices.Clone(ms)
	slices.Sort(s)
	return s[len(s)/2]
}

func machine() string {
	cpu := ""
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "model name") {
				cpu = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				break
			}
		}
	}
	return fmt.Sprintf("%s, %d CPUs, %s/%s", cpu, runtime.NumCPU(), runtime.GOOS, runtime.GOARCH)
}
