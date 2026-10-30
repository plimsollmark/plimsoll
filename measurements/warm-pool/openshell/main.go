// Command openshell measures the openshell provider's session pool
// (SANDBOX_SESSION_POOL): the time from asking for a session to its first call's
// answer with no pool, against the same first call in a session opened ahead of time
// (with its interpreter not yet started and already started: what a pool could save),
// and against a session claimed from a pool. It also reads what a waiting session
// holds in memory. Like measurements/session-latency it calls the provider directly,
// not through plimsolld, against a gateway named by the SANDBOX_OPENSHELL_* settings.
//
//	go run ./measurements/warm-pool/openshell            # -pool 0 skips the pool
//
// It writes docs/measurements/warm-pool/openshell.json.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/openshell"
)

// Sample is one measured operation: every repetition's wall time in ms.
type Sample struct {
	Name string    `json:"name"`
	Ms   []float64 `json:"ms"`
}

// Run is one gateway's measurements.
type Run struct {
	Provider string    `json:"provider"`
	Tier     string    `json:"tier"`
	Image    string    `json:"image"`
	When     time.Time `json:"when"`
	Reps     int       `json:"reps"`
	PauseMs  int64     `json:"pauseMs"`
	Samples  []Sample  `json:"samples"`
	// BareMiB is docker's memory use for a waiting session's containers (the workload
	// and the gateway's supervisor beside it) with no interpreter started; WarmMiB with
	// both interpreters started.
	BareMiB []float64 `json:"bareMiB"`
	WarmMiB []float64 `json:"warmMiB"`
}

func main() {
	reps := flag.Int("reps", 15, "repetitions per operation")
	poolSize := flag.Int("pool", 2, "members of the measured pool; 0 measures no pool")
	pause := flag.Duration("pause", 3*time.Second, "untimed pause before each repetition, as between an agent's conversations")
	flag.Parse()
	ctx := context.Background()
	p, err := openshell.FromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if err := p.EnsureReady(ctx); err != nil {
		log.Fatalf("EnsureReady: %v", err)
	}
	sp := p.Sandbox.(sandbox.SessionProvider)
	// pooled is a second provider on the same gateway, with a pool: each provider
	// labels its own sandboxes, so the pool's refills never serve the no-pool opens.
	var pooled sandbox.SessionProvider
	if *poolSize > 0 {
		pp, err := openshell.FromEnv(os.Getenv)
		if err != nil {
			log.Fatal(err)
		}
		if err := pp.EnsureReady(ctx); err != nil {
			log.Fatalf("EnsureReady (pooled): %v", err)
		}
		if err := pp.Sandbox.(sandbox.SessionPool).StartSessionPool(ctx, *poolSize, 10*time.Minute); err != nil {
			log.Fatalf("StartSessionPool: %v", err)
		}
		pooled = pp.Sandbox.(sandbox.SessionProvider)
	}
	defer func() {
		dctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		for _, d := range []any{p.Sandbox, pooled} {
			if d, ok := d.(sandbox.Drainer); ok {
				_ = d.Drain(dctx)
			}
		}
	}()
	run := Run{Provider: "openshell", Tier: p.Sandbox.IsolationClass().String(), Image: os.Getenv("SANDBOX_OPENSHELL_IMAGE"),
		When: time.Now().UTC(), Reps: *reps, PauseMs: pause.Milliseconds()}
	langs := sp.SessionEnvironments().Project.Languages
	opts := sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

	cell := func(s sandbox.Session, lang sandbox.Language) error {
		code := "6 * 7"
		res, err := s.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: code, Timeout: 60 * time.Second})
		if err != nil {
			return err
		}
		if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "42" {
			return fmt.Errorf("%s cell: exit %d, %q, %q", lang, res.ExitCode, res.Stdout, res.Stderr)
		}
		return nil
	}
	snippet := func(s sandbox.Session) error {
		res, err := s.RunJavaScript(ctx, sandbox.Request{Code: "console.log(42)"})
		if err != nil {
			return err
		}
		if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "42" {
			return fmt.Errorf("snippet: exit %d, %q, %q", res.ExitCode, res.Stdout, res.Stderr)
		}
		return nil
	}
	openOn := func(sp sandbox.SessionProvider) sandbox.Session {
		s, err := sp.OpenSession(ctx, opts)
		if err != nil {
			log.Fatalf("open: %v", err)
		}
		return s
	}
	open := func() sandbox.Session { return openOn(sp) }

	// cold times OpenSession on sp plus the first call: with no pool, what a session
	// costs today.
	cold := func(sp sandbox.SessionProvider, label string, first func(sandbox.Session) error) {
		s, so, sc := Sample{Name: label}, Sample{Name: label + " (open)"}, Sample{Name: label + " (call)"}
		for i := 0; i < *reps; i++ {
			time.Sleep(*pause)
			start := time.Now()
			sess := openOn(sp)
			opened := time.Now()
			if err := first(sess); err != nil {
				log.Fatalf("%s: %v", label, err)
			}
			end := time.Now()
			_ = sess.Close(ctx)
			s.Ms, so.Ms, sc.Ms = append(s.Ms, ms(end.Sub(start))), append(so.Ms, ms(opened.Sub(start))), append(sc.Ms, ms(end.Sub(opened)))
		}
		run.Samples = append(run.Samples, s, so, sc)
		fmt.Printf("%-48s median %7.1f ms (open %.1f, call %.1f)\n", label, median(s.Ms), median(so.Ms), median(sc.Ms))
	}
	// preopened times the first call in a session opened before the pause, after
	// prepare (untimed): what a claim of a waiting member would leave of it.
	preopened := func(label string, prepare, first func(sandbox.Session) error) {
		s := Sample{Name: label}
		for i := 0; i < *reps; i++ {
			sess := open()
			if prepare != nil {
				if err := prepare(sess); err != nil {
					log.Fatalf("%s: prepare: %v", label, err)
				}
			}
			time.Sleep(*pause)
			start := time.Now()
			if err := first(sess); err != nil {
				log.Fatalf("%s: %v", label, err)
			}
			s.Ms = append(s.Ms, ms(time.Since(start)))
			_ = sess.Close(ctx)
		}
		run.Samples = append(run.Samples, s)
		fmt.Printf("%-48s median %7.1f ms\n", label, median(s.Ms))
	}

	cold(sp, "no pool: open + first snippet", snippet)
	preopened("opened ahead: first snippet", nil, snippet)
	if pooled != nil {
		cold(pooled, "pool: claim + first snippet", snippet)
	}
	for _, lang := range langs {
		first := func(s sandbox.Session) error { return cell(s, lang) }
		cold(sp, "no pool: open + first "+string(lang)+" cell", first)
		if pooled != nil {
			cold(pooled, "pool: claim + first "+string(lang)+" cell", first)
		}
		preopened("opened ahead: first "+string(lang)+" cell, interpreter not started", nil, first)
		// The other language's cell starts its interpreter too, as a member warming every
		// language would; then the timed cell is the first in its own language after a
		// pause, its interpreter already running.
		preopened("opened ahead: first "+string(lang)+" cell, interpreter started", func(s sandbox.Session) error {
			for _, l := range langs {
				if err := cell(s, l); err != nil {
					return err
				}
			}
			return nil
		}, first)
	}

	// Memory: a waiting session's containers, bare and with every interpreter started.
	for i := 0; i < 2; i++ {
		before := sandboxContainers()
		sess := open()
		time.Sleep(3 * time.Second)
		added := newContainers(before)
		fmt.Println("waiting session containers:", added)
		run.BareMiB = append(run.BareMiB, memMiB(added))
		for _, l := range langs {
			if err := cell(sess, l); err != nil {
				log.Fatal(err)
			}
		}
		time.Sleep(3 * time.Second)
		run.WarmMiB = append(run.WarmMiB, memMiB(added))
		_ = sess.Close(ctx)
	}
	fmt.Printf("waiting session memory: bare %v MiB, interpreters started %v MiB\n", run.BareMiB, run.WarmMiB)

	out, _ := json.MarshalIndent(run, "", "  ")
	path := filepath.Join("docs", "measurements", "warm-pool", "openshell.json")
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote", path)
}

// sandboxContainers names the containers the gateway's docker driver runs.
func sandboxContainers() []string {
	out, err := exec.Command("docker", "ps", "--filter", "label=openshell.ai/isolation-backend", "--format", "{{.Names}}").Output()
	if err != nil {
		log.Fatal(err)
	}
	all := strings.Fields(string(out))
	sup, err := exec.Command("docker", "ps", "--filter", "name=supervisor", "--format", "{{.Names}}").Output()
	if err != nil {
		log.Fatal(err)
	}
	return append(all, strings.Fields(string(sup))...)
}

func newContainers(before []string) []string {
	var added []string
	for _, c := range sandboxContainers() {
		if !slices.Contains(before, c) {
			added = append(added, c)
		}
	}
	if len(added) == 0 {
		log.Fatal("no new gateway container found for the session")
	}
	return added
}

// memMiB sums docker's memory use of the containers named.
func memMiB(names []string) float64 {
	total := 0.0
	for _, name := range names {
		out, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", name).Output()
		if err != nil {
			log.Fatal(err)
		}
		used := strings.TrimSpace(strings.SplitN(string(out), "/", 2)[0])
		num, err := strconv.ParseFloat(strings.TrimRight(used, "KMGiB"), 64)
		if err != nil {
			log.Fatalf("docker stats %q: %v", used, err)
		}
		switch {
		case strings.HasSuffix(used, "KiB"):
			num /= 1024
		case strings.HasSuffix(used, "GiB"):
			num *= 1024
		}
		total += num
	}
	return total
}

func median(ms []float64) float64 {
	s := slices.Clone(ms)
	slices.Sort(s)
	return s[len(s)/2]
}
