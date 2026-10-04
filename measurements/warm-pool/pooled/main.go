// Command pooled measures the docker session pool (SANDBOX_SESSION_POOL): the time
// from asking for a session to the first cell's answer, with and without a pool member
// waiting, for each language; and what a waiting member holds in memory. Like
// measurements/session-latency it calls the provider directly, not through plimsolld.
//
//	go run ./measurements/warm-pool/pooled                  # runc
//	go run ./measurements/warm-pool/pooled -runtime runsc   # gVisor
//
// It writes docs/measurements/warm-pool/pooled-<runc|runsc>.json, which report.py
// renders.
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
)

// Sample is one measured operation: every repetition's wall time in ms.
type Sample struct {
	Name string    `json:"name"`
	Ms   []float64 `json:"ms"`
}

// Run is one runtime's measurements.
type Run struct {
	Runtime string    `json:"runtime"`
	Tier    string    `json:"tier"`
	Image   string    `json:"image"`
	When    time.Time `json:"when"`
	Reps    int       `json:"reps"`
	Samples []Sample  `json:"samples"`
	// MemberMiB is docker's memory use for each waiting member (both interpreters
	// started); BareMiB for a session container with no interpreter yet.
	MemberMiB []float64 `json:"memberMiB"`
	BareMiB   []float64 `json:"bareMiB"`
}

func main() {
	rt := flag.String("runtime", "", "docker runtime (runsc for gVisor)")
	reps := flag.Int("reps", 15, "repetitions per operation")
	flag.Parse()
	ctx := context.Background()
	name := *rt
	if name == "" {
		name = "runc"
	}
	const image = "plimsoll/sandbox-python:latest"
	newDocker := func() *sandbox.DockerSandbox {
		d := sandbox.DefaultDocker("")
		d.Runtime = *rt
		d.ProjectImage = image
		if err := (sandbox.Provider{Sandbox: d}).EnsureReady(ctx); err != nil {
			log.Fatalf("EnsureReady: %v", err)
		}
		return d
	}
	plain, pooled := newDocker(), newDocker()
	if err := pooled.StartSessionPool(ctx, 2, 10*time.Minute); err != nil {
		log.Fatalf("StartSessionPool: %v", err)
	}
	defer func() {
		dctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		_ = pooled.Drain(dctx)
		_ = plain.Drain(dctx)
	}()
	run := Run{Runtime: name, Tier: plain.IsolationClass().String(), Image: image, When: time.Now().UTC(), Reps: *reps}
	opts := sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20}

	// openAndCell times OpenSession plus the first cell, then closes the session
	// untimed. A pause before each repetition gives the pool time to refill, as an
	// agent's seconds between conversations would.
	openAndCell := func(label string, d *sandbox.DockerSandbox, lang sandbox.Language) {
		s, so, sc := Sample{Name: label}, Sample{Name: label + " (open)"}, Sample{Name: label + " (cell)"}
		ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
		for i := 0; i < *reps; i++ {
			time.Sleep(3 * time.Second)
			start := time.Now()
			sess, err := d.OpenSession(ctx, opts)
			if err != nil {
				log.Fatalf("%s: open: %v", label, err)
			}
			opened := time.Now()
			res, err := sess.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: "6 * 7"})
			end := time.Now()
			_ = sess.Close(ctx)
			if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "42" {
				log.Fatalf("%s: cell: %+v, %v", label, res, err)
			}
			s.Ms, so.Ms, sc.Ms = append(s.Ms, ms(end.Sub(start))), append(so.Ms, ms(opened.Sub(start))), append(sc.Ms, ms(end.Sub(opened)))
		}
		run.Samples = append(run.Samples, s, so, sc)
		fmt.Printf("%-40s median %7.1f ms (open %.1f, cell %.1f)\n", label, median(s.Ms), median(so.Ms), median(sc.Ms))
	}
	for _, lang := range []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython} {
		openAndCell("no pool: open + first "+string(lang)+" cell", plain, lang)
		openAndCell("pool: claim + first "+string(lang)+" cell", pooled, lang)
	}

	// Memory: the pool's waiting members, and bare session containers for comparison.
	time.Sleep(5 * time.Second)
	for _, c := range sessionContainers() {
		if containsInterpreters(c) {
			run.MemberMiB = append(run.MemberMiB, memMiB(c))
		}
	}
	for i := 0; i < 2; i++ {
		before := sessionContainers()
		sess, err := plain.OpenSession(ctx, opts)
		if err != nil {
			log.Fatal(err)
		}
		time.Sleep(3 * time.Second)
		for _, c := range sessionContainers() {
			if !slices.Contains(before, c) {
				run.BareMiB = append(run.BareMiB, memMiB(c))
			}
		}
		_ = sess.Close(ctx)
	}
	fmt.Printf("member memory %v MiB, bare session %v MiB\n", run.MemberMiB, run.BareMiB)
	out, _ := json.MarshalIndent(run, "", "  ")
	path := filepath.Join("docs", "measurements", "warm-pool", "pooled-"+name+".json")
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote", path)
}

func sessionContainers() []string {
	out, err := exec.Command("docker", "ps", "--filter", "label=io.plimsoll.session", "--format", "{{.Names}}").Output()
	if err != nil {
		log.Fatal(err)
	}
	return strings.Fields(string(out))
}

func containsInterpreters(name string) bool {
	out, _ := exec.Command("docker", "exec", name, "sh", "-c", `cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' ' '`).Output()
	return strings.Contains(string(out), "python3 -I -c") && strings.Contains(string(out), "node --expose-internals")
}

func memMiB(name string) float64 {
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
		return num / 1024
	case strings.HasSuffix(used, "GiB"):
		return num * 1024
	}
	return num
}

func median(ms []float64) float64 {
	s := slices.Clone(ms)
	slices.Sort(s)
	return s[len(s)/2]
}
