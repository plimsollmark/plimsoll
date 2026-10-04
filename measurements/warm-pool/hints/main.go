// Command hints measures the warm pool's language hints: how the pool's split across
// language sets follows the hints sessions open with, what a member of each set holds
// in memory, and the time from a hinted open to its first cell's answer. Like pooled it
// calls the provider directly, not through plimsolld.
//
//	go run ./measurements/warm-pool/hints                  # runc
//	go run ./measurements/warm-pool/hints -runtime runsc   # gVisor
//
// It writes docs/measurements/warm-pool/hints-<runc|runsc>.json, which report.py
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

// Phase is the pool after a run of opens with one hint.
type Phase struct {
	Hint  string         `json:"hint"` // "" for no hint
	Opens int            `json:"opens"`
	Split map[string]int `json:"split"` // waiting members by the languages they warm
	// FirstCellMs is each open's time to its first cell's answer, in the hinted
	// language (Python without a hint).
	FirstCellMs []float64 `json:"firstCellMs"`
}

// Run is one runtime's measurements.
type Run struct {
	Runtime string             `json:"runtime"`
	Tier    string             `json:"tier"`
	Image   string             `json:"image"`
	When    time.Time          `json:"when"`
	Size    int                `json:"size"`
	Phases  []Phase            `json:"phases"`
	MiB     map[string]float64 `json:"mib"` // a waiting member's memory, by the languages it warms
}

func main() {
	rt := flag.String("runtime", "", "docker runtime (runsc for gVisor)")
	opens := flag.Int("opens", 16, "opens per phase")
	flag.Parse()
	ctx := context.Background()
	name := *rt
	if name == "" {
		name = "runc"
	}
	const image, size = "plimsoll/sandbox-python:latest", 4
	d := sandbox.DefaultDocker("")
	d.Runtime = *rt
	d.ProjectImage = image
	if err := (sandbox.Provider{Sandbox: d}).EnsureReady(ctx); err != nil {
		log.Fatalf("EnsureReady: %v", err)
	}
	if err := d.StartSessionPool(ctx, size, 10*time.Minute); err != nil {
		log.Fatalf("StartSessionPool: %v", err)
	}
	defer func() {
		dctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		_ = d.Drain(dctx)
	}()
	run := Run{Runtime: name, Tier: d.IsolationClass().String(), Image: image, When: time.Now().UTC(), Size: size, MiB: map[string]float64{}}
	run.Phases = append(run.Phases, Phase{Split: settle(size, run.MiB)})
	fmt.Printf("start: %v\n", run.Phases[0].Split)
	for _, hint := range []sandbox.Language{sandbox.LanguagePython, sandbox.LanguageJavaScript} {
		ph := Phase{Hint: string(hint), Opens: *opens}
		for range *opens {
			// An agent's seconds between conversations, so the pool can refill and move.
			time.Sleep(3 * time.Second)
			start := time.Now()
			s, err := d.OpenSession(ctx, sandbox.SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20, Languages: []sandbox.Language{hint}})
			if err != nil {
				log.Fatalf("open: %v", err)
			}
			res, err := s.RunCell(ctx, sandbox.CellRequest{Language: hint, Code: "6 * 7"})
			ph.FirstCellMs = append(ph.FirstCellMs, float64(time.Since(start).Microseconds())/1000)
			_ = s.Close(ctx)
			if err != nil || strings.TrimSpace(res.Stdout) != "42" {
				log.Fatalf("cell: %+v, %v", res, err)
			}
		}
		ph.Split = settle(size, run.MiB)
		fmt.Printf("after %d %s opens: %v, first cell median %.1f ms\n", *opens, hint, ph.Split, median(ph.FirstCellMs))
		run.Phases = append(run.Phases, ph)
	}
	fmt.Printf("memory by set (MiB): %v\n", run.MiB)
	out, _ := json.MarshalIndent(run, "", "  ")
	path := filepath.Join("docs", "measurements", "warm-pool", "hints-"+name+".json")
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote", path)
}

// settle waits until size members wait with their relays attached (closed sessions'
// containers gone) and the split reads the same on two polls in a row (a member still
// warming its languages shows only some of them), then returns the split and records
// each set's memory.
func settle(size int, mib map[string]float64) map[string]int {
	last := ""
	for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(time.Second) {
		names := sessionContainers()
		if len(names) != size {
			continue
		}
		split := map[string]int{}
		mem := map[string]float64{}
		for _, n := range names {
			set := warmSet(n)
			if set == "" {
				break
			}
			split[set]++
			mem[set] = memMiB(n)
		}
		key := fmt.Sprint(split)
		if total := sum(split); total == size && key == last {
			for k, v := range mem {
				mib[k] = v
			}
			return split
		}
		last = key
	}
	log.Fatal("the pool did not settle")
	return nil
}

// warmSet names the languages whose relay is attached in a container, or "".
func warmSet(name string) string {
	out, err := exec.Command("docker", "exec", name, "sh", "-c", `for p in /proc/[0-9]*; do tr '\0' ' ' < "$p/cmdline" 2>/dev/null; echo; done`).Output()
	if err != nil {
		return ""
	}
	var set []string
	for _, l := range []string{"javascript", "python"} {
		if strings.Contains(string(out), ".plimsoll-interp/"+l+" /work") {
			set = append(set, l)
		}
	}
	return strings.Join(set, ",")
}

func sessionContainers() []string {
	out, err := exec.Command("docker", "ps", "--filter", "label=io.plimsoll.session", "--format", "{{.Names}}").Output()
	if err != nil {
		log.Fatal(err)
	}
	return strings.Fields(string(out))
}

func memMiB(name string) float64 {
	out, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", name).Output()
	if err != nil {
		return 0
	}
	used := strings.TrimSpace(strings.SplitN(string(out), "/", 2)[0])
	num, err := strconv.ParseFloat(strings.TrimRight(used, "KMGiB"), 64)
	if err != nil {
		return 0
	}
	switch {
	case strings.HasSuffix(used, "KiB"):
		return num / 1024
	case strings.HasSuffix(used, "GiB"):
		return num * 1024
	}
	return num
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func median(ms []float64) float64 {
	s := slices.Clone(ms)
	slices.Sort(s)
	return s[len(s)/2]
}
