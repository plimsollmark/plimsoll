// Command verifiers runs Prime Intellect's verifiers library on plimsoll and writes the
// page that shows what happened: an outside environment, unchanged, whose every tool call
// ran in a plimsoll docker session and left a run record, rechecked afterwards from a
// JSON-lines log.
//
// The model is scripted, not a language model: a loopback server answers each chat
// completion from a fixed policy (clients/python/frameworks/verifiers/scripted_model.py and
// attempt/policies.py), so every number measures the harness, the runtime and verifiers'
// own machinery, never a model's skill. Nothing is paid for.
//
// What it runs, each fresh, through the Python harness in clients/python/frameworks/verifiers:
//
//   - vf-validate of plimsoll-sum, the docker suite's own check (docker_check.py), under
//     runc and under gVisor (runsc);
//   - Prime's uuid_ctf task (prime-envs, pinned by commit and by every file's SHA-256)
//     through vf-eval: plimsoll-bash on plimsoll under runc and gVisor with the solving
//     policy, under runc with a wrong answer, verifiers' shipped bash harness on plimsoll,
//     and verifiers' shipped bash harness on verifiers' own docker runtime as the baseline;
//   - each runtime call timed through verifiers' runtime API (measure_calls.py);
//   - Terminal-Bench 2, pinned by commit, read as data (nothing in it runs).
//
// Every record log is rechecked twice, by the Python client's check_record_log and by this
// program's Go checker, and published beside the page. Run it from the repository root,
// with docker, gVisor, the images make docker-images builds and the environment
// make py-frameworks PY_FRAMEWORKS=verifiers builds:
//
//	go run ./examples/verifiers            # run everything, write docs/examples/verifiers/
//	go run ./examples/verifiers -verify    # recheck the published files; starts nothing
//	go run ./examples/verifiers -render    # rewrite the page from evidence.json
//	go run ./examples/verifiers -assemble  # rebuild the evidence from the last run's raw output
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	out := flag.String("out", filepath.Join("docs", "examples", "verifiers"), "the page's directory: index.html, evidence.json and records/")
	python := flag.String("python", filepath.Join("tmp", "py-frameworks", "verifiers", "bin", "python"), "the verifiers environment's interpreter (make py-frameworks PY_FRAMEWORKS=verifiers)")
	prime := flag.String("prime-envs", filepath.Join("tmp", "verifiers-example", "prime-envs"), "a prime-envs checkout; fetched at the pinned commit when absent")
	bench := flag.String("terminal-bench", filepath.Join("tmp", "verifiers-example", "terminal-bench-2"), "a terminal-bench-2 checkout; fetched at the pinned commit when absent")
	work := flag.String("work", filepath.Join("tmp", "verifiers-example", "run"), "scratch for every configuration's raw output; emptied first, never published")
	runsc := flag.Bool("runsc", true, "run the gVisor configurations and the call timing (needs docker's runsc runtime)")
	verify := flag.Bool("verify", false, "recheck the published files and write nothing")
	render := flag.Bool("render", false, "rewrite index.html from the published evidence.json; start nothing")
	assembleOnly := flag.Bool("assemble", false, "rebuild evidence.json, the record logs and the page from the last run's raw output in -work; start nothing")
	flag.Parse()

	var err error
	switch {
	case *verify:
		err = verifyPublished(*out)
		if err == nil {
			fmt.Println("verifiers: the published record logs recheck and the page is what evidence.json renders")
		}
	case *render:
		err = renderPublished(*out)
	case *assembleOnly:
		var c config
		if c, err = newConfig(*out, *python, *prime, *bench, *work, *runsc); err == nil {
			err = assembleAndPublish(context.Background(), c, nil)
		}
	default:
		var c config
		c, err = newConfig(*out, *python, *prime, *bench, *work, *runsc)
		if err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = runAll(ctx, c)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "verifiers:", err)
		os.Exit(1)
	}
}

func newConfig(out, python, prime, bench, work string, runsc bool) (config, error) {
	repo, err := os.Getwd()
	if err != nil {
		return config{}, err
	}
	if !fileExists(filepath.Join(repo, "cmd", "plimsolld")) {
		return config{}, fmt.Errorf("run this from the repository root (no cmd/plimsolld in %s)", repo)
	}
	abs := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(repo, p)
	}
	c := config{repo: repo, python: abs(python), prime: abs(prime), bench: abs(bench), work: abs(work), out: abs(out), runsc: runsc}
	return c, os.MkdirAll(c.out, 0o755)
}
