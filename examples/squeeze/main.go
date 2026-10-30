// Command squeeze runs the squeeze test on plimsoll: did a loop that graded itself on the
// same practice tests every round learn the job, or learn the test?
//
// The test is from Bertran, Roth and Wu, "What Fits (Into Few Tokens) Doesn't Overfit"
// (arXiv 2606.11045): squeeze what a loop learned into a recipe of about 32 tokens, let fresh
// agents rebuild from the recipe alone, and compare their scores with the loop's on the
// loop's own practice tests, which no rebuild has seen. Memorized answers do not fit in 32
// tokens; a real method does. This program is the rebuild-and-grade half of it, ported from the
// did-it-learn hackathon entry (github.com/carrollco/did-it-learn) onto plimsoll:
//
//   - each rebuild is the caller's model in a fresh plimsoll session that holds the brief, the
//     course's API text and a baseline controller, never the simulator; it practises through a
//     fly tool, a separate run that holds the simulator and answers with flight results;
//   - every controller, the loop's own included, is graded in a run of its own on two sealed
//     sets: the loop's practice flights and fresh flights drawn for this run;
//   - every call is signed into a bundle by a key made for the run, and a leak scan anyone can
//     rerun reads every request that entered a rebuild's sandbox or a practice run for the
//     sealed seeds, the loop's controller and the simulator's source.
//
// The squeeze needs a model to write the recipe and the rebuilds. This program never calls one
// on its own: a job that builds rebuilds needs the caller's key and a token budget. A job that
// only imports controllers made elsewhere (the hackathon's) grades them and spends nothing.
//
//	go run ./examples/squeeze -import ../did-it-learn      # grade the hackathon's controllers
//	go run ./examples/squeeze -verify                       # check the published files; writes nothing
//	go run ./examples/squeeze -render                       # rewrite the page from the published files
//	go run ./examples/squeeze -import ../did-it-learn -loops-only \
//	    -fresh docs/examples/squeeze/fresh.json -fresh-sha256 <its run.json's fresh_sha256> -out <dir>
//	                                                        # fly the loops again on the published set
//
// Writes docs/examples/squeeze/: index.html, evidence.json, bundle.jsonl.gz, harness.pub,
// fresh.json and run.json. The run's private key is never written.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/examples/internal/daemonproc"
)

func main() {
	jobPath := flag.String("job", filepath.Join("examples", "squeeze", "jobs", "hackathon-regrade.json"), "the job: courses, loops, rebuild groups")
	importRoot := flag.String("import", "", "the directory a job's imported controllers are under (a did-it-learn checkout)")
	out := flag.String("out", filepath.Join("docs", "examples", "squeeze"), "where the page and its evidence go")
	daemon := flag.String("daemon", "", "a running plimsolld to use instead of starting one (its token in PLIMSOLL_TOKEN)")
	runtime := flag.String("runtime", "runsc", "the docker runtime of the daemon this program starts: runsc (gVisor) or runc")
	image := flag.String("image", "plimsoll/sandbox-python:latest", "the image of the daemon this program starts: Node for the course, Python too for rebuilds")
	parallel := flag.Int("parallel", 4, "runs or rebuilds at once")
	model := flag.String("model", "nvidia/nemotron-3-super-120b-a12b", "the model that writes rebuilds, on an OpenAI-compatible API")
	base := flag.String("base", "https://api.tokenfactory.nebius.com/v1", "the OpenAI-compatible API base")
	keyEnv := flag.String("key-env", "NEBIUS_API_KEY", "the environment variable holding the model's key; read, never written")
	maxTokens := flag.Int("max-tokens", 0, "the most prompt plus completion tokens the run may spend, all rebuilds together; required when the job builds")
	verify := flag.Bool("verify", false, "check the published files and write nothing")
	render := flag.Bool("render", false, "rewrite the page and evidence.json from the published files; start no sandbox")
	freshPath := flag.String("fresh", "", "fly on this fresh set, an earlier run's fresh.json, instead of drawing one; needs -fresh-sha256")
	freshSHA := flag.String("fresh-sha256", "", "the SHA-256 the earlier run committed to for the -fresh set (its run.json's fresh_sha256)")
	loopsOnly := flag.Bool("loops-only", false, "grade the job's loops' own controllers alone, no rebuilds")
	flag.Parse()

	job, err := loadJob(*jobPath)
	if err != nil {
		fail(err)
	}
	if (*freshPath == "") != (*freshSHA == "") {
		fail(errors.New("-fresh and -fresh-sha256 go together: the set, and the digest it was committed to"))
	}
	if *freshPath != "" && (*verify || *render) {
		fail(errors.New("-fresh is for a run; -verify and -render read the fresh set published in -out"))
	}
	if *loopsOnly {
		job = job.loopsOnly()
	}
	switch {
	case *verify:
		err = verifyPublished(*out, job)
	case *render:
		err = renderPublished(*out, job)
	default:
		err = runAndPublish(context.Background(), job, *importRoot, *out, *daemon, *runtime, *image, *parallel, *model, *base, *keyEnv, *maxTokens, givenFresh{path: *freshPath, sha256: *freshSHA})
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "squeeze:", err)
	os.Exit(1)
}

func runAndPublish(ctx context.Context, job *Job, importRoot, out, daemonURL, runtime, image string, parallel int, model, base, keyEnv string, maxTokens int, given givenFresh) error {
	if parallel < 1 || parallel > 16 {
		return errors.New("-parallel is 1 to 16")
	}
	l := &live{job: job, importRoot: importRoot, parallel: parallel, daemon: daemonURL, token: os.Getenv("PLIMSOLL_TOKEN"), given: given}
	if job.builds() > 0 {
		key := os.Getenv(keyEnv)
		if key == "" {
			return errNoModel
		}
		if maxTokens <= 0 {
			return errors.New("this job builds rebuilds with a model: set -max-tokens, the most the run may spend")
		}
		l.model = &chat{base: base, key: key, model: model, budget: maxTokens, http: &http.Client{Timeout: 6 * time.Minute}}
	}
	if daemonURL == "" {
		work, err := os.MkdirTemp("", "plimsoll-squeeze-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(work)
		bin, err := daemonproc.Build(ctx, work)
		if err != nil {
			return err
		}
		tok := make([]byte, 16)
		if _, err := rand.Read(tok); err != nil {
			return err
		}
		l.token = hex.EncodeToString(tok)
		rt := runtime
		if rt == "runc" {
			rt = "" // the docker provider's default runtime
		}
		env := []string{"SANDBOX_PROVIDER=docker", "SANDBOX_DOCKER_RUNTIME=" + rt, "SANDBOX_DOCKER_PROJECT_IMAGE=" + image,
			"PLIMSOLL_TOKEN=" + l.token, fmt.Sprintf("SANDBOX_MAX_CONCURRENT=%d", 2*parallel+2), fmt.Sprintf("SANDBOX_PER_KEY_CONCURRENT=%d", 2*parallel+2)}
		if job.builds() > 0 {
			env = append(env, fmt.Sprintf("SANDBOX_MAX_SESSIONS=%d", parallel), "SANDBOX_SESSION_LIFETIME=2h", "SANDBOX_SESSION_IDLE=20m", "SANDBOX_SESSION_DISK_MB=64")
		}
		d, err := daemonproc.Start(ctx, bin, daemonproc.Options{Env: env, Ready: 3 * time.Minute})
		if err != nil {
			return err
		}
		defer func() { _ = d.Stop(2 * time.Minute) }()
		l.daemon = d.BaseURL
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(out), ".squeeze-staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := l.run(ctx, staging); err != nil {
		return err
	}
	if err := compressBundle(staging); err != nil {
		return err
	}
	// The run's own files are published before the page is rendered from them, so a page that
	// fails to render costs no run: fix the renderer and run -render.
	if err := publish(staging, out, runFiles); err != nil {
		return err
	}
	if err := writePage(out, job); err != nil {
		return fmt.Errorf("the run's files are in %s but the page did not render (fix it, then run -render): %w", out, err)
	}
	fmt.Printf("done      | page %s\n", filepath.Join(out, "index.html"))
	return nil
}

// runFiles are what a run writes into the page's directory; writePage adds evidence.json and
// index.html, derived from them.
var runFiles = []string{bundleName, "harness.pub", "fresh.json", "run.json"}

// writePage derives the evidence from dir's files and writes evidence.json and index.html.
func writePage(dir string, job *Job) error {
	ev, err := derive(dir, job)
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "evidence.json"), ev); err != nil {
		return err
	}
	page, err := renderPage(ev)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "index.html"), page, 0o644)
}

func renderPublished(dir string, job *Job) error {
	if err := writePage(dir, job); err != nil {
		return err
	}
	fmt.Printf("rendered  | %s\n", filepath.Join(dir, "index.html"))
	return nil
}

// verifyPublished checks the bundle, the leak scan and the grading sets, and that evidence.json
// and index.html are exactly what the bundle renders.
func verifyPublished(dir string, job *Job) error {
	ev, err := derive(dir, job)
	if err != nil {
		return err
	}
	want, err := encodeJSON(ev)
	if err != nil {
		return err
	}
	have, err := os.ReadFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		return err
	}
	if !bytes.Equal(have, want) {
		return errors.New("evidence.json is not what the bundle states; run -render")
	}
	page, err := renderPage(ev)
	if err != nil {
		return err
	}
	if published, err := os.ReadFile(filepath.Join(dir, "index.html")); err != nil || !bytes.Equal(published, page) {
		return errors.New("index.html is not what the evidence renders; run -render")
	}
	if len(ev.Scan.Hits) > 0 {
		return fmt.Errorf("the leak scan found %d forbidden strings: %v", len(ev.Scan.Hits), ev.Scan.Hits)
	}
	if !ev.Scan.SetsHeld {
		return errors.New("a grading run did not hold exactly its course's practice set and the published fresh set")
	}
	fmt.Printf("verified  | %d lines signed by %s; %d grading runs on the sealed sets (fresh %s…); %d session calls and %d practice runs scanned for %d forbidden strings, none found\n",
		ev.Lines, ev.Harness, ev.Scan.GradingRuns, ev.FreshSHA256[:16], ev.Scan.SessionCalls, ev.Scan.PracticeRuns, ev.Scan.Needles)
	for _, set := range ev.Sets {
		var scores []string
		for _, l := range set.Loops {
			differ := ""
			if !l.Same {
				differ = " (the runs landed different flights)"
			}
			scores = append(scores, fmt.Sprintf("%s %s %v%s", l.Course, l.Loop, l.Fresh, differ))
		}
		fmt.Printf("set       | fresh %s… in %v: %s\n", set.SHA256[:16], set.Runs, strings.Join(scores, ", "))
	}
	return nil
}
