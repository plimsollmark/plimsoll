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
//	go run ./examples/squeeze -job examples/squeeze/jobs/recipe-scramble-easy.json -staged -verify \
//	    -out docs/examples/squeeze-recipe                   # check the staged recipe experiment's page (-render rewrites it)
//	go run ./examples/squeeze -import ../did-it-learn -loops-only \
//	    -fresh docs/examples/squeeze/fresh.json -fresh-sha256 <its run.json's fresh_sha256> -out <dir>
//	                                                        # fly the loops again on the published set
//
// Writes docs/examples/squeeze/: index.html, evidence.json, bundle.jsonl.gz, harness.pub,
// fresh.json and run.json. The run's private key is never written.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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
	api := flag.String("api", "chat", "the model's API: chat (OpenAI-compatible chat completions) or messages (Anthropic's Messages API)")
	model := flag.String("model", "", "the model that writes rebuilds (chat: default nvidia/nemotron-3-super-120b-a12b; messages: required)")
	base := flag.String("base", "", "the API base (chat: default https://api.tokenfactory.nebius.com/v1; messages: https://api.anthropic.com)")
	keyEnv := flag.String("key-env", "", "the environment variable holding the model's key, read, never written (chat: default NEBIUS_API_KEY; messages: ANTHROPIC_API_KEY)")
	maxTokens := flag.Int("max-tokens", 0, "the most prompt plus completion tokens the run may spend, all rebuilds together; required when the job builds")
	paid := flag.Bool("paid", false, "allow model calls to a base that is not on this machine, which spend the key's money; without it such a run refuses to start")
	designOut := flag.String("design", "", "write the design document of -job, -api and -model to this file and exit; starts nothing")
	designSHA := flag.String("design-sha256", "", "refuse to start a building run unless its design document has this SHA-256")
	groups := flag.String("groups", "", "build only these groups (comma-separated ids), in a run of an experiment staged in parts; the job and its design are unchanged")
	build := flag.Int("build", 0, "with -groups: build this many rebuilds of each named group, at most the job's build for it (a size decided between stages); 0 builds the job's")
	sealOut := flag.String("seal", "", "draw the job's fresh set now (crypto/rand, no practice or smoke seed) into this file and exit, for a run to fly with -fresh; starts nothing")
	verify := flag.Bool("verify", false, "check the published files and write nothing")
	render := flag.Bool("render", false, "rewrite the page and evidence.json from the published files; start no sandbox")
	staged := flag.Bool("staged", false, "with -render or -verify: -out is a staged experiment's page, its stages/<name>/ each one run of -job that built some of its groups, experiment.json its stages and registered rule (docs/examples/squeeze-recipe)")
	regradeDir := flag.String("regrade", "", "grade again, with no model call, the controllers of this building run's agents whose grading failed (agents.json grade_problem), on its own sealed sets, into DIR/regrades/; then write agents.json again")
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
	mo, err := modelDefaults(modelOpts{api: *api, model: *model, base: *base, keyEnv: *keyEnv, maxTokens: *maxTokens, paid: *paid, designSHA: *designSHA, groups: splitList(*groups), build: *build})
	if err != nil {
		fail(err)
	}
	if *sealOut != "" {
		avoid := map[uint32]bool{}
		for _, c := range job.Courses {
			for _, x := range append(slices.Clone(c.Practice), smokeSeeds(c.ID)...) {
				avoid[x] = true
			}
		}
		set, err := sealFresh(job.Fresh, avoid)
		if err == nil {
			err = os.WriteFile(*sealOut, set.encode(), 0o644)
		}
		if err != nil {
			fail(err)
		}
		fmt.Printf("sealed    | %d fresh flights in %s, SHA-256 %s\n", len(set.Seeds), *sealOut, digest(set.encode()))
		return
	}
	if *designOut != "" {
		b, err := designBytes(job, mo.api, mo.model)
		if err == nil {
			err = os.WriteFile(*designOut, b, 0o644)
		}
		if err != nil {
			fail(err)
		}
		fmt.Printf("design    | %s, SHA-256 %s\n", *designOut, digest(b))
		return
	}
	switch {
	case *staged && *verify:
		err = verifyStaged(*out, job)
	case *staged && *render:
		err = renderStaged(*out, job)
	case *staged:
		err = errors.New("-staged goes with -render or -verify")
	case *verify:
		err = verifyPublished(*out, job)
	case *render:
		err = renderPublished(*out, job)
	case *regradeDir != "":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = regradePublished(ctx, *regradeDir, job, *daemon, *runtime, *image, *parallel)
		stop()
	default:
		// An interrupt or a terminate stops the run, which keeps what it made (runAndPublish).
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = runAndPublish(ctx, job, *importRoot, *out, *daemon, *runtime, *image, *parallel, mo, givenFresh{path: *freshPath, sha256: *freshSHA})
		stop()
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "squeeze:", err)
	os.Exit(1)
}

// modelOpts are the model flags of a building run.
type modelOpts struct {
	api, model, base, keyEnv string
	maxTokens                int
	paid                     bool
	designSHA                string
	groups                   []string // build only these groups; none named builds every group
	build                    int      // with groups: this many of each, at most its job build; 0 is the job's
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// modelDefaults fills each API's defaults.
func modelDefaults(mo modelOpts) (modelOpts, error) {
	switch mo.api {
	case "chat":
		mo.model = cmp.Or(mo.model, "nvidia/nemotron-3-super-120b-a12b")
		mo.base = cmp.Or(mo.base, "https://api.tokenfactory.nebius.com/v1")
		mo.keyEnv = cmp.Or(mo.keyEnv, "NEBIUS_API_KEY")
	case "messages":
		mo.base = cmp.Or(mo.base, "https://api.anthropic.com")
		mo.keyEnv = cmp.Or(mo.keyEnv, "ANTHROPIC_API_KEY")
	default:
		return mo, fmt.Errorf("-api %q: chat or messages", mo.api)
	}
	return mo, nil
}

func runAndPublish(ctx context.Context, job *Job, importRoot, out, daemonURL, runtime, image string, parallel int, mo modelOpts, given givenFresh) error {
	if parallel < 1 || parallel > 16 {
		return errors.New("-parallel is 1 to 16")
	}
	l := &live{job: job, importRoot: importRoot, parallel: parallel, daemon: daemonURL, token: os.Getenv("PLIMSOLL_TOKEN"), given: given, tree: harnessTree()}
	fmt.Printf("harness   | %s (%s), clean %v\n", cmp.Or(l.tree.Commit, "no commit"), l.tree.From, l.tree.Clean)
	if mo.paid && !l.tree.Clean {
		return fmt.Errorf("%w (%s): %s", errDirtyTree, l.tree.From, strings.Join(l.tree.Dirty, "; "))
	}
	if job.builds() > 0 {
		if mo.model == "" {
			return errors.New("this job builds rebuilds with a model: name it with -model")
		}
		design, err := checkDesign(job, mo.api, mo.model, mo.designSHA)
		if err != nil {
			return err
		}
		key := os.Getenv(mo.keyEnv)
		if key == "" {
			return errNoModel
		}
		if mo.maxTokens <= 0 {
			return errors.New("this job builds rebuilds with a model: set -max-tokens, the most the run may spend")
		}
		if !mo.paid && !loopbackBase(mo.base) {
			return errNotPaid
		}
		b := &budget{limit: mo.maxTokens}
		r := job.Rebuild
		hc := &http.Client{Timeout: 11 * time.Minute}
		if mo.api == "messages" {
			l.model = &messagesAPI{base: mo.base, key: key, model: mo.model, http: hc, maxTokens: r.MaxTokens, promptCap: r.PromptCap, effort: r.Effort, b: b}
		} else {
			l.model = &chat{base: mo.base, key: key, model: mo.model, http: hc, maxTokens: r.MaxTokens, promptCap: r.PromptCap, b: b}
		}
		l.api, l.design = mo.api, design
		for _, g := range mo.groups {
			found := false
			for _, c := range job.Courses {
				for _, jg := range c.Groups {
					found = found || (jg.ID == g && jg.Build > 0)
				}
			}
			if !found {
				return fmt.Errorf("-groups: the job builds no group %q", g)
			}
		}
		l.groups = mo.groups
		if mo.build != 0 {
			if mo.build < 0 || len(mo.groups) == 0 {
				return errors.New("-build is a positive count for the groups -groups names")
			}
			for _, c := range job.Courses {
				for _, jg := range c.Groups {
					if slices.Contains(mo.groups, jg.ID) && mo.build > jg.Build {
						return fmt.Errorf("-build %d: the job builds at most %d of group %s", mo.build, jg.Build, jg.ID)
					}
				}
			}
			l.build = mo.build
		}
		fmt.Printf("design    | SHA-256 %s\n", design)
	}
	if daemonURL == "" {
		base, token, stop, err := startDaemon(ctx, runtime, image, parallel, job.builds() > 0)
		if err != nil {
			return err
		}
		defer stop()
		l.daemon, l.token = base, token
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	// The staging directory sits beside -out under its name, so a run killed outright leaves it in
	// plain sight; a run that fails keeps it as <out>.failed-<time>, its signed bundle and every
	// finished agent's transcript in it: the spend is sunk, so nothing of it is deleted.
	staging, err := os.MkdirTemp(filepath.Dir(out), filepath.Base(out)+".staging-")
	if err != nil {
		return err
	}
	kept := ""
	defer func() {
		if kept == "" {
			_ = os.RemoveAll(staging)
		}
	}()
	keep := func(err error) error {
		failed := fmt.Sprintf("%s.failed-%s", out, time.Now().UTC().Format("20060102T150405Z"))
		if rerr := os.Rename(staging, failed); rerr != nil {
			return fmt.Errorf("%w (and the staging directory %s could not be kept: %v)", err, staging, rerr)
		}
		kept = failed
		return fmt.Errorf("%w; what the run made (the signed bundle, every finished agent's transcript) is kept in %s", err, failed)
	}
	if err := l.run(ctx, staging); err != nil {
		return keep(err)
	}
	if err := compressBundle(staging); err != nil {
		return keep(err)
	}
	// The run's own files are published before the page is rendered from them, so a page that
	// fails to render costs no run: fix the renderer and run -render.
	if err := publish(staging, out, runFilesOf(job)); err != nil {
		return keep(err)
	}
	if err := writePage(out, job); err != nil {
		return fmt.Errorf("the run's files are in %s but the page did not render (fix it, then run -render): %w", out, err)
	}
	var rf RunFile
	if err := readJSON(filepath.Join(out, "run.json"), &rf); err != nil {
		return err
	}
	if lost := incomplete(rf); len(lost) > 0 {
		for _, w := range lost {
			fmt.Printf("lost      | %s\n", w)
		}
		return fmt.Errorf("%w: %d (listed above; run.json has each); the files are in %s", errIncomplete, len(lost), out)
	}
	fmt.Printf("done      | %s\n", out)
	return nil
}

// startDaemon builds and starts a plimsolld for this program alone, under the docker provider, and
// says how to reach it and how to stop it.
func startDaemon(ctx context.Context, runtime, image string, parallel int, sessions bool) (base, token string, stop func(), err error) {
	work, err := os.MkdirTemp("", "plimsoll-squeeze-")
	if err != nil {
		return "", "", nil, err
	}
	bin, err := daemonproc.Build(ctx, work)
	if err != nil {
		_ = os.RemoveAll(work)
		return "", "", nil, err
	}
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		_ = os.RemoveAll(work)
		return "", "", nil, err
	}
	token = hex.EncodeToString(tok)
	rt := runtime
	if rt == "runc" {
		rt = "" // the docker provider's default runtime
	}
	env := []string{"SANDBOX_PROVIDER=docker", "SANDBOX_DOCKER_RUNTIME=" + rt, "SANDBOX_DOCKER_PROJECT_IMAGE=" + image,
		"PLIMSOLL_TOKEN=" + token, fmt.Sprintf("SANDBOX_MAX_CONCURRENT=%d", 2*parallel+2), fmt.Sprintf("SANDBOX_PER_KEY_CONCURRENT=%d", 2*parallel+2),
		// The harness is this daemon's only caller and bounds its own concurrency above, so a
		// per-minute limit only stalls it (the default 30 refused 5 of 8 stand-in agents, 2026-11-07).
		"SANDBOX_RATE_PER_MIN=0"}
	if sessions {
		env = append(env, fmt.Sprintf("SANDBOX_MAX_SESSIONS=%d", parallel), "SANDBOX_SESSION_LIFETIME=2h", "SANDBOX_SESSION_IDLE=20m", "SANDBOX_SESSION_DISK_MB=64")
	}
	d, err := daemonproc.Start(ctx, bin, daemonproc.Options{Env: env, Ready: 3 * time.Minute})
	if err != nil {
		_ = os.RemoveAll(work)
		return "", "", nil, err
	}
	return d.BaseURL, token, func() { _ = d.Stop(2 * time.Minute); _ = os.RemoveAll(work) }, nil
}

// cleanEnds are the endings of a session the model or its own budgets ended; any other (a model
// call that failed, the run's token budget, a harness fault) cut the session short.
var cleanEnds = []string{"answered", "turns", "prompt_cap", "refusal"}

// incomplete is what a run lost: every call that came back without a record, and every rebuild
// whose session something other than the model or its budgets ended. A run that lost any exits
// non-zero, so nothing downstream reads it as a whole run.
func incomplete(rf RunFile) []string {
	lost := slices.Clone(rf.Failures)
	for _, b := range rf.Built {
		if !slices.Contains(cleanEnds, b.Ended) {
			lost = append(lost, fmt.Sprintf("sq.%s.%s.%d.build: the session ended %s: %s", b.Course, b.Group, b.N, cmp.Or(b.Ended, "(no ending)"), clip(b.Problem, 200)))
		}
	}
	return lost
}

// errIncomplete is a run that published its files but lost calls or sessions.
var errIncomplete = errors.New("the run is incomplete: calls came back without a record, or sessions were cut short")

// runFilesOf are what a run writes into the page's directory; writePage adds evidence.json,
// agents.json when the job builds, and index.html unless the job has no page.
func runFilesOf(job *Job) []string {
	files := []string{bundleName, "harness.pub", "fresh.json", "run.json"}
	if job.builds() > 0 {
		files = append(files, transcriptsName)
	}
	return files
}

// writePage derives the evidence from dir's files and writes evidence.json, agents.json and
// index.html.
func writePage(dir string, job *Job) error {
	ev, err := derive(dir, job)
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "evidence.json"), ev); err != nil {
		return err
	}
	if job.builds() > 0 {
		agents, err := agentRecords(dir, job, ev)
		if err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, "agents.json"), agents); err != nil {
			return err
		}
	}
	if job.NoPage {
		return nil
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
	if job.builds() > 0 {
		agents, err := agentRecords(dir, job, ev)
		if err != nil {
			return err
		}
		want, err := encodeJSON(agents)
		if err != nil {
			return err
		}
		if have, err := os.ReadFile(filepath.Join(dir, "agents.json")); err != nil || !bytes.Equal(have, want) {
			return errors.New("agents.json is not what the transcripts and the bundle state; run -render")
		}
	}
	if !job.NoPage {
		page, err := renderPage(ev)
		if err != nil {
			return err
		}
		if published, err := os.ReadFile(filepath.Join(dir, "index.html")); err != nil || !bytes.Equal(published, page) {
			return errors.New("index.html is not what the evidence renders; run -render")
		}
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
