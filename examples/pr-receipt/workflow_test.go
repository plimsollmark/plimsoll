package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The receipt job fails closed only while GitHub cannot turn a skip into a pass. Its
// docs (Troubleshooting required status checks, read 2026-10-27): a workflow skipped by
// a path, branch or commit-message filter leaves its required check "Pending", which
// blocks the merge, but a job skipped by its own `if:` reports "Success", and a job that
// needs a failed job is skipped and "may not block merging". So the workflow keeps one
// job, with no job-level condition, no needs and no event filter.
func TestReceiptWorkflowCannotPassBySkipping(t *testing.T) {
	raw, err := os.ReadFile("workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	section := ""
	jobs := 0
	for i, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			section = strings.TrimSuffix(strings.Fields(line)[0], ":")
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key := strings.TrimSuffix(strings.Fields(strings.TrimSpace(line))[0], ":")
		switch section {
		case "on":
			if indent == 2 && key != "pull_request" {
				t.Errorf("line %d: the workflow runs on %q; want pull_request alone", i+1, key)
			}
			if indent > 2 {
				t.Errorf("line %d: %q filters pull_request; a filtered-out run leaves the required check pending, which blocks every pull request the filter skips", i+1, key)
			}
		case "jobs":
			if indent == 2 {
				jobs++
			}
			if indent == 4 && (key == "if" || key == "needs") {
				t.Errorf("line %d: a job-level %q lets the job be skipped, and a skipped job reports Success", i+1, key)
			}
		}
	}
	if jobs != 1 {
		t.Errorf("%d jobs; want the one receipt job, so the required check names it", jobs)
	}
	if !regexp.MustCompile(`(?m)^on:\n  pull_request:\s*$`).MatchString(string(raw)) {
		t.Error("the workflow's trigger is not a bare pull_request")
	}
}

// workflowStep is one step of workflow.yml: its place among the steps, its keys, and its run script with the block's
// indentation removed. The file is read as text, as TestReceiptWorkflowCannotPassBySkipping reads it.
type workflowStep struct {
	index int
	keys  map[string]string
	run   string
}

func readWorkflowSteps(t *testing.T) map[string]workflowStep {
	t.Helper()
	raw, err := os.ReadFile("workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	steps := map[string]workflowStep{}
	name, cur, n := "", workflowStep{}, 0
	inRun, keyIndent, blockIndent := false, 0, -1
	for _, line := range strings.Split(string(raw), "\n") {
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)
		if inRun {
			if trimmed == "" || indent > keyIndent {
				if trimmed != "" && blockIndent < 0 {
					blockIndent = indent
				}
				if blockIndent >= 0 && len(line) > blockIndent {
					cur.run += line[blockIndent:]
				}
				cur.run += "\n"
				continue
			}
			inRun = false
		}
		if rest, ok := strings.CutPrefix(trimmed, "- name: "); ok && indent == 6 {
			if name != "" {
				steps[name] = cur
			}
			name, cur = rest, workflowStep{index: n, keys: map[string]string{}}
			n++
			continue
		}
		if name == "" || indent != 8 || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, _ := strings.Cut(trimmed, ":")
		cur.keys[key] = strings.TrimSpace(value)
		if key == "run" && strings.TrimSpace(value) == "|" {
			inRun, keyIndent, blockIndent = true, indent, -1
		}
	}
	if name != "" {
		steps[name] = cur
	}
	return steps
}

const tagStep = "Fetch the release tags that name the pinned commit"

// The shipped workflow fetches the release tags of its pin between the pinned checkout and the run, in a bash step in
// plimsoll's checkout that reads the pin from the environment (no workflow expression is pasted into the script),
// fetches tag refs only, and moves nothing: no checkout, reset, switch, merge or pull. Every action stays pinned by a
// full commit SHA and the job's permissions stay contents: read.
func TestTheWorkflowFetchesTheReleaseTagsOfItsPin(t *testing.T) {
	steps := readWorkflowSteps(t)
	step, ok := steps[tagStep]
	if !ok {
		t.Fatalf("workflow.yml has no step %q", tagStep)
	}
	checkout, okC := steps["Check out trusted pinned plimsoll tools"]
	run, okR := steps["Run the project and check its receipt"]
	if !okC || !okR || !(checkout.index < step.index && step.index < run.index) {
		t.Errorf("the tag step is step %d; want it after the pinned checkout (%d) and before the run (%d)", step.index, checkout.index, run.index)
	}
	if step.keys["shell"] != "bash" || step.keys["working-directory"] != "tools/plimsoll" || step.keys["uses"] != "" {
		t.Errorf("the tag step's keys are %v; want a bash run step in tools/plimsoll", step.keys)
	}
	if !strings.Contains(step.run, `"$PLIMSOLL_REF"`) || strings.Contains(step.run, "${{") {
		t.Error("the tag step must read the pin from the environment, with no workflow expression in its script")
	}
	if !strings.Contains(step.run, `git fetch --no-tags --no-recurse-submodules --depth=1 origin "${refs[@]}"`) ||
		!strings.Contains(step.run, `refs+=("+refs/tags/$tag:refs/tags/$tag")`) {
		t.Error("the tag step does not fetch exactly the listed tag refs")
	}
	for _, verb := range []string{"checkout", "reset", "switch", "merge", "pull", "rebase", "worktree", "update-ref", "restore"} {
		if regexp.MustCompile(`\bgit\b[^\n]*\b` + verb + `\b`).MatchString(step.run) {
			t.Errorf("the tag step runs git %s, which could change what the checkout holds", verb)
		}
	}
	raw, err := os.ReadFile("workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?m)^\s*uses:\s*(\S+)`).FindAllStringSubmatch(string(raw), -1) {
		if !regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(m[1]) {
			t.Errorf("%s is not pinned by a full commit SHA", m[1])
		}
	}
	if !strings.Contains(string(raw), "permissions:\n  contents: read\njobs:") {
		t.Error("the workflow's permissions are no longer contents: read alone")
	}
}

// The workflow's checkout of plimsoll, imitated with plain git: one commit fetched by its SHA at depth 1 with no tags,
// as the pinned checkout action does with a SHA (its ref-helper and git-command-manager at that commit), then the tag
// step's own script from workflow.yml, run as GitHub runs a bash step. At a release commit buildvcs.sh then answers
// true and the build states the release; at a commit no release names, false and (devel). Only release tags naming the
// pinned commit are fetched: a pre-release and a tag that is no version on it, and releases on other commits, stay out,
// and the step moves nothing.
func TestTheWorkflowsCheckoutStatesTheRelease(t *testing.T) {
	w := newStampWorld(t)
	origin := w.repo("origin", "example.com/tiny", "v0.27.1")
	if err := os.WriteFile(filepath.Join(origin, "main.go"), []byte("package main\n\nfunc main() { println(28) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.git(origin, "commit", "-q", "-am", "the release")
	w.git(origin, "tag", "v0.27.9")
	w.git(origin, "tag", "-a", "-m", "v0.28.0", "v0.28.0")
	w.git(origin, "tag", "v0.29.0-rc.1")
	w.git(origin, "tag", "latest")
	release := w.git(origin, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(origin, "main.go"), []byte("package main\n\nfunc main() { println(29) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.git(origin, "commit", "-q", "-am", "after the release")
	w.git(origin, "tag", "-a", "-m", "v0.30.0", "v0.30.0", release+"~1")
	unreleased := w.git(origin, "rev-parse", "HEAD")

	step, ok := readWorkflowSteps(t)[tagStep]
	if !ok || step.run == "" {
		t.Fatalf("workflow.yml has no run script for %q", tagStep)
	}
	script := filepath.Join(w.root, "tag-step.sh")
	if err := os.WriteFile(script, []byte(step.run), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, pin, release string
		tags               []string
	}{
		{"a release commit", release, "v0.28.0", []string{"v0.27.9", "v0.28.0"}},
		{"a commit no release names", unreleased, "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			parent := w.t
			w.t = t
			defer func() { w.t = parent }()
			dir := w.shallow(origin, c.pin, "checkout-"+c.pin[:12])
			env := w.env("PLIMSOLL_REF=" + c.pin)
			cmd := exec.Command(w.bash, "--noprofile", "--norc", "-eo", "pipefail", script)
			cmd.Dir, cmd.Env = dir, env
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("the tag step: %v\n%s", err, out)
			}
			if got := strings.Fields(w.git(dir, "tag", "--list")); !slices.Equal(got, c.tags) {
				t.Errorf("the checkout holds tags %v, want %v", got, c.tags)
			}
			if head := w.git(dir, "rev-parse", "HEAD"); head != c.pin {
				t.Errorf("HEAD moved to %s", head)
			}
			if status := w.git(dir, "status", "--porcelain"); status != "" {
				t.Errorf("the checkout changed: %s", status)
			}
			got := w.answer(dir, env)
			s := w.build(dir, got, env)
			if c.release != "" && (got != "true" || s.version != c.release || s.revision != c.pin) {
				t.Errorf("buildvcs.sh says %s and the build states %s at %s; want true and %s at %s", got, s.version, s.revision, c.release, c.pin)
			}
			if c.release == "" && (got != "false" || s.version != "(devel)" || s.vcs) {
				t.Errorf("buildvcs.sh says %s and the build states %s; want false and (devel)", got, s.version)
			}
			if err := w.check(dir, s.binary, env); err != nil {
				t.Errorf("the second form refuses the build: %v", err)
			}
		})
	}
}

// Every docker build in a published workflow of a Dockerfile that copies from a named build
// context must pass that context, as make docker-images does. v0.28.0 shipped this workflow's
// build without --build-context nativehelper=..., so every user's job failed at the image
// build and made no receipt (finding release-104, found on a real GitHub run): no test built
// the image the way the workflow does.
func TestEveryWorkflowDockerBuildPassesTheContextsItsDockerfileNeeds(t *testing.T) {
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "workflow.yml")
	from := regexp.MustCompile(`(?m)^\s*COPY\s+--from=([a-z][a-z0-9_-]*)\s`)
	stage := regexp.MustCompile(`(?mi)^\s*FROM\s+\S+\s+AS\s+([a-z0-9_-]+)\s*$`)
	checked := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, cmd := range workflowDockerBuilds(string(raw)) {
			fields := strings.Fields(cmd)
			dir, dockerfile := fields[len(fields)-1], ""
			for i, w := range fields {
				if w == "-f" && i+1 < len(fields) {
					dockerfile = fields[i+1]
				}
			}
			// Map the workflow's checkout path back to this repository.
			local := func(p string) string {
				p = strings.TrimPrefix(p, "tools/plimsoll/")
				return filepath.Join("..", "..", p)
			}
			path := filepath.Join(local(dir), "Dockerfile")
			if dockerfile != "" {
				path = local(dockerfile)
			}
			df, err := os.ReadFile(path)
			if err != nil {
				continue // not one of plimsoll's own Dockerfiles
			}
			stages := map[string]bool{}
			for _, m := range stage.FindAllStringSubmatch(string(df), -1) {
				stages[strings.ToLower(m[1])] = true
			}
			for _, m := range from.FindAllStringSubmatch(string(df), -1) {
				name := m[1]
				if stages[name] {
					continue
				}
				checked++
				if !strings.Contains(cmd, "--build-context "+name+"=") {
					t.Errorf("%s: %q builds %s, which copies from the build context %q, without --build-context %s=...", f, cmd, path, name, name)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no docker build of a Dockerfile with a named build context was found; the check reads nothing")
	}
}

// workflowDockerBuilds returns each docker build command of a workflow's run: steps, a folded
// or literal block's lines joined, so a command split across lines reads as one.
func workflowDockerBuilds(text string) []string {
	lines := strings.Split(text, "\n")
	indent := func(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }
	var cmds []string
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		t = strings.TrimPrefix(t, "- ")
		if !strings.HasPrefix(t, "run:") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(t, "run:"))
		var parts []string
		if body == ">-" || body == ">" || body == "|" || body == "|-" {
			base := indent(lines[i])
			for j := i + 1; j < len(lines) && (strings.TrimSpace(lines[j]) == "" || indent(lines[j]) > base); j++ {
				parts = append(parts, strings.TrimSpace(lines[j]))
			}
		} else {
			parts = []string{body}
		}
		joined := strings.Join(parts, " ")
		for _, m := range regexp.MustCompile(`docker build( +[^;&|]+)`).FindAllString(joined, -1) {
			cmds = append(cmds, strings.TrimSpace(m))
		}
	}
	return cmds
}
