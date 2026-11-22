package sandbox

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// Every node command line plimsoll writes is built in sessionkit (node.go), by NodeArgv for
// its own programs, which keeps their debugger shut to guest code with
// --disable-sigusr1 (finding rust-native-helper-26), or by GuestNodeArgv or
// StartupNodeArgv, which say why that node is left as it is. This test fails the build on a
// node command line written anywhere else: in a non-test Go file of the code that builds
// sandbox command lines, and in an in-sandbox script that starts node itself. A new node
// program therefore cannot be added without choosing one of the three, as
// TestDockerCLIIsStartedOnlyThroughDockerCommand does for the docker CLI.
func TestNodeIsStartedOnlyThroughSessionkit(t *testing.T) {
	t.Parallel()
	root := ".."
	// Go: the literal "node" or a full path to it (an argv word), a shell command line
	// that starts node, and a script in a literal that starts node. Under clients/ and
	// examples/ too since 2026-11-20 (hunt-quality-64): code there writes the steps and
	// harnesses that run in a sandbox, and the scan found one that needed the flag
	// (examples/squeeze, flyStep).
	var goFiles []string
	for _, dir := range []string{"sandbox", "cmd", "internal", "clients", "examples"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				goFiles = append(goFiles, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	onePlace := filepath.Join(root, "sandbox", "internal", "sessionkit", "node.go")
	fset := token.NewFileSet()
	seen := map[string]bool{}
	for _, p := range goFiles {
		if p == onePlace {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			own := !strings.HasPrefix(rel, "clients/") && !strings.HasPrefix(rel, "examples/")
			why := nodeStartIn(v, own)
			if why == "" {
				return true
			}
			key := rel + ": " + v
			if len(key) > 160 {
				key = key[:160]
			}
			if _, ok := nodeStartExceptions[key]; ok {
				seen[key] = true
				return true
			}
			t.Errorf("%s: %s; build it with sessionkit.NodeArgv, GuestNodeArgv, GuestNode or StartupNodeArgv (sandbox/internal/sessionkit/node.go) (key %q)", fset.Position(lit.Pos()), why, key)
			return true
		})
	}
	// In-sandbox scripts: every node a script starts itself (process.execPath as a
	// program) carries the flag, or is an exception counted below with its reason.
	for _, dir := range []string{"sandbox", "docker"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || d.Name() == "node_modules" || d.Name() == "target") {
				return filepath.SkipDir
			}
			ext := filepath.Ext(p)
			if d.IsDir() || (ext != ".js" && ext != ".mjs" && ext != ".cjs" && ext != ".sh") {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			n := len(jsNodeStarts(string(raw)))
			if ext == ".sh" {
				for _, line := range strings.Split(string(raw), "\n") {
					if l := strings.TrimSpace(line); !strings.HasPrefix(l, "#") && nodeShellStart.MatchString(l) {
						n++
					}
				}
			}
			want := scriptNodeStartExceptions[rel].count
			if n != want {
				t.Errorf("%s: %d node starts without %s, not the %d its exception names; add the flag (sessionkit.NodeSignalFlag) or state the exception in scriptNodeStartExceptions", rel, n, sessionkit.NodeSignalFlag, want)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for key := range nodeStartExceptions {
		file, _, _ := strings.Cut(key, ": ")
		if _, err := os.Stat(filepath.Join(root, file)); err != nil {
			continue // a file this copy does not carry (the public repository holds fewer)
		}
		if !seen[key] {
			t.Errorf("exception %q matches nothing any more; remove it", key)
		}
	}
}

// nodeStartIn says how a Go string literal starts node, "" when it does not: the argv word
// node, by name or by a full path ("/usr/bin/node"); a shell command line that starts
// node; a script that starts node without the flag. In the code that builds plimsoll's own
// command lines (own: sandbox, cmd, internal) every shell start counts, flag or no flag,
// since sessionkit builds them all; under clients/ and examples/, which cannot import
// sessionkit, a shell start that carries the flag as its first argument is in order.
func nodeStartIn(v string, own bool) string {
	switch {
	case v == "node" || strings.HasSuffix(v, "/node"):
		return `the argv word "node"`
	case own && nodeShellStart.MatchString(v):
		return "a shell command line that starts node"
	case shellNodeStartWithoutFlag(v):
		return "a shell command line that starts node without " + sessionkit.NodeSignalFlag
	case len(jsNodeStarts(v)) > 0:
		return "a script that starts node without " + sessionkit.NodeSignalFlag
	}
	return ""
}

// nodeShellStart is a shell command line that starts node: the word node, by name or at
// the end of a path (/usr/bin/node), followed by an option, a path, a script file, a
// variable, or (a literal that ends there) a space before what is concatenated after it.
// Prose that names node ("node did not answer") does not match. What follows it is
// checked for the flag (shellNodeStartWithoutFlag).
var nodeShellStart = regexp.MustCompile(`(?:^|[\s;&|(/])node(?:\s+(?:-|/|\.|\$|[A-Za-z0-9_./-]+\.[cm]?js\b)|\s+$)`)

// shellNodeStartWithoutFlag reports whether line starts node somewhere without the flag
// as its first argument.
func shellNodeStartWithoutFlag(line string) bool {
	for _, m := range nodeShellStart.FindAllStringIndex(line, -1) {
		from := m[0] + strings.Index(line[m[0]:m[1]], "node") + len("node")
		if rest := strings.TrimLeft(line[from:], " \t"); !strings.HasPrefix(rest, sessionkit.NodeSignalFlag+" ") && rest != sessionkit.NodeSignalFlag {
			return true
		}
	}
	return false
}

// jsNodeStart is a script starting node itself: process.execPath, or node named in a
// string by name or by a full path ('node', "/usr/bin/node"), as the program of an argv
// array or of a child_process call. What follows it is checked for the flag.
var jsNodeStart = regexp.MustCompile("(?:\\[\\s*|(?:spawn|spawnSync|execFile|execFileSync|fork)\\(\\s*)(?:process\\.execPath|['\"`](?:[^'\"`\\s]*/)?node['\"`])\\s*,\\s*\\[?\\s*")

// jsShellStart is a script starting node through a shell: exec or execSync of a command
// line, whose text shellNodeStartWithoutFlag then reads.
var jsShellStart = regexp.MustCompile("(?:exec|execSync)\\(\\s*['\"`]([^'\"`]*)['\"`]")

// jsNodeStarts returns the offsets of the node starts in src that are not followed by the flag.
func jsNodeStarts(src string) []int {
	var out []int
	for _, m := range jsNodeStart.FindAllStringIndex(src, -1) {
		rest := src[m[1]:]
		if !strings.HasPrefix(rest, `"`+sessionkit.NodeSignalFlag+`"`) && !strings.HasPrefix(rest, `'`+sessionkit.NodeSignalFlag+`'`) {
			out = append(out, m[0])
		}
	}
	for _, m := range jsShellStart.FindAllStringSubmatchIndex(src, -1) {
		if shellNodeStartWithoutFlag(src[m[2]:m[3]]) {
			out = append(out, m[0])
		}
	}
	return out
}

// The scan's own shapes, each as a line that must count and its flagged form that must
// not: the three it missed until 2026-11-20 (a node named by a full path, a script that
// starts node by name, Go under clients/ and examples/, hunt-quality-64) beside the ones
// it had.
func TestNodeStartScanFindsEachShape(t *testing.T) {
	t.Parallel()
	flag := sessionkit.NodeSignalFlag
	for _, tc := range []struct {
		literal string
		found   bool
	}{
		{"node", true},
		{"/usr/bin/node", true},
		{"/usr/local/bin/node", true},
		{"node_modules", false},
		{"/work/node_modules/x", false},
		{"node main.js", true},
		{"node " + flag + " main.js", false},
		{"cd /work && node --no-warnings run.mjs", true},
		{"cd /work && /usr/bin/node -e 1", true},
		{"/usr/bin/node " + flag + " -e 1", false},
		{"exec /usr/local/bin/node /runner.mjs", true},
		{"node ", true}, // a literal that ends before what is concatenated after it
		{"node " + flag, false},
		{"node did not answer", false},
		{"the image's node does not accept it", false},
		{`spawn(process.execPath, ["-e", x])`, true},
		{`spawn(process.execPath, ["` + flag + `", "-e", x])`, false},
		{`spawnSync('node', ['run.mjs'])`, true},
		{`spawnSync('node', ['` + flag + `', 'run.mjs'])`, false},
		{`execFile("/usr/bin/node", ["run.mjs"])`, true},
		{"cp.fork(`node`, [])", true},
		{`const argv = ["node", "x.js"]`, true},
		{`const argv = ['node', '` + flag + `', 'x.js']`, false},
		{`execSync("node run.mjs")`, true},
		{`execSync("node ` + flag + ` run.mjs")`, false},
		{`const pinRequired = ["node", "sh", "setpriv"];`, true}, // counted: a list that starts with node reads as an argv, so it is a stated exception
	} {
		if got := nodeStartIn(tc.literal, false) != ""; got != tc.found {
			t.Errorf("nodeStartIn(%q) found a node start: %v, want %v", tc.literal, got, tc.found)
		}
	}
	// In plimsoll's own command-line code a shell start counts with the flag too: it is
	// written by sessionkit or it is an exception.
	if nodeStartIn("node "+flag+" main.js", true) == "" || nodeStartIn("/usr/bin/node "+flag+" -e 1", true) == "" {
		t.Error("a hand-written flagged shell start in plimsoll's own code was not counted")
	}
}

// nodeStartExceptions are the Go literals that name node and are not a node command line
// of plimsoll's own, keyed "file: literal" (cut at 160 bytes), each with why. The guest's
// own steps and snippets are guest code: the guest already runs inside that process.
var nodeStartExceptions = map[string]string{
	`sandbox/internal/dcfake/agent/main.go: node`: "a user name (the fake agent's default user), not a command",
	`sandbox/agentsandbox/smoke.go: node`:         "a log line's key, not a command",
	`sandbox/e2b.go: node`:                        "the word looked for in env's error text when the closed PATH holds no node (e2bNoControlNode), not a command",
	`sandbox/e2b_session.go: node`:                "the name the open pins node's path under (e2bRequiredBins, Interps.Bins), a map key; every E2B start of node is built by NodeArgv or GuestNodeArgv and names the path through it",

	// Under examples/ (scanned since 2026-11-20). A project step is the caller's own
	// command: the reasons below say, for each, why no node of a trusted program runs
	// there beside code it must keep out, which is the case the flag is for. The one
	// start that was such a case, examples/squeeze's flyStep, now carries the flag. A
	// working copy that holds examples of its own adds their entries from a file of its
	// own (an init in this package).
	`examples/adapter/main.go: node probe.js `:                                        "a project step: the example's own script, alone in its run",
	`examples/adapter/main.go: node harness.js `:                                      "a project step: the harness loads the adapter under test into its own process, so no node of the harness's stands apart from that code",
	`examples/adapter/qualify/statement.go: node harness.js `:                         "the same step's words, compared with a stored statement; nothing is started here",
	`examples/adapter/qualify/statement.go: node `:                                    "a step's first word, compared with a stored statement; nothing is started here",
	`examples/adapter/trial/practice/practice.go: node harness.js nominal adapter.js`: "a project step: the harness loads the adapter under test into its own process",
	`examples/dependency-receipt/live/evidence.go: node`:                              "an argv word read back from a run's evidence and compared; nothing is started here",
	`examples/dependency-receipt/live/page.go: plimsoll's in-sandbox runner, node /runner.mjs: it writes the run's files, checks that a step cannot open its descript`: "a page's sentence about the runner, not a command",
	`examples/dependency-receipt/live/page.go: node /runner.mjs`:                                                               "the published run's runner command line, compared with a log's to pick the sentence; nothing is started here",
	`examples/dependency-receipt/live/run.go: node -e 'require("plimsoll-fixture-`:                                             "a project step that loads the package under observation: the guest's own code, which is the process",
	`examples/internal/grade/grade.go: base64 -d %s.b64 > %s.bin && node --no-warnings /oracle/graders/%s.mjs %s.bin %s`:       "a grading run of its own: the only code in that sandbox is the image's grader, and the trajectories are data",
	`examples/nemotron-agent/main.go: node`:                                                                                    "a language's name in a model's answer, not a command",
	`examples/oracle/main.go: node --no-warnings /oracle/run.mjs controller.js`:                                                "the image's trial runner, which starts itself again with the flag before it reads anything (docker/sim/oracle/run.mjs, rust-native-helper-34)",
	`examples/providers/main.go: node --version`:                                                                               "a project step that prints node's version, alone",
	`examples/providers/main.go: node decode.mjs`:                                                                              "a project step: the example's own decoder on a trajectory, which is data",
	`examples/providers/main.go: node --no-warnings run.mjs controller.js cartpole.wasm 0.2 20 trajectory.bin`:                 "the image's trial runner sent as a file (docker/sim/oracle/run.mjs), which starts itself again with the flag",
	`examples/sessions/main.go: node test.js`:                                                                                  "a project step: the example's own test, the guest's code",
	"examples/sessions/main.go: files: lib.js, test.js\nstep:  node test.js":                                                   "a page's label for that step, not a command",
	`examples/sessions/main.go: step:  node test.js`:                                                                           "a page's label for that step, not a command",
	`examples/wasm-buck/main.go: node --no-warnings /oracle/judge.mjs %s %s %s.scenario %s %s %s.bin`:                          "the image's judge, which starts itself again with the flag before it reads the scenario (docker/sim/oracle/judge.mjs, rust-native-helper-34)",
	`examples/wasm-controller/main.go: node --no-warnings /oracle/judge.mjs %s /models/cartpole.wasm %s.scenario %s %s %s.bin`: "the image's judge, which starts itself again with the flag",
}

// scriptNodeStartExceptions counts, per in-sandbox script, what the scan reads as a node
// start that carries no flag, with why. No script under sandbox/ or docker/ starts a node
// without the flag, the trial runners' controllers included (rust-native-helper-34,
// 2026-11-20); the one entry is a list of names the scan cannot tell from an argv. A file
// under docker/ is part of an image, so a change there is an image rebuild.
var scriptNodeStartExceptions = map[string]struct {
	count int
	why   string
}{
	"sandbox/e2b_session.js": {1, `pinRequired = ["node", "sh", "setpriv"]: the names of the programs the open pins, a list that starts with node, not an argv`},
}

// The docker provider's own node programs carry the flag, and the guest's node does not:
// the forwarder of a granted run (its runner, the native helper, is no node), and the forwarder of a granted
// snippet, whose child is the snippet's own node.
func TestDockerNodeCommandLinesCarryTheSignalFlag(t *testing.T) {
	t.Parallel()
	count := func(argv []string) (flags, nodes int) {
		for _, a := range argv {
			switch a {
			case "node":
				nodes++
			case sessionkit.NodeSignalFlag:
				flags++
			}
		}
		return
	}
	runner, err := (&DockerSandbox{}).runnerArgv("m")
	if err != nil {
		t.Fatal(err)
	}
	forwarding, err := (&DockerSandbox{}).forwardingRunnerArgv("m", "127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	snippet, err := dockerForwardingSnippetArgv("m", "127.0.0.1:8080", []string{"A=1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		argv          []string
		flags, guests int
	}{
		// The runner is the native helper, no node at all; the forwarder in front of it is node.
		{"runner", runner, 0, 0},
		{"forwarding runner", forwarding, 1, 0},
		{"forwarding snippet", snippet, 1, 1},
	} {
		flags, nodes := count(tc.argv)
		if flags != tc.flags || nodes-flags != tc.guests {
			t.Errorf("%s: %d nodes, %d with %s; want %d with it and %d guest node", tc.name, nodes, flags, sessionkit.NodeSignalFlag, tc.flags, tc.guests)
		}
	}
	// The flag is an argument, never a variable a guest's node could inherit.
	for _, argv := range [][]string{runner, forwarding, snippet} {
		for _, a := range argv {
			if strings.HasPrefix(a, "NODE_OPTIONS=") {
				t.Errorf("a command line sets %q", a)
			}
		}
	}
}
