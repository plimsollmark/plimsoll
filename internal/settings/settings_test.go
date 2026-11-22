package settings

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// variableName is the shape of a variable plimsolld or a provider it builds reads.
var variableName = regexp.MustCompile(`^(?:(?:PLIMSOLL|SANDBOX|E2B|DOCKER_SBX|AWS)_[A-Z0-9_]+|DOCKER_HOST|DOCKER_DEFAULT_PLATFORM)$`)

// notSettings are names of that shape that are not settings the daemon reads, each with
// why. A new entry needs a reason a reviewer can check.
var notSettings = map[string]string{
	"PLIMSOLL_WORK":                         "set by plimsoll for a guest's program (its working directory), never read by the daemon",
	"PLIMSOLL_INTERP_DIR":                   "set by plimsoll for a session's interpreter, never read by the daemon",
	"PLIMSOLL_RELAY_UID":                    "set by plimsoll for a session's relay inside the sandbox, never read by the daemon",
	"PLIMSOLL_RUNNER_PID":                   "set by plimsoll's runner inside the sandbox, never read by the daemon",
	"SANDBOX_STATUS_RUNNING":                "a Docker Cloud API value, not a variable",
	"SANDBOX_STATUS_FAILED":                 "a Docker Cloud API value, not a variable",
	"SANDBOX_STATUS_STOPPED":                "a Docker Cloud API value, not a variable",
	"SANDBOX_STATUS_STOPPING":               "a Docker Cloud API value, not a variable",
	"SANDBOX_ENDPOINT_PROTOCOL_CONNECT":     "a Docker Cloud API value, not a variable",
	"SANDBOX_ENDPOINT_PROTOCOL_UNIX_SOCKET": "a Docker Cloud API value, not a variable",
	"SANDBOX_TEST_REQUIRE_DOCKER":           "a test suite's switch (sandbox/internal/dockertest), read by tests only",
}

// daemonRoots are the directories whose code plimsolld is built from. The other programs
// (cmd/plimsoll-attest, the clients, the examples, the guest-side programs) read variables
// of their own, which are not plimsolld's settings.
var daemonRoots = []string{"cmd/plimsolld", "sandbox", "internal", "placement", "record", "protocol"}

// skipDirs are directories under daemonRoots that hold no daemon code.
var skipDirs = map[string]string{
	"internal/settings":    "this table",
	"internal/clientsuite": "the client suites' named test daemons (PLIMSOLL_*_URL tell a suite where each is)",
}

// TestNoVariableIsReadOutsideTheTable fails when a non-test file names one of plimsolld's
// variables by a string literal instead of through its setting here: a direct read
// (getenv("X"), os.Getenv("X")), or a list or message built from the literal. That is how
// a variable used to escape -h and the unknown-variable warning: TestUsageNamesEveryVariable
// scanned cmd/plimsolld, sandbox/factory.go and sandbox/*/env.go only, and missed the
// reads in internal/grants, internal/rpc and docker's Preflight (DOCKER_DEFAULT_PLATFORM,
// DOCKER_HOST).
func TestNoVariableIsReadOutsideTheTable(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	found := 0
	for _, dir := range daemonRoots {
		if err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if _, skip := skipDirs[rel]; skip || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil || !variableName.MatchString(s) {
					return true
				}
				found++
				if _, ok := notSettings[s]; ok {
					return true
				}
				if _, ok := byName[s]; ok {
					t.Errorf("%s: names %s by a literal; read it through its setting (internal/settings)", fset.Position(lit.Pos()), s)
				} else {
					t.Errorf("%s: names %s, which no setting declares: declare it in internal/settings/registry.go, or list it in notSettings with why it is not one", fset.Position(lit.Pos()), s)
				}
				return true
			})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if found == 0 {
		t.Fatal("found no variable names at all; the scan is broken")
	}
}

// TestEverySettingIsDocumented: every setting has -h text or names the setting whose
// entry documents it, in the same section, and every section prints something.
func TestEverySettingIsDocumented(t *testing.T) {
	for name, m := range byName {
		switch {
		case m.Doc == "" && m.DocWith == "":
			t.Errorf("%s has no -h text", name)
		case m.DocWith != "" && (byName[m.DocWith] == nil || byName[m.DocWith].section != m.section || byName[m.DocWith].DocWith != ""):
			t.Errorf("%s is documented with %s, which is not a documented setting of its section", name, m.DocWith)
		}
	}
	help := Help([]string{"wasm"}, func(string) bool { return true })
	for _, name := range Names() {
		if !regexp.MustCompile(`(?m)^  (?:[A-Z0-9_]+ / )*` + name + `\b`).MatchString(help) {
			t.Errorf("-h has no entry for %s", name)
		}
	}
	// Every declared default reads as its own kind (a bad one would panic at the first read).
	unset := func(string) string { return "" }
	for _, v := range all {
		var err error
		switch v := v.(type) {
		case *Int:
			_, err = v.Get(unset)
		case *Duration:
			_, err = v.Get(unset)
		}
		if err != nil {
			t.Errorf("%s: %v", NameOf(v), err)
		}
	}
	if !strings.Contains(Help([]string{"wasm", "docker"}, func(string) bool { return false }), "  SANDBOX_PROVIDER           wasm | docker | (unset = disabled)") {
		t.Error("-h does not list the providers it is given")
	}
	if strings.Contains(Help(nil, func(string) bool { return false }), "SANDBOX_WSLC_") {
		t.Error("-h prints the section of a provider the build does not have")
	}
}

// namesADefault finds where a -h entry (its lines joined by single spaces) states the
// setting's own default: "(default X", "; default X", "X (default)", "(the default;".
// "docker's built-in default" and "off by default" are not that.
var namesADefault = regexp.MustCompile(`\(default[ )=]|[;,:] default |\(the default[;)]`)

// defaultInOtherWords are the settings whose table default is stated in -h in words
// that do not repeat it whole; the words given must be in the entry and in the default.
var defaultInOtherWords = map[string]string{
	"SANDBOX_AGENTSANDBOX_CA_FILE": "/var/run/secrets/kubernetes.io/serviceaccount",
}

// defaultNotInTheTable are the settings whose -h entry names a default the table does not
// hold, each with where that default lives. For these the text and the value can still
// part (hunt-quality-60 stays open for them); the list exists so that it cannot grow
// unseen: a new setting that names a default in its text holds it in the table's Default,
// where TestAHelpTextsDefaultIsTheTablesDefault checks it, or is added here with a reason.
var defaultNotInTheTable = map[string]string{
	"PLIMSOLL_METRICS_ADDR":                     "cmd/plimsolld: the metrics listener's own default",
	"PLIMSOLL_LOG_FORMAT":                       "cmd/plimsolld: anything but text is json",
	"SANDBOX_DOCKER_IMAGE":                      "the docker provider's default image",
	"SANDBOX_DOCKER_PROJECT_IMAGE":              "the docker provider's default project image",
	"SANDBOX_GUEST_UID":                         "the docker provider's default guest uid",
	"SANDBOX_DOCKERCLOUD_AUTH_URL":              "the dockercloud provider's default endpoint",
	"SANDBOX_DOCKERCLOUD_POLICY_URL":            "the dockercloud provider's default endpoint",
	"SANDBOX_DOCKERCLOUD_API":                   "the dockercloud provider's default API",
	"SANDBOX_DOCKERCLOUD_API_URL":               "the dockercloud provider's default per API",
	"SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE":  "states the agentsandbox provider's memory and CPU defaults, other settings' own",
	"SANDBOX_AGENTSANDBOX_SANDBOXD_SERVER_NAME": "the agentsandbox provider's default name",
	"SANDBOX_LAMBDAMICROVM_SIGNING_NAME":        "the lambdamicrovm provider's default",
	"SANDBOX_LAMBDAMICROVM_INGRESS_CONNECTOR":   "the lambdamicrovm provider's default",
	"SANDBOX_OPENSHELL_IMAGE":                   "states the openshell provider's memory and CPU defaults, other settings' own",
	"SANDBOX_WSLC_MODE":                         "the wslc provider's default mode",
	"SANDBOX_WSLC_MAX_SESSIONS":                 "the wslc provider's default in the per-run mode (the shared mode takes none)",
	"SANDBOX_WSLC_RUNSC_HELPERS":                "the wslc provider: none",
	"SANDBOX_WSLC_RUN_ROOT":                     "the wslc provider's default, read from Windows",
	"SANDBOX_WSLC_PATH":                         "the wslc provider's default path",
	"SANDBOX_WSLC_NPROC":                        "the wslc provider's default",
	"SANDBOX_PER_KEY_CONCURRENT":                "computed from SANDBOX_MAX_CONCURRENT (PerKeyConcurrentDefault)",
	"SANDBOX_RATE_BURST":                        "computed from SANDBOX_RATE_PER_MIN",
}

// statedDefault checks one setting's -h entry against the table's default for it: an
// entry that names a default names the table's, whole, every time it names one; an entry
// whose setting holds no default in the table names none, unless listed (notInTable).
func statedDefault(m *Meta, isBool bool, otherWords, notInTable map[string]string) error {
	doc := strings.Join(strings.Fields(m.Doc), " ")
	at := namesADefault.FindAllStringIndex(doc, -1)
	if isBool && regexp.MustCompile(`\bon by default\b|\(default (?:on|1|true)\b`).MatchString(doc) {
		return fmt.Errorf("%s is a switch, off when unset, and its -h entry says it is on by default", m.Name)
	}
	if m.Default == "" {
		_, listed := notInTable[m.Name]
		switch {
		case len(at) > 0 && !listed:
			return fmt.Errorf("%s: its -h entry names a default (%q) and the table holds none: set Default, or list it in defaultNotInTheTable with where the default lives", m.Name, doc[at[0][0]:min(len(doc), at[0][1]+30)])
		case len(at) == 0 && listed:
			return fmt.Errorf("%s is listed in defaultNotInTheTable and its -h entry names no default; remove it from the list", m.Name)
		}
		return nil
	}
	if _, listed := notInTable[m.Name]; listed {
		return fmt.Errorf("%s is listed in defaultNotInTheTable and the table holds its default %q; remove it from the list", m.Name, m.Default)
	}
	if words, ok := otherWords[m.Name]; ok {
		if !strings.Contains(doc, words) || !strings.Contains(m.Default, words) {
			return fmt.Errorf("%s: its default %q and its -h entry do not both hold %q", m.Name, m.Default, words)
		}
		return nil
	}
	for _, loc := range at {
		// "X (default) or Y", "X (the default; ...": the default is the word before.
		if found := doc[loc[0]:loc[1]]; found == "(default)" || strings.HasPrefix(found, "(the default") {
			if before := strings.TrimRight(doc[:loc[0]], " "); !strings.HasSuffix(" "+before, " "+m.Default) {
				return fmt.Errorf("%s: its -h entry marks %q as the default and the table's default is %q", m.Name, before[max(0, len(before)-30):], m.Default)
			}
			continue
		}
		start := strings.Index(doc[loc[0]:], "default") + loc[0] + len("default")
		rest := strings.TrimLeft(doc[start:], " =")
		after := strings.TrimPrefix(rest, m.Default)
		if !strings.HasPrefix(rest, m.Default) || (after != "" && !strings.ContainsRune(" ,;:)", rune(after[0]))) {
			return fmt.Errorf("%s: its -h entry says %q and the table's default is %q", m.Name, doc[loc[0]:min(len(doc), start+30)], m.Default)
		}
	}
	return nil
}

// TestAHelpTextsDefaultIsTheTablesDefault: the default a setting's -h entry names is the
// one the table holds, so a changed default cannot leave -h saying the old one
// (hunt-quality-60). It found two on 2026-11-20: SANDBOX_WSLC_MAX_SESSIONS and
// SANDBOX_WSLC_NPROC held "0" in the table beside "(default 2" and "(default 256", the
// provider's own defaults; the table no longer claims a default for them.
func TestAHelpTextsDefaultIsTheTablesDefault(t *testing.T) {
	for _, v := range all {
		_, isBool := v.(*Bool)
		if err := statedDefault(v.meta(), isBool, defaultInOtherWords, defaultNotInTheTable); err != nil {
			t.Error(err)
		}
	}
	for name := range defaultNotInTheTable {
		if byName[name] == nil {
			t.Errorf("defaultNotInTheTable lists %s, which is not a setting", name)
		}
	}
	for name := range defaultInOtherWords {
		if byName[name] == nil || byName[name].Default == "" {
			t.Errorf("defaultInOtherWords lists %s, which holds no default in the table", name)
		}
	}
	// The check itself, on copies of entries with one thing changed.
	for _, tc := range []struct {
		what string
		m    Meta
		bool bool
		ok   bool
	}{
		{"the table's default as stated", Meta{Name: "X", Default: "8", Doc: "global max in-flight runs (default 8)"}, false, true},
		{"a default changed in the table alone", Meta{Name: "X", Default: "9", Doc: "global max in-flight runs (default 8)"}, false, false},
		{"a default changed in the text alone", Meta{Name: "X", Default: "30m", Doc: "a lifetime\n(default 45m, at most 12h)"}, false, false},
		{"a default that only starts the same", Meta{Name: "X", Default: "30", Doc: "a lifetime (default 30m, at most 12h)"}, false, false},
		{"a default over a line break", Meta{Name: "X", Default: "30m", Doc: "a lifetime (default\n30m, at most 12h)"}, false, true},
		{"stated twice, once wrong", Meta{Name: "X", Default: "0", Doc: "a cap (default 0: none); shared: default 2"}, false, false},
		{"a default with a meaning after it", Meta{Name: "X", Default: "0", Doc: "a cap (the end user; default 0: no cap)"}, false, true},
		{"marked as the default", Meta{Name: "X", Default: "json", Doc: "json (default) or text"}, false, true},
		{"the other one marked as the default", Meta{Name: "X", Default: "text", Doc: "json (default) or text"}, false, false},
		{"marked as the default after other words", Meta{Name: "X", Default: "connect", Doc: "which API: connect (the default; the only one with a contract) or rest"}, false, true},
		{"a default the table does not hold", Meta{Name: "X", Doc: "an image (default node:22-alpine)"}, false, false},
		{"no default named", Meta{Name: "X", Doc: "keeps docker's built-in default"}, false, true},
		{"a switch said to be off", Meta{Name: "X", Doc: "per-run only, off by default"}, true, true},
		{"a switch said to be on", Meta{Name: "X", Doc: "on by default"}, true, false},
	} {
		if err := statedDefault(&tc.m, tc.bool, nil, nil); (err == nil) != tc.ok {
			t.Errorf("%s: %v; want accepted=%v", tc.what, err, tc.ok)
		}
	}
}

// TestKinds is each kind's rule: what it accepts, what it refuses, and the message.
func TestKinds(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	b := &Bool{Meta{Name: "B"}}
	for v, want := range map[string]bool{"": false, "0": false, "false": false, " FALSE ": false, "1": true, "true": true, " True ": true} {
		if got, err := b.Get(env(v)); err != nil || got != want {
			t.Errorf("Bool %q = %v, %v; want %v", v, got, err, want)
		}
	}
	for _, v := range []string{"yes", "on", "2", "t", "1.0"} {
		if _, err := b.Get(env(v)); err == nil || err.Error() != "B must be one of 0, 1, false, or true" {
			t.Errorf("Bool %q = %v, want refused", v, err)
		}
	}
	c := &Count{Meta{Name: "C"}}
	for v, want := range map[string]int{"": 0, " ": 0, "0": 0, " 7 ": 7} {
		if got, err := c.Get(env(v)); err != nil || got != want {
			t.Errorf("Count %q = %v, %v; want %v", v, got, err, want)
		}
	}
	for _, v := range []string{"-1", "1.5", "x"} {
		if _, err := c.Get(env(v)); err == nil || !strings.Contains(err.Error(), "must be a non-negative integer") {
			t.Errorf("Count %q = %v, want refused", v, err)
		}
	}
	a := &Amount{Meta{Name: "A"}}
	for v, want := range map[string]float64{"": 0, "0.5": 0.5, " 2 ": 2} {
		if got, err := a.Get(env(v)); err != nil || got != want {
			t.Errorf("Amount %q = %v, %v; want %v", v, got, err, want)
		}
	}
	for _, v := range []string{"-0.5", "NaN", "Inf", "x"} {
		if _, err := a.Get(env(v)); err == nil || !strings.Contains(err.Error(), "must be a finite non-negative number") {
			t.Errorf("Amount %q = %v, want refused", v, err)
		}
	}
	i := &Int{Meta{Name: "I", Default: "8"}}
	for v, want := range map[string]int{"": 8, " ": 8, "-3": -3, " 4 ": 4} {
		if got, err := i.Get(env(v)); err != nil || got != want {
			t.Errorf("Int %q = %v, %v; want %v", v, got, err, want)
		}
	}
	if got, _ := i.GetOr(env(""), 5); got != 5 {
		t.Errorf("Int GetOr unset = %v, want the default given", got)
	}
	if _, err := i.Get(env("1.5")); err == nil || err.Error() != `I="1.5" must be an integer` {
		t.Errorf("Int 1.5 = %v", err)
	}
	d := &Duration{Meta{Name: "D", Default: "5m"}}
	if got, err := d.Get(env("")); err != nil || got != 5*time.Minute {
		t.Errorf("Duration unset = %v, %v", got, err)
	}
	if _, err := d.Get(env("5")); err == nil || !strings.Contains(err.Error(), "must be a duration") {
		t.Errorf("Duration 5 = %v, want refused", err)
	}
	tx := &Text{Meta{Name: "T", Default: "def"}}
	tr := &Trimmed{Meta{Name: "R", Default: "def"}}
	lo := &Lower{Meta{Name: "L"}}
	for v, want := range map[string][3]string{"": {"def", "def", ""}, " ": {" ", "def", ""}, " A ": {" A ", "A", "a"}} {
		if got := [3]string{tx.Get(env(v)), tr.Get(env(v)), lo.Get(env(v))}; got != want {
			t.Errorf("Text, Trimmed, Lower %q = %q, want %q", v, got, want)
		}
	}
	for v, want := range map[string][2]bool{"": {false, false}, "0": {true, false}, " 3 ": {true, true}, "x": {true, false}} {
		if set, pos := c.Positive(env(v)); [2]bool{set, pos} != want {
			t.Errorf("Count.Positive %q = %v, %v; want %v", v, set, pos, want)
		}
	}
}
