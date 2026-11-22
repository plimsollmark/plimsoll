package outsidefacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// root is the repository's top directory, from this package's.
var root = filepath.Join("..", "..")

func loadTable(t *testing.T) *Table {
	t.Helper()
	table, err := Load(".")
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// TestEverySiteHasARow fails for product code of a scanned shape that no row answers: a test
// for words in an error's text or in a program's output, an exit code compared with a number,
// a version taken apart, a provider named outside the tables that list providers, an operating
// system or machine named by a literal. The message
// is the row to add.
func TestEverySiteHasARow(t *testing.T) {
	table := loadTable(t)
	sites, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) == 0 {
		t.Fatal("the scan found no site at all; it is broken")
	}
	told := map[string]bool{}
	for _, s := range sites {
		if table.Covers(s) || told[s.Key()] {
			continue
		}
		told[s.Key()] = true
		t.Errorf("%s:%d: %s in %s rests on a fact plimsoll does not own (%s) and no row of internal/outsidefacts/facts.json says which.\n"+
			"Add this row there, filled in (rules: internal/outsidefacts/rules.md):\n%s",
			s.File, s.Line, s.Text, s.Symbol, s.Shape, Skeleton(s))
	}
}

// TestEveryFixedWaitSaysWhy fails for a test that sleeps a fixed time, or reads a timer nothing
// fails on, outside any loop and with no reason beside it. Such a wait stands for "the other
// thing has happened by now", which is true until the machine is slow. The answer is a comment
// with the reason, or a row for a file whose comment cannot be added.
func TestEveryFixedWaitSaysWhy(t *testing.T) {
	table := loadTable(t)
	waits, err := ScanTests(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range waits {
		if table.Covers(s) {
			continue
		}
		t.Errorf("%s:%d: %s in %s is a fixed wait with no reason. If the test waits for something to have happened, wait for the thing itself "+
			"(a channel, a poll with a limit). If the wait is right, say why on the line above it:\n    // %s <why a fixed wait is safe here>",
			s.File, s.Line, s.Text, s.Symbol, WaitMarker)
	}
}

// TestRowsAreWellFormedAndCurrent fails for a row with a field missing or misspelled, and for a
// row that names a file, a symbol or a test that is no longer there: a table that keeps rows for
// code that moved says nothing about the code that replaced it.
func TestRowsAreWellFormedAndCurrent(t *testing.T) {
	table := loadTable(t)
	for _, err := range table.Validate() {
		t.Error(err)
	}
	if len(table.Rows) == 0 {
		t.Fatal("the table has no rows")
	}
	for _, err := range table.Current(root) {
		t.Error(err)
	}
}

// TestNoRowAnswersNothing fails for a row that claims to answer a scanned shape at a place
// where the scan finds none: the code changed and the row stayed. Rows with no shapes (the
// places the scan cannot see) are checked by TestRowsAreWellFormedAndCurrent alone.
func TestNoRowAnswersNothing(t *testing.T) {
	table := loadTable(t)
	sites, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	waits, err := ScanTests(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range table.Unanswering(append(sites, waits...)) {
		t.Error(err)
	}
}

// The check is shown failing: one planted example of each shape, none of which a row answers,
// and beside each the same code in a form the rule leaves alone.
func TestTheScanFindsEachPlantedShape(t *testing.T) {
	const planted = `package planted

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var toolSays = regexp.MustCompile("fatal: (.*)")

func errorText(err error) bool {
	return strings.Contains(err.Error(), "no such container")
}

func errorTextEqual(err, other error) bool {
	return err.Error() == other.Error()
}

func outputText(stderr string) bool {
	return strings.HasPrefix(stderr, "Error response from daemon")
}

func outputPattern(cmd *exec.Cmd, stdout string) []string {
	return toolSays.FindStringSubmatch(stdout)
}

func exitCode(res struct{ ExitCode int }) bool {
	return res.ExitCode == 127
}

func exitSwitch(exitCode int) string {
	switch exitCode {
	case 125:
		return "the tool itself failed"
	}
	return ""
}

func parseToolVersion(s string) int {
	major, _ := strconv.Atoi(strings.Split(s, ".")[0])
	return major
}

func versionWords(serverVersion string) bool {
	return strings.HasPrefix(serverVersion, "v2.")
}

func providerName(name string) bool {
	return name == "docker"
}

func providerSwitch(name string) int {
	switch name {
	case "e2b", "dockercloud":
		return 1
	}
	return 0
}

func platformCase() bool {
	return runtime.GOOS == "windows"
}

func platformSwitch() int {
	switch runtime.GOARCH {
	case "arm64":
		return 1
	}
	return 0
}

// What the rules leave alone.
func quiet(err error, res struct{ ExitCode int }, stdout, path string) error {
	if errors.Is(err, exec.ErrNotFound) || res.ExitCode != 0 || stdout == "" {
		return fmt.Errorf("failed: %w", err)
	}
	if strings.HasPrefix(path, "/") || len(strings.Split(stdout, "\n")) > 3 {
		return nil
	}
	return nil
}
`
	sites, err := ScanSource("sandbox/planted.go", []byte(planted))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range sites {
		got[s.Symbol] += s.Shape + " "
	}
	want := map[string]string{
		"errorText":        ShapeErrorText + " ",
		"errorTextEqual":   ShapeErrorText + " ",
		"outputText":       ShapeOutputText + " ",
		"outputPattern":    ShapeOutputText + " ",
		"exitCode":         ShapeExitCode + " ",
		"exitSwitch":       ShapeExitCode + " ",
		"parseToolVersion": ShapeVersionParse + " ",
		"versionWords":     ShapeVersionParse + " ",
		"providerName":     ShapeProviderName + " ",
		"providerSwitch":   ShapeProviderName + " " + ShapeProviderName + " ",
		"platformCase":     ShapePlatformCase + " ",
		"platformSwitch":   ShapePlatformCase + " ",
	}
	for sym, shapes := range want {
		if got[sym] != shapes {
			t.Errorf("planted %s: the scan found %q, want %q", sym, got[sym], shapes)
		}
	}
	for sym, shapes := range got {
		if _, ok := want[sym]; !ok {
			t.Errorf("the scan found %q in %s, which the rules leave alone", shapes, sym)
		}
	}
	// Each planted site fails the check: the table answers none of them.
	table := loadTable(t)
	for _, s := range sites {
		if table.Covers(s) {
			t.Errorf("a row answers the planted %s in %s; the planted file is not real", s.Shape, s.Symbol)
		}
	}
	// And a provider's name in a file that lists providers is the table, not a special case.
	for file := range ProviderTables {
		listed, err := ScanSource(file, []byte("package p\nfunc f(name string) bool { return name == \"docker\" }\n"))
		if err != nil || len(listed) != 0 {
			t.Errorf("%s lists providers, and the scan found %v in it (%v)", file, listed, err)
		}
	}
}

func TestTheScanFindsEachPlantedWait(t *testing.T) {
	const planted = `package planted

import (
	"testing"
	"time"
)

func TestSleepsAndHopes(t *testing.T) {
	go work()
	time.Sleep(200 * time.Millisecond)
	check(t)
}

func TestTimerNothingFailsOn(t *testing.T) {
	select {
	case <-done:
		t.Fatal("finished early")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestBareTimer(t *testing.T) {
	<-time.After(time.Second)
}

// What the rule leaves alone.
func TestPollsWithALimit(t *testing.T) {
	deadline := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("never ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("not done in 5 s")
	}
}

func TestSaysWhy(t *testing.T) {
	// fixed-wait: the fake answers after 50 ms by construction; this is the fake's own delay.
	time.Sleep(50 * time.Millisecond)
	time.Sleep(time.Second) // fixed-wait: one tick of the 1 s clock under test
}

func TestMarkerWithNoReason(t *testing.T) {
	// fixed-wait:
	time.Sleep(time.Second)
}
`
	sites, err := ScanTestSource("sandbox/planted_test.go", []byte(planted))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, s := range sites {
		if s.Shape != ShapeFixedWait {
			t.Errorf("%s: shape %s", s.Symbol, s.Shape)
		}
		got[s.Symbol]++
	}
	want := map[string]int{"TestSleepsAndHopes": 1, "TestTimerNothingFailsOn": 1, "TestBareTimer": 1, "TestMarkerWithNoReason": 1}
	for sym, n := range want {
		if got[sym] != n {
			t.Errorf("planted %s: the scan found %d waits, want %d", sym, got[sym], n)
		}
	}
	for sym, n := range got {
		if want[sym] == 0 {
			t.Errorf("the scan found %d waits in %s, which the rule leaves alone", n, sym)
		}
	}
}

// The table's own checks are shown failing: a row with fields missing, a row that fails open
// with no finding, two rows with one id.
func TestValidateRefusesABadRow(t *testing.T) {
	good := Row{ID: "a-row", File: "f.go", Symbol: "F", Kind: "words", Fact: "x", Owner: "o", Version: "1", Read: "read",
		Fails: "closed", Refusal: "refused", RealTest: "none: no such program here", Boundary: "none", Number: "none"}
	if errs := (&Table{Rows: []Row{good}}).Validate(); len(errs) != 0 {
		t.Fatalf("a good row is refused: %v", errs)
	}
	cases := map[string]func(*Row){
		"id must be":           func(r *Row) { r.ID = "A Row" },
		"fact is empty":        func(r *Row) { r.Fact = " " },
		"kind":                 func(r *Row) { r.Kind = "vibes" },
		"fails":                func(r *Row) { r.Fails = "maybe" },
		"shape":                func(r *Row) { r.Shapes = []string{"anything"} },
		"boundary":             func(r *Row) { r.Boundary = "" },
		"number":               func(r *Row) { r.Number = "guessed" },
		"real_test":            func(r *Row) { r.RealTest = "none" },
		"names the finding":    func(r *Row) { r.Fails = "open" },
		"real_test is \"TestX": func(r *Row) { r.RealTest = "TestX" },
	}
	for want, change := range cases {
		r := good
		change(&r)
		errs := (&Table{Rows: []Row{r}}).Validate()
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), want) {
			t.Errorf("want one error holding %q, got %v", want, errs)
		}
	}
	if errs := (&Table{Rows: []Row{good, good}}).Validate(); len(errs) != 1 || !strings.Contains(errs[0].Error(), "used twice") {
		t.Errorf("two rows with one id: %v", errs)
	}
	if errs := (&Table{Rows: []Row{good}, Hosted: map[string]HostedFact{"other": {}}}).Validate(); len(errs) != 1 {
		t.Errorf("a hosted measurement for no row: %v", errs)
	}
}

// Every directory the scan skips is there, and so is every file it treats as a provider table:
// a skip that outlives its directory hides nothing today and anything tomorrow.
func TestSkipsAndTablesExist(t *testing.T) {
	// A copy of the repository without the local file is one that some directories were
	// left out of; there a skipped directory may be absent, and the copy it was made from
	// holds this check in full.
	_, localErr := os.Stat(LocalFile)
	whole := localErr == nil
	for dir := range SkipDirs {
		st, err := os.Stat(filepath.Join(root, filepath.FromSlash(dir)))
		if err == nil && !st.IsDir() || err != nil && whole {
			t.Errorf("SkipDirs names %s, which is not a directory", dir)
		}
	}
	for file := range ProviderTables {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(file))); err != nil {
			t.Errorf("ProviderTables names %s, which is not there", file)
		}
	}
	for _, dir := range ProductRoots {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(dir))); err != nil {
			t.Errorf("ProductRoots names %s, which is not there", dir)
		}
	}
}
