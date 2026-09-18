package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestParseArgsAcceptsOnlyHelp(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}} {
		help, err := parseArgs(args)
		if err != nil || !help {
			t.Fatalf("parseArgs(%q) = %v, %v; want a help request", args, help, err)
		}
	}
	if help, err := parseArgs(nil); err != nil || help {
		t.Fatalf("parseArgs(nil) = %v, %v; want a normal start", help, err)
	}
	for _, args := range [][]string{{"-x"}, {"-h", "extra"}, {"serve"}, {"--addr=:1"}, {"PLIMSOLL_ADDR=:1"}} {
		if _, err := parseArgs(args); err == nil {
			t.Fatalf("parseArgs(%q) accepted an argument the daemon does not take", args)
		}
	}
}

// TestUsageNamesEveryVariable is the drift guard for -h: every PLIMSOLL_, SANDBOX_
// or E2B_ variable a non-test file in this package reads must be documented in
// usage, so the help text cannot fall behind the code. The provider factory in
// the sandbox package reads the SANDBOX_ and E2B_ variables on the daemon's
// behalf, so its file is scanned too; without it a provider variable added there
// would be undocumented and this test would not notice.
func TestUsageNamesEveryVariable(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			files = append(files, entry.Name())
		}
	}
	files = append(files, "../../sandbox/factory.go")
	name := regexp.MustCompile(`"((?:PLIMSOLL|SANDBOX|E2B)_[A-Z0-9_]+)"`)
	seen := 0
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range name.FindAllStringSubmatch(string(src), -1) {
			seen++
			if !strings.Contains(usage, match[1]) {
				t.Errorf("%s reads %s but usage (-h) does not document it", file, match[1])
			}
		}
	}
	if seen == 0 {
		t.Fatal("found no environment variable reads to check; the guard is broken")
	}
}
