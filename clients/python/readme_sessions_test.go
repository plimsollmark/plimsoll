package python

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sessionProviderNames gives, for each provider docs/sessions.md lists, the name a
// package README uses for it in prose. A provider missing here fails the test, so a
// new row in that table gets its prose name the day it is added.
var sessionProviderNames = map[string]string{
	"openshell":   "OpenShell",
	"docker":      "docker",
	"e2b":         "E2B",
	"dockercloud": "Docker Cloud",
	"wasm":        "wasm",
	"wslc":        "WSL",
}

// TestPackageReadmesNameOnlyProvidersWithSessions checks every package README's
// sentence "needs a provider with sessions: ..." against the table in docs/sessions.md:
// it may name only providers the table marks Yes. The langchain-plimsoll README named
// Docker Cloud, which the table marks "Not yet", so a reader who picked it would have
// met a daemon that refuses sessions.
func TestPackageReadmesNameOnlyProvidersWithSessions(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "sessions.md"))
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| `([a-z]+)` \\| (Yes|No|Not yet)\\b")
	var without []string
	yes := 0
	for _, m := range row.FindAllStringSubmatch(string(doc), -1) {
		name, ok := sessionProviderNames[m[1]]
		if !ok {
			t.Fatalf("docs/sessions.md lists provider %q, which has no prose name in sessionProviderNames", m[1])
		}
		if m[2] == "Yes" {
			yes++
		} else {
			without = append(without, name)
		}
	}
	if yes == 0 || len(without) == 0 {
		t.Fatalf("read %d providers with sessions and %d without from docs/sessions.md; the table's shape changed", yes, len(without))
	}

	readmes, err := filepath.Glob(filepath.Join("*", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	sentence := regexp.MustCompile(`needs a provider with sessions:[^.]*`)
	checked := 0
	for _, path := range readmes {
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range sentence.FindAllString(strings.ReplaceAll(string(text), "\n", " "), -1) {
			checked++
			for _, name := range without {
				if strings.Contains(s, name) {
					t.Errorf("%s says %q, but docs/sessions.md does not mark %s as offering sessions", path, s, name)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no package README states which providers have sessions; the sentence this test reads is gone")
	}
}
