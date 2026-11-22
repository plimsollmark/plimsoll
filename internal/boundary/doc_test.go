package boundary_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/boundary"
	"github.com/plimsollmark/plimsoll/internal/boundary/boundarytest"
	_ "github.com/plimsollmark/plimsoll/sandbox"              // declares wasm, docker, e2b and dockercloud
	_ "github.com/plimsollmark/plimsoll/sandbox/agentsandbox" // declares agentsandbox
	_ "github.com/plimsollmark/plimsoll/sandbox/openshell"    // declares openshell
	_ "github.com/plimsollmark/plimsoll/sandbox/wslc"         // declares wslc
)

var update = flag.Bool("update", false, "rewrite the generated section of docs/isolation-tiers.md from the declarations")

// docProviders are the providers the page compares, in its order.
var docProviders = []string{"wasm", "docker", "e2b", "dockercloud", "openshell", "agentsandbox", "wslc"}

const (
	tierPage = "../../docs/isolation-tiers.md"
	begin    = "<!-- Generated from each provider's boundary declaration by `go test ./internal/boundary -run TestTierPageIsGenerated -update`: change a declaration, not this section. -->"
	end      = "<!-- End of the generated section. -->"
)

// TestTierPageIsGenerated holds the comparison in docs/isolation-tiers.md to the
// declarations the smoke tests are checked against, so the page cannot say a provider
// proves what its smoke test does not, or miss what it does.
func TestTierPageIsGenerated(t *testing.T) {
	if got := boundary.Providers(); !slices.Equal(got, sortedCopy(docProviders)) {
		t.Fatalf("declared providers %v, but the page compares %v: add the provider to docProviders", got, docProviders)
	}
	raw, err := os.ReadFile(tierPage)
	if err != nil {
		t.Fatal(err)
	}
	pageText := string(raw)
	i, j := strings.Index(pageText, begin), strings.Index(pageText, end)
	if i < 0 || j < i {
		t.Fatalf("%s has no generated section (the lines %q and %q)", tierPage, begin, end)
	}
	want := pageText[:i] + begin + "\n" + render() + end + pageText[j+len(end):]
	if want == pageText {
		return
	}
	if *update {
		if err := os.WriteFile(tierPage, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("%s's generated section is not what the declarations say: run go test ./internal/boundary -run TestTierPageIsGenerated -update", tierPage)
}

// TestSmokeCodeRecordsWhatItsDeclarationSays holds each provider's smoke code to its
// declaration without running it (boundarytest), so a provider whose smoke test needs a
// live service is held as firmly as docker: every record names the function it is
// written in, and every declared step records its claim.
func TestSmokeCodeRecordsWhatItsDeclarationSays(t *testing.T) {
	for _, p := range docProviders {
		d := boundary.For(p)
		problems, err := boundarytest.Problems(d, filepath.Join("..", ".."))
		if err != nil {
			t.Fatal(err)
		}
		for _, problem := range problems {
			t.Errorf("%s: %s", p, problem)
		}
	}
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

// render is the generated section: a table per group of claims, then each provider's
// answers in full.
func render() string {
	var b strings.Builder
	decls := make([]*boundary.Declaration, len(docProviders))
	for i, p := range docProviders {
		decls[i] = boundary.For(p)
	}
	b.WriteString("\nEach provider declares, for every claim below, the steps of its startup test that prove it, or why its test does not check it ")
	b.WriteString("([internal/boundary](../internal/boundary/boundary.go) holds the list of claims). The test records each claim as its check passes, ")
	b.WriteString("and the provider serves nothing when the record differs from the declaration, so this comparison says what the code proves, no more and no less. ")
	b.WriteString("\"Not checked\" says nothing about whether the property holds, only that the startup test does not check it; each provider's list below says why.\n")
	for _, g := range []struct {
		group boundary.Group
		title string
	}{{boundary.Wall, "The wall around a run"}, {boundary.Path, "The path every run takes"}} {
		fmt.Fprintf(&b, "\n**%s**\n\n| Claim |", g.title)
		for _, p := range docProviders {
			fmt.Fprintf(&b, " `%s` |", p)
		}
		b.WriteString("\n|---|" + strings.Repeat("---|", len(docProviders)) + "\n")
		for _, info := range boundary.Claims() {
			if info.Group != g.group {
				continue
			}
			fmt.Fprintf(&b, "| %s (`%s`) |", info.Says, info.Claim)
			for _, d := range decls {
				e := d.Entries[info.Claim]
				switch {
				case e.Checked() && e.When != "":
					fmt.Fprintf(&b, " proved, %s |", e.When)
				case e.Checked():
					b.WriteString(" proved |")
				default:
					b.WriteString(" not checked |")
				}
			}
			b.WriteString("\n")
		}
	}
	for _, d := range decls {
		fmt.Fprintf(&b, "\n**`%s`**, [%s](../%s). %s\n\n", d.Provider, d.Source[strings.LastIndex(d.Source, "/")+1:], d.Source, d.Startup)
		for _, info := range boundary.Claims() {
			e := d.Entries[info.Claim]
			if e.Checked() {
				when := ""
				if e.When != "" {
					when = " Only " + e.When + "."
				}
				fmt.Fprintf(&b, "- `%s`, proved: %s%s (%s)\n", info.Claim, e.How, when, steps(e.Steps))
			} else {
				fmt.Fprintf(&b, "- `%s`, not checked: %s\n", info.Claim, e.Not)
			}
		}
	}
	b.WriteString("\n")
	return b.String()
}

func steps(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = "`" + n + "`"
	}
	return strings.Join(quoted, ", ")
}
