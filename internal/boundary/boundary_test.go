package boundary

import (
	"strings"
	"testing"
)

// complete is a declaration answering every claim: all not checked, except Proven,
// checked by step "probe", and Conditional, checked by "probe" under a condition.
func complete(proven, conditional Claim) Declaration {
	d := Declaration{Provider: "test", Source: "x.go", Startup: "A test.", Entries: map[Claim]Entry{}}
	for _, info := range claims {
		d.Entries[info.Claim] = Entry{Not: "not in this test"}
	}
	d.Entries[proven] = Entry{Steps: []string{"probe"}, How: "tries it"}
	d.Entries[conditional] = Entry{Steps: []string{"probe"}, How: "tries it", When: "when set"}
	return d
}

// TestDeclarationMustAnswerEveryClaim is the conformance rule: a declaration that leaves
// a claim of the closed list unanswered, or answers it both ways or neither, or answers
// one outside the list, is refused.
func TestDeclarationMustAnswerEveryClaim(t *testing.T) {
	if err := complete(NoEgress, MemoryLimit).validate(); err != nil {
		t.Fatalf("a complete declaration was refused: %v", err)
	}
	cases := map[string]func(*Declaration){
		"a claim left out":      func(d *Declaration) { delete(d.Entries, LoopbackOnly) },
		"both ways":             func(d *Declaration) { d.Entries[NoEgress] = Entry{Steps: []string{"probe"}, How: "x", Not: "y"} },
		"neither way":           func(d *Declaration) { d.Entries[NoEgress] = Entry{} },
		"checked without how":   func(d *Declaration) { d.Entries[NoEgress] = Entry{Steps: []string{"probe"}} },
		"not checked with how":  func(d *Declaration) { d.Entries[CPULimit] = Entry{Not: "x", How: "y"} },
		"an empty step":         func(d *Declaration) { d.Entries[NoEgress] = Entry{Steps: []string{""}, How: "x"} },
		"a claim outside":       func(d *Declaration) { d.Entries["made-up"] = Entry{Not: "x"} },
		"no provider":           func(d *Declaration) { d.Provider = "" },
		"no source or sentence": func(d *Declaration) { d.Startup = "" },
		"not checked with when": func(d *Declaration) { d.Entries[CPULimit] = Entry{Not: "x", When: "y"} },
	}
	for name, mutate := range cases {
		d := complete(NoEgress, MemoryLimit)
		d.Entries = cloneEntries(d.Entries)
		mutate(&d)
		if err := d.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func cloneEntries(m map[Claim]Entry) map[Claim]Entry {
	out := make(map[Claim]Entry, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// TestProofMustMatchTheDeclaration holds Done to the declaration both ways: a declared
// claim not proved fails, a claim proved that is declared not checked fails, a step the
// declaration does not name fails, and only a conditional claim may be skipped.
func TestProofMustMatchTheDeclaration(t *testing.T) {
	d := complete(NoEgress, MemoryLimit)
	decl := &d
	run := func(f func(p *Proof)) error {
		p := decl.Start()
		f(p)
		return p.Done()
	}
	if err := run(func(p *Proof) { p.Proved(NoEgress, "probe"); p.Proved(MemoryLimit, "probe") }); err != nil {
		t.Fatalf("a matching record failed: %v", err)
	}
	if err := run(func(p *Proof) { p.Proved(NoEgress, "probe"); p.Skipped(MemoryLimit) }); err != nil {
		t.Fatalf("a conditional claim skipped failed: %v", err)
	}
	if err := run(func(p *Proof) { _ = p.Check(NoEgress, "probe", nil); p.Skipped(MemoryLimit) }); err != nil {
		t.Fatalf("Check with no error did not prove: %v", err)
	}
	for name, f := range map[string]func(p *Proof){
		"a checked claim not proved":  func(p *Proof) { p.Skipped(MemoryLimit) },
		"an unconditional skip":       func(p *Proof) { p.Skipped(NoEgress); p.Skipped(MemoryLimit) },
		"a claim not checked proved":  func(p *Proof) { p.Proved(NoEgress, "probe"); p.Skipped(MemoryLimit); p.Proved(CPULimit, "probe") },
		"an undeclared step":          func(p *Proof) { p.Proved(NoEgress, "elsewhere"); p.Skipped(MemoryLimit) },
		"a failed check":              func(p *Proof) { _ = p.Check(NoEgress, "probe", errTest); p.Skipped(MemoryLimit) },
		"a claim outside the list":    func(p *Proof) { p.Proved(NoEgress, "probe"); p.Skipped(MemoryLimit); p.Proved("made-up", "probe") },
		"a conditional claim neither": func(p *Proof) { p.Proved(NoEgress, "probe") },
	} {
		err := run(f)
		if err == nil {
			t.Errorf("%s: Done passed", name)
		} else if !strings.Contains(err.Error(), "test smoke test: what it proved differs from its boundary declaration") {
			t.Errorf("%s: Done's error %q does not say what differs from what", name, err)
		}
	}
}

var errTest = testError("refused")

type testError string

func (e testError) Error() string { return string(e) }

// TestDeclareRefusesADuplicate keeps one declaration per provider.
func TestDeclareRefusesADuplicate(t *testing.T) {
	d := complete(NoEgress, MemoryLimit)
	d.Provider = "test-duplicate"
	Declare(d)
	defer func() {
		registryMu.Lock()
		delete(registry, "test-duplicate")
		registryMu.Unlock()
	}()
	defer func() {
		if recover() == nil {
			t.Fatal("a second declaration of the same provider was accepted")
		}
	}()
	Declare(d)
}

// TestClaimsAreUnique keeps the closed list free of a claim listed twice.
func TestClaimsAreUnique(t *testing.T) {
	seen := map[Claim]bool{}
	for _, info := range claims {
		if seen[info.Claim] || info.Says == "" || (info.Group != Wall && info.Group != Path) {
			t.Errorf("%s: listed twice, or without what it says or its group", info.Claim)
		}
		seen[info.Claim] = true
	}
}
