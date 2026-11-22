// Package boundary is the closed list of what a provider's startup smoke test can prove
// about a run, each provider's declaration of which of those its smoke test proves (and
// how, and when) or why it does not, and the record a smoke test keeps of what it proved.
//
// Before this package, each provider's smoke test checked a list of its own, in its own
// program, and nothing said what a smoke test must prove: a new provider decided for
// itself, and a reader could not compare two providers at the same tier (review P8,
// 2026-11-18). Now every provider declares every claim (Declare refuses a declaration
// that leaves one out), its smoke test records each claim as the check behind it passes,
// and the smoke test fails when the record differs from the declaration (Proof.Done), so
// the declaration cannot say more or less than the code does. The comparison in
// docs/isolation-tiers.md is rendered from the same declarations.
//
// A claim is proven by configuration and provider evidence plus the behavioral startup
// test, never by runtime attestation, as every tier is.
package boundary

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Claim names one thing a startup smoke test can prove about a run.
type Claim string

// The claims, in the order the documentation lists them.
const (
	WritablePlaces    Claim = "writable-places"
	WritableBounds    Claim = "writable-bounds"
	LoopbackOnly      Claim = "loopback-only"
	NoEgress          Claim = "no-egress"
	GuestUser         Claim = "guest-user"
	NoCapabilities    Claim = "no-capabilities"
	SeccompFilter     Claim = "seccomp-filter"
	GuestGuard        Claim = "guest-guard"
	ProcessLimit      Claim = "process-limit"
	MemoryLimit       Claim = "memory-limit"
	CPULimit          Claim = "cpu-limit"
	FixedResolver     Claim = "fixed-resolver"
	ClosedEnvironment Claim = "closed-environment"
	ControlChannel    Claim = "control-channel"
	NoHostShare       Claim = "no-host-share"
	TierInside        Claim = "tier-inside"

	SetupReadBack Claim = "setup-read-back"
	RunPath       Claim = "run-path"
	DeadlineKill  Claim = "deadline-kill"
	OutputCap     Claim = "output-cap"
	GrantSocket   Claim = "grant-socket"
	Languages     Claim = "languages"
	Teardown      Claim = "teardown"
)

// Group says whether a claim is about the wall around a run or about the path every run
// takes through the provider.
type Group string

const (
	// Wall claims are about what the code inside can and cannot do.
	Wall Group = "wall"
	// Path claims are about the path every run takes, which a wall is worth nothing without.
	Path Group = "path"
)

// Info is one claim and what it says, in plain words.
type Info struct {
	Claim Claim
	Group Group
	Says  string
}

// claims is the closed list. A new claim here makes every Declare call that does not
// answer it panic, so every provider must say, for the new claim, how its smoke test
// proves it or why it does not.
var claims = []Info{
	{WritablePlaces, Wall, "Only the promised places accept a write; the root filesystem refuses one"},
	{WritableBounds, Wall, "Each place that accepts a write is held to a size bound"},
	{LoopbackOnly, Wall, "The code sees no network interface but loopback"},
	{NoEgress, Wall, "No connection the code tries to an outside address succeeds"},
	{GuestUser, Wall, "The <dfn>*guest*</dfn>, the code running inside the sandbox, runs as an unprivileged user of its own, with no other user or group"},
	{NoCapabilities, Wall, "The code holds no Linux capability (a power the kernel gives a process beyond its user's)"},
	{SeccompFilter, Wall, "A <dfn>*seccomp*</dfn> filter (the kernel's filter on which requests a process may make) is in force on the code"},
	{GuestGuard, Wall, "Every program plimsoll starts in the sandbox starts behind plimsoll's <dfn>*guest guard*</dfn>, a seccomp filter of plimsoll's own that refuses the code the requests that make a <dfn>*namespace*</dfn> (a private view of the system in which the code acts as administrator) or a mount of its own, and tracing"},
	{ProcessLimit, Wall, "The configured limit on the number of processes is applied"},
	{MemoryLimit, Wall, "The configured memory limit is applied"},
	{CPULimit, Wall, "The configured CPU limit is applied"},
	{FixedResolver, Wall, "The code's resolver settings (which name server it asks) are plimsoll's own, with nothing of the host's"},
	{ClosedEnvironment, Wall, "No environment variable reaches the code from outside its image and plimsoll's own runner"},
	{ControlChannel, Wall, "The code cannot open plimsoll's own channel to the run: the runner's plan, its report and its memory, and any agent of the provider's beside it"},
	{NoHostShare, Wall, "No device or folder of the host machine reaches the code"},
	{TierInside, Wall, "From inside, the code sees the kernel the stated tier rests on"},

	{SetupReadBack, Path, "Before code runs, what the service set up for it (image, policy, limits, runtime) is read back and must be what was asked"},
	{RunPath, Path, "Code runs end to end through the path a run takes: files in, steps run, output and files back"},
	{DeadlineKill, Path, "A command past its time limit is ended, with every process it started"},
	{OutputCap, Path, "Output past the cap is cut off, and the cut is reported"},
	{GrantSocket, Path, "A host socket handed to a run for its <dfn>*grant*</dfn> (its permission to call listed routes of one HTTP API) is reachable from inside it"},
	{Languages, Path, "The languages stated for runs are the ones that answered at startup"},
	{Teardown, Path, "A run's sandbox is gone after the run"},
}

// Claims is the closed list, in documentation order.
func Claims() []Info { return slices.Clone(claims) }

// Entry is one provider's answer for one claim: the steps of its smoke test that prove
// it, how, and when they run; or why its smoke test does not check it. Exactly one of
// Steps and Not is set.
type Entry struct {
	// Steps are the functions of the provider's smoke code that prove the claim, by
	// name, so a reader can find them. Proof.Proved must name one of them.
	Steps []string
	// How is what the steps do, in plain words.
	How string
	// When is the condition the steps run under, in plain words ("under the container
	// tier"); empty when they always run. When it does not hold, the smoke test records
	// the claim as skipped (Proof.Skipped), which only a claim with a condition may be.
	When string
	// Not is why the provider's smoke test does not check the claim.
	Not string
}

// Checked reports whether a smoke step proves the claim.
func (e Entry) Checked() bool { return len(e.Steps) > 0 }

// Declaration is one provider's answer for every claim.
type Declaration struct {
	// Provider is the SANDBOX_PROVIDER value.
	Provider string
	// Source is the file of the provider's smoke test, from the module root.
	Source string
	// Startup is one sentence on what the provider's startup check is, printed above
	// its entries.
	Startup string
	// Entries answers every claim in the closed list, and only those.
	Entries map[Claim]Entry
}

var (
	registryMu sync.Mutex
	registry   = map[string]*Declaration{}
)

// Declare checks d and records it as the provider's declaration. A declaration that
// leaves a claim unanswered, answers one outside the list, answers one both ways or
// neither, gives no reason or names a provider twice is a programming error, so Declare
// panics: a provider package's variable initialization calls it, and every test of that
// package then fails.
func Declare(d Declaration) *Declaration {
	if err := d.validate(); err != nil {
		panic(err)
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[d.Provider]; dup {
		panic(fmt.Sprintf("boundary: %s is declared twice", d.Provider))
	}
	stored := d
	stored.Entries = make(map[Claim]Entry, len(d.Entries))
	for c, e := range d.Entries {
		e.Steps = slices.Clone(e.Steps)
		stored.Entries[c] = e
	}
	registry[d.Provider] = &stored
	return &stored
}

// For is the named provider's declaration, nil when none was declared.
func For(provider string) *Declaration {
	registryMu.Lock()
	defer registryMu.Unlock()
	return registry[provider]
}

// Providers are the providers declared in this program, sorted.
func Providers() []string {
	registryMu.Lock()
	defer registryMu.Unlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// validate is Declare's check, without the registry.
func (d Declaration) validate() error {
	var errs []error
	if d.Provider == "" {
		errs = append(errs, errors.New("names no provider"))
	}
	if d.Source == "" || d.Startup == "" {
		errs = append(errs, errors.New("names no smoke test source or startup sentence"))
	}
	known := map[Claim]bool{}
	for _, info := range claims {
		known[info.Claim] = true
		e, ok := d.Entries[info.Claim]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s: not declared: say which smoke steps prove it, or why the smoke test does not check it", info.Claim))
		case e.Checked() && e.Not != "":
			errs = append(errs, fmt.Errorf("%s: declared both checked and not checked", info.Claim))
		case !e.Checked() && e.Not == "":
			errs = append(errs, fmt.Errorf("%s: declared neither checked nor not checked", info.Claim))
		case e.Checked() && e.How == "":
			errs = append(errs, fmt.Errorf("%s: checked, but says not how", info.Claim))
		case !e.Checked() && (e.How != "" || e.When != ""):
			errs = append(errs, fmt.Errorf("%s: not checked, but says how or when", info.Claim))
		case slices.Contains(e.Steps, ""):
			errs = append(errs, fmt.Errorf("%s: names an empty step", info.Claim))
		}
	}
	for c := range d.Entries {
		if !known[c] {
			errs = append(errs, fmt.Errorf("%s: not a claim of the closed list", c))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("boundary: the declaration of %q: %w", d.Provider, err)
	}
	return nil
}

// Proof is what one run of a provider's smoke test proved, checked against its
// declaration when the test ends.
type Proof struct {
	decl    *Declaration
	mu      sync.Mutex
	proved  map[Claim]bool
	skipped map[Claim]bool
	errs    []error
}

// Start begins the record of one smoke test run.
func (d *Declaration) Start() *Proof {
	return &Proof{decl: d, proved: map[Claim]bool{}, skipped: map[Claim]bool{}}
}

// Proved records that step's check of c passed. A step the declaration does not name
// for c is recorded as an error Done returns.
func (p *Proof) Proved(c Claim, step string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.decl.Entries[c]
	switch {
	case !ok:
		p.errs = append(p.errs, fmt.Errorf("proved %s, which is not a claim of the closed list", c))
	case !e.Checked():
		p.errs = append(p.errs, fmt.Errorf("proved %s, which its declaration says the smoke test does not check", c))
	case !slices.Contains(e.Steps, step):
		p.errs = append(p.errs, fmt.Errorf("proved %s in step %s, which its declaration does not name (it names %s)", c, step, strings.Join(e.Steps, ", ")))
	default:
		p.proved[c] = true
	}
}

// Skipped records that the condition of c's steps (Entry.When) does not hold in this
// configuration, so its check did not run. A claim declared without a condition may not
// be skipped.
func (p *Proof) Skipped(c Claim) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.decl.Entries[c]; !ok || !e.Checked() || e.When == "" {
		p.errs = append(p.errs, fmt.Errorf("skipped %s, which its declaration does not make conditional", c))
		return
	}
	p.skipped[c] = true
}

// Check records c as proved by step when err is nil, and returns err.
func (p *Proof) Check(c Claim, step string, err error) error {
	if err == nil {
		p.Proved(c, step)
	}
	return err
}

// Done compares the record with the declaration: every claim it declares checked was
// proved (or, under a condition, skipped), and nothing else was. A difference means the
// smoke code and its declaration disagree, so the smoke test fails rather than state
// claims nobody proved.
func (p *Proof) Done() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	errs := slices.Clone(p.errs)
	for _, info := range claims {
		e := p.decl.Entries[info.Claim]
		if e.Checked() && !p.proved[info.Claim] && !p.skipped[info.Claim] {
			if e.When != "" {
				errs = append(errs, fmt.Errorf("%s is declared checked %s, and was neither proved nor skipped", info.Claim, e.When))
			} else {
				errs = append(errs, fmt.Errorf("%s is declared checked by %s, and was not proved", info.Claim, strings.Join(e.Steps, ", ")))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%s smoke test: what it proved differs from its boundary declaration: %w", p.decl.Provider, err)
	}
	return nil
}
