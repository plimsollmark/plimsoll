package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// daemonProvider is a provider plimsolld constructs itself instead of through
// sandbox.Build: one whose dependencies must not reach every program that imports
// package sandbox, such as generated protocol code that registers protobuf names
// another SDK also registers (protobuf-go panics at start on a duplicate). Each
// registers from its own file, so that file's presence decides whether a build has
// the provider.
type daemonProvider struct {
	// build constructs the provider from the environment.
	build func(getenv func(string) string) (sandbox.Provider, error)
	// usage is the provider's section of -h; it names every variable build reads.
	usage string
	// hardenedEnvelope is the resource envelope hardened mode requires for the
	// provider: every dimension it enforces and none its configuration rejects.
	hardenedEnvelope []string
	// pinnedImages makes hardened mode require SANDBOX_REQUIRE_PINNED_IMAGES=1.
	pinnedImages bool
}

// daemonProviders maps a SANDBOX_PROVIDER value to its daemon-built provider.
var daemonProviders = map[string]daemonProvider{}

func daemonProviderNames() []string {
	names := make([]string, 0, len(daemonProviders))
	for name := range daemonProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// buildProvider constructs the provider SANDBOX_PROVIDER names: a daemon-built one
// through its own constructor, any other through sandbox.Build. A name neither knows
// is refused here, naming every provider this build has, since Build's own refusal
// would list only its own.
func buildProvider(getenv func(string) string) (sandbox.Provider, error) {
	raw := getenv("SANDBOX_PROVIDER")
	name := strings.ToLower(strings.TrimSpace(raw))
	if dp, ok := daemonProviders[name]; ok {
		return dp.build(getenv)
	}
	if name != "" && !slices.Contains(sandbox.ProviderNames(), name) {
		return sandbox.Provider{}, fmt.Errorf("SANDBOX_PROVIDER=%q is not recognized (known: %s; unset = disabled)",
			raw, strings.Join(append(sandbox.ProviderNames(), daemonProviderNames()...), ", "))
	}
	return sandbox.Build(getenv)
}

// helpText is what -h prints: the fixed usage text around the two parts that depend on
// the build, the SANDBOX_PROVIDER line naming every provider it has and the sections
// of the daemon-built ones.
func helpText() string {
	var b strings.Builder
	b.WriteString(usageHead)
	fmt.Fprintf(&b, "  SANDBOX_PROVIDER           %s | (unset = disabled)\n",
		strings.Join(append(sandbox.ProviderNames(), daemonProviderNames()...), " | "))
	b.WriteString(usageProviders)
	b.WriteString("  DOCKER_DEFAULT_PLATFORM      Docker platform selected for image inspection and runs (for example linux/amd64)\n")
	for _, name := range daemonProviderNames() {
		b.WriteString(daemonProviders[name].usage)
	}
	b.WriteString(usageLimits)
	return b.String()
}
