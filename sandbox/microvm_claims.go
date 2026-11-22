package sandbox

import (
	"maps"

	"github.com/plimsollmark/plimsoll/internal/boundary"
)

// hostedMicroVMClaims is the declaration of a provider whose wall is a hosted microVM (e2b,
// dockercloud): the answers the two give alike are written here once, so they cannot drift
// apart, and own adds the provider's other answers. A claim in own that is also answered
// here is a programming error.
func hostedMicroVMClaims(provider, source, startup string, own map[boundary.Claim]boundary.Entry) *boundary.Declaration {
	entries := map[boundary.Claim]boundary.Entry{
		boundary.WritablePlaces: {Not: "the wall is the microVM itself, not a read-only filesystem inside it."},
		boundary.GuestUser:      {Not: "the wall is the microVM, and the test does not read which user a step runs as inside it."},
		boundary.NoCapabilities: {Not: "the wall is the microVM, and the test reads nothing of the kernel's inside it."},
		boundary.SeccompFilter:  {Not: "the wall is the microVM, and the test reads nothing of the kernel's inside it."},
		boundary.GuestGuard:     {Not: "not applied: the wall is the virtual machine, no `noexec` mark is stated to protect, and the service's own process interface starts each command, not a command line of plimsoll's."},
		boundary.FixedResolver:  {Not: "the deny-all policy holds the network shut, and the request by name above must fail."},
		boundary.NoHostShare:    {Not: "the wall is the microVM, which shares no folder or device of plimsolld's host."},
		boundary.Languages: {Steps: []string{"SmokeTest"},
			How: "JavaScript is stated because node ran the test program; each other language only when its interpreter answers a probe."},
	}
	for c := range own {
		if _, shared := entries[c]; shared {
			panic("sandbox: " + provider + " answers " + string(c) + ", which hostedMicroVMClaims answers for it")
		}
	}
	maps.Copy(entries, own)
	return boundary.Declare(boundary.Declaration{Provider: provider, Source: source, Startup: startup, Entries: entries})
}
