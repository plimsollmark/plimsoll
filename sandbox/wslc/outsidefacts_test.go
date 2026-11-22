package wslc

import (
	"testing"

	"github.com/plimsollmark/plimsoll/internal/outsidefacts"
)

// The stand-in for wslc.exe (internal/fakewslc) is built from the table of outside facts: it
// writes the file the table says WSL writes at boot and prints the words the table says ls
// prints. The provider keeps its own constants for both, since product code does not read a
// table to decide what to refuse. This test is what joins the two: a fact changed in the table
// changes the stand-in at once and fails here until the provider's constant is read against
// the real program again. Without it the provider and its stand-in could each be changed to
// agree with the other while the real WSL said something else.
func TestTheProviderAgreesWithTheFactsItsStandInIsBuiltFrom(t *testing.T) {
	for id, own := range map[string]string{
		"wslc-daemon-json-exact":     msDaemonJSON,
		"wslc-ls-no-such-file-words": lsAbsentWords,
	} {
		if fact := outsidefacts.Value(id); fact != own {
			t.Errorf("the table's row %s says %q and the provider's constant says %q: read the provider against the real program and bring the two together", id, fact, own)
		}
	}
}
