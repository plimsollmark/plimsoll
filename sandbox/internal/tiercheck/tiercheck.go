// Package tiercheck is the one assertion every provider's tests make about the tier a
// result names (release-55). The daemon writes a result's tier into the run's record,
// "unknown" when the result names none, and every official client refuses such a
// record after the code ran: a provider whose result leaves the tier unset turns every
// run on that path into a refused answer. cmd/plimsolld's TestEveryProviderIsHeldToStatingATier
// requires, for every provider the daemon can serve, tests that call Stated on its
// results.
//
// It imports nothing of package sandbox, so that package's own tests can use it.
package tiercheck

import (
	"fmt"
	"testing"
)

// unknown is the name sandbox.IsolationClass gives a tier that is not one of the five.
const unknown = "unknown"

// Stated fails t when got, the tier a result of kind (a snippet, a project, a module, a
// cell) named, is unknown or is not want, the tier the provider (or the session) states.
func Stated(t testing.TB, kind string, got, want fmt.Stringer) {
	t.Helper()
	if got.String() == unknown || got.String() != want.String() {
		t.Errorf("a %s's result names the tier %q; the provider states %q", kind, got, want)
	}
}
