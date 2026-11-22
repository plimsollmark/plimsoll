package main

import (
	"testing"

	"github.com/plimsollmark/plimsoll/internal/boundary"
)

// TestEveryProviderDeclaresItsBoundaryClaims fails a provider this build can select that
// has no boundary declaration (internal/boundary): each must say, for every claim, how its
// smoke test proves it or why it does not, before plimsolld can serve it. boundary.Declare
// already refuses a declaration that leaves a claim out; this refuses a provider with
// none at all, which a new provider added to providers would otherwise be.
func TestEveryProviderDeclaresItsBoundaryClaims(t *testing.T) {
	if len(providers) == 0 {
		t.Fatal("no providers")
	}
	for name := range providers {
		if boundary.For(name) == nil {
			t.Errorf("SANDBOX_PROVIDER=%s has no boundary declaration: declare it beside its smoke test (boundary.Declare)", name)
		}
	}
}
