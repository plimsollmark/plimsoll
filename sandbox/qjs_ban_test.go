package sandbox

import (
	"testing"

	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// TestNoBannedQJSDependency fails if this module reintroduces the banned
// github.com/fastschema/qjs. The scan lives once in plimsoll/sandboxtest; the
// depguard rule in .golangci.yml is the companion for CI running golangci-lint.
func TestNoBannedQJSDependency(t *testing.T) { sandboxtest.RequireNoQJS(t) }
