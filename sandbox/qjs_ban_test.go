// This file is package sandbox_test, not sandbox, and that is load-bearing rather
// than stylistic. sandboxtest now offers helpers that construct real providers, so
// it imports sandbox; an in-package test importing sandboxtest would then be an
// import cycle. It uses no unexported identifier, so the external test package
// costs nothing.
package sandbox_test

import (
	"testing"

	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// TestNoBannedQJSDependency fails if this module reintroduces the banned
// github.com/fastschema/qjs. The scan lives once in plimsoll/sandboxtest; the
// depguard rule in .golangci.yml is the companion for CI running golangci-lint.
func TestNoBannedQJSDependency(t *testing.T) { sandboxtest.RequireNoQJS(t) }
