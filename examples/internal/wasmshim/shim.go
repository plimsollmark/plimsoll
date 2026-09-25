// Package wasmshim holds the Node shim that runs a controller compiled to
// WebAssembly under the judge: controller.js, sent as a project file beside
// controller.wasm. One shim serves every single-output plant, because it passes the
// module whatever observations the judge sends. The examples embed it from here and
// the docker tests read the same file, so there is one copy.
package wasmshim

import (
	_ "embed"
	"fmt"
	"strings"
)

// Source is controller.js.
//
//go:embed controller.js
var Source string

// WithImports returns Source with its empty import object replaced by provided, a
// JavaScript object literal, for a build that deliberately lets the module import
// something (the cart-pole example binds env.host_cos to Math.cos to show that cos
// is its whole difference from the JavaScript law).
func WithImports(provided string) (string, error) {
	const empty = "const provided = {};"
	if strings.Count(Source, empty) != 1 {
		return "", fmt.Errorf("controller.js no longer declares %q exactly once", empty)
	}
	return strings.Replace(Source, empty, "const provided = "+provided+";", 1), nil
}
