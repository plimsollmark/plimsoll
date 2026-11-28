package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// tierTest names a test, by its file under the repository's root and its function, that
// holds one kind of a provider's results to stating its tier.
type tierTest struct{ kind, file, test string }

// tierTests are, for every provider this build can serve, the tests that hold its
// results to naming the tier it states, by kind: snippet, project, module, session. A
// project test is also what holds a cell run by itself (it runs as a project and keeps
// the project's tier, sandbox/cell_fresh.go). Live and docker tests run in their own
// suites (make audit DOCKER=1, E2B=1, OPENSHELL=1); the stand-in tests run in every gate.
// A provider registered in a file of its own adds its entry from that file.
var tierTests = map[string][]tierTest{
	"wasm": {{"snippet", "sandbox/wasm_test.go", "TestWasmRunJavaScript"}},
	"docker": {
		{"snippet", "sandbox/docker_test.go", "TestDockerRunCapturesStdoutAndExitZero"},
		{"project", "sandbox/docker_projecttest_test.go", "TestDockerProjectConformance"},
		{"module", "sandbox/docker_sim_test.go", "TestDockerRunModule"},
		{"session", "sandbox/docker_session_test.go", "TestDockerSessionConformance"},
		{"session", "sandbox/docker_session_pool_test.go", "TestDockerSessionPoolConformance"},
	},
	"e2b": {
		{"snippet", "sandbox/e2b_test.go", "TestE2BSingleRunsServeANodeTooOldForSessions"},
		{"project", "sandbox/e2b_session_docker_test.go", "TestE2BDockerProjectConformance"},
		{"session", "sandbox/e2b_session_docker_test.go", "TestE2BSessionDockerConformance"},
	},
	"dockercloud": {
		{"snippet", "sandbox/dockercloud_test.go", "TestDockerCloudCreateDeniesAllEgressAndWrapsTheSnippet"},
		{"project", "sandbox/dockercloud_rest_test.go", "TestDockerCloudRESTCreateAndCredentials"},
	},
	"openshell": {
		{"snippet", "sandbox/openshell/openshell_test.go", "TestRunJavaScript"},
		{"project", "sandbox/openshell/openshell_test.go", "TestRunProject"},
		{"project", "sandbox/openshell/project_live_test.go", "TestOpenShellProjectConformanceLive"},
		{"session", "sandbox/openshell/session_live_test.go", "TestOpenShellSessionConformanceLive"},
	},
	"agentsandbox": {
		{"snippet", "sandbox/agentsandbox/agentsandbox_test.go", "TestRunsClaimRunAndDelete"},
		{"project", "sandbox/agentsandbox/agentsandbox_test.go", "TestRunsClaimRunAndDelete"},
	},
	"wslc": {
		{"snippet", "sandbox/wslc/wslc_test.go", "TestRunProjectAndSnippet"},
		{"project", "sandbox/wslc/wslc_test.go", "TestRunProjectAndSnippet"},
		{"snippet", "sandbox/wslc/perrun_test.go", "TestHolderInputIsOnlyTheExitLine"},
		{"project", "sandbox/wslc/perrun_test.go", "TestHolderInputIsOnlyTheExitLine"},
	},
}

// tierChecks are the calls that hold a result to its tier: the assertion itself, and the
// two conformance suites, which make it on every result they read.
var tierChecks = map[string][]string{"tiercheck": {"Stated"}, "projecttest": {"Run"}, "sessiontest": {"Run"}}

// TestEveryProviderIsHeldToStatingATier fails a provider this build can serve that has no
// test holding its snippets (and, when it runs them, its projects) to naming its tier,
// and a listed test that is gone or makes no tier check (release-55). The daemon writes
// "unknown" for a result that names no tier, and every official client then refuses the
// record after the code ran; until 2026-11-26 nothing held every provider to it.
func TestEveryProviderIsHeldToStatingATier(t *testing.T) {
	root := filepath.Join("..", "..")
	parsed := map[string]*ast.File{}
	for _, name := range append(sandbox.ProviderNames(), daemonProviderNames()...) {
		tests := tierTests[name]
		var kinds []string
		for _, tt := range tests {
			kinds = append(kinds, tt.kind)
			f, ok := parsed[tt.file]
			if !ok {
				var err error
				f, err = parser.ParseFile(token.NewFileSet(), filepath.Join(root, tt.file), nil, 0)
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				parsed[tt.file] = f
			}
			if fn := findFunc(f, tt.test); fn == nil {
				t.Errorf("%s: %s has no %s", name, tt.file, tt.test)
			} else if !checksTier(fn) {
				t.Errorf("%s: %s in %s makes no tier check (tiercheck.Stated, or projecttest.Run or sessiontest.Run)", name, tt.test, tt.file)
			}
		}
		if !slices.Contains(kinds, "snippet") {
			t.Errorf("%s: no test holds its snippets to naming its tier; add one to tierTests", name)
		}
		if name != "wasm" && !slices.Contains(kinds, "project") {
			t.Errorf("%s: no test holds its projects to naming its tier; add one to tierTests", name)
		}
	}
}

func findFunc(f *ast.File, name string) *ast.FuncDecl {
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// checksTier reports whether fn calls one of tierChecks.
func checksTier(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && slices.Contains(tierChecks[pkg.Name], sel.Sel.Name) {
				found = true
			}
		}
		return !found
	})
	return found
}
