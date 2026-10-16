package server

import (
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The fresh-call runners, byte for byte the TypeScript client's RUNNERS (its suite
// compares them with these files), so a fresh call prints its last expression and
// takes top-level await and work-directory imports as a session cell does.
var (
	//go:embed runners/run.py
	runPy string
	//go:embed runners/run.cjs
	runCjs string
)

type runner struct{ path, file, step, source string }

var runners = map[sandbox.Language]runner{
	sandbox.LanguagePython:     {path: ".plimsoll/run.py", file: ".plimsoll/cell.py", step: "python3 -I .plimsoll/run.py", source: runPy},
	sandbox.LanguageJavaScript: {path: ".plimsoll/run.cjs", file: ".plimsoll/cell.js", step: "node --expose-internals .plimsoll/run.cjs", source: runCjs},
}

// snippetRunner wraps code for a daemon that runs only snippets (wasm): its last
// value printed, on Node and QuickJS alike, as the TypeScript client's snippetRunner.
func snippetRunner(code string) string {
	quoted, _ := json.Marshal(code)
	return strings.Join([]string{
		"(() => {",
		"  const show = (v) => {",
		`    if (typeof require === "function") { try { return require("node:util").inspect(v, { depth: 4 }); } catch (_) {} }`,
		"    try { const s = JSON.stringify(v); if (s !== undefined) return s; } catch (_) {}",
		"    return String(v);",
		"  };",
		"  const v = (0, eval)(" + string(quoted) + ");",
		"  Promise.resolve(v).then((v) => { if (v !== undefined) console.log(show(v)); });",
		"})();",
		"",
	}, "\n")
}
