package sandbox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGrantedSnippetCellNeedsAnAsyncFunction is what the granted code tools tell a model on
// a daemon that runs snippets only (wasm): a granted call there is SnippetCell's form, which
// evaluates the code as a script, so top-level await fails, and the form those tools'
// descriptions name instead, an async function's call as the final expression, calls the
// API and prints the value once it settles (clients/typescript/src/tool.ts SNIPPET_JS,
// clients/mcp/server/grant.go apiText).
func TestGrantedSnippetCellNeedsAnAsyncFunction(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"hall","on":false}`)
	}))
	defer upstream.Close()
	grant := &HostAPIGrant{BaseURL: upstream.URL, Allow: []HostRoute{{Method: "GET", Path: "/v1/lights/*"}}, Minter: StaticToken("snippet-key")}
	run := func(code string) Result {
		t.Helper()
		res, err := testWasm().RunJavaScript(context.Background(), Request{Code: SnippetCell(code), Grant: grant})
		if err != nil {
			t.Fatalf("RunJavaScript: %v", err)
		}
		return res
	}
	if res := run(`const light = await host.get("/v1/lights/hall");` + "\nlight.id"); res.ExitCode == 0 && strings.Contains(res.Stdout, "hall") {
		t.Fatalf("top-level await worked in the snippet form (stdout %q): the descriptions say it does not", res.Stdout)
	}
	res := run(`(async () => { const light = await host.get("/v1/lights/hall"); return light.id + " " + light.on; })()`)
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "hall false") {
		t.Fatalf("the async function's form: exit %d stdout %q stderr %q", res.ExitCode, res.Stdout, res.Stderr)
	}
}
