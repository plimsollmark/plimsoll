package server_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
	"github.com/plimsollmark/plimsoll/sandbox"
)

type gainOut struct {
	Summary string  `json:"summary"`
	Gain    float64 `json:"gain"`
}

// A tool whose code ran and whose output cannot be written (a number that is not finite, a
// value its output schema refuses) is answered ran "maybe", with or without pictures, and
// never "nothing ran" or a protocol error: the model would run it again, as told it was safe
// to (hunt-quality-43).
func TestAnOutputThatCannotBeWrittenMayHaveRun(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	s, err := server.New(local(d.URL))
	if err != nil {
		t.Fatal(err)
	}
	img := tinyPNG(t)
	var ran atomic.Int32
	server.ExtendRun(s, &mcp.Tool{Name: "tune", Description: "Tunes."}, func(_ context.Context, in echoIn) (gainOut, []server.Picture, error) {
		ran.Add(1)
		var pics []server.Picture
		gain := math.NaN()
		switch in.Say {
		case "picture":
			pics = []server.Picture{{PNG: img, Title: "step response"}}
		case "infinite":
			gain = math.Inf(1)
		case "finite":
			gain = 2
		}
		return gainOut{Summary: "tuned", Gain: gain}, pics, nil
	})
	strict := &jsonschema.Schema{Type: "object", Required: []string{"summary"}, Properties: map[string]*jsonschema.Schema{"summary": {Type: "string", MinLength: new(int)}}}
	*strict.Properties["summary"].MinLength = 5
	server.Extend(s, &mcp.Tool{Name: "strict", Description: "Says too little.", OutputSchema: strict}, func(context.Context, echoIn) (echoOut, []server.Picture, error) {
		return echoOut{Summary: "no"}, nil, nil
	})
	// A tool registered on MCP() directly is not the server's: its answers pass as written.
	mcp.AddTool(s.MCP(), &mcp.Tool{Name: "direct", Description: "Not the server's."}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return nil, nil, errors.New("it ran, then failed")
	})
	c := connectServer(t, s)

	for _, say := range []string{"nan", "picture", "infinite"} {
		// call fails the test on a protocol error, which says nothing of whether anything ran.
		f := c.fail("tune", map[string]any{"say": say})
		if f.Ran != "maybe" || f.Refusal != "" || !strings.HasPrefix(f.Summary, "The code may have run, and its output could not be delivered") || !strings.Contains(f.Summary, "unsupported value") {
			t.Errorf("%s: an output that could not be written: %+v", say, f)
		}
	}
	if got := ran.Load(); got != 3 {
		t.Errorf("the tool ran %d times, want 3", got)
	}
	if out := c.ok("tune", map[string]any{"say": "finite"}); out["gain"] != float64(2) {
		t.Errorf("a finite output: %v", out)
	}
	if f := c.fail("strict", map[string]any{"say": "x"}); f.Ran != "maybe" || !strings.Contains(f.Summary, "could not be delivered") {
		t.Errorf("an output its schema refuses: %+v", f)
	}
	// What the input schema refuses is still refused before the tool, nothing run.
	if f := c.fail("tune", map[string]any{"say": 3}); f.Ran != "no" || f.Refusal != "request" || !strings.Contains(f.Summary, "input schema") {
		t.Errorf("arguments the schema refuses: %+v", f)
	}
	if got := ran.Load(); got != 4 {
		t.Errorf("the tool ran %d times after a schema refusal, want 4", got)
	}
	if res := c.call("direct", nil); !res.IsError || text(res) != "it ran, then failed" {
		t.Errorf("a tool not the server's was rewritten: %s", text(res))
	}
}

// Every tool answer is made in one place, answer (and toolError, its writer of failures), and
// every tool is registered in one, addToolWith: a tool registered, or a tool result made,
// anywhere else in the module would answer a model without the server's rule that a call that
// reached its tool is never told nothing ran (hunt-quality-43).
func TestEveryToolAnswerGoesThroughOnePlace(t *testing.T) {
	allowed := map[string]map[string]bool{
		"AddTool":        {"addToolWith": true},
		"CallToolResult": {"answer": true, "toolError": true},
	}
	found := map[string]int{}
	err := filepath.WalkDir("..", func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			name := ""
			if fn, ok := decl.(*ast.FuncDecl); ok {
				name = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				var what string
				switch n := n.(type) {
				case *ast.CallExpr:
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "AddTool" {
						what = "AddTool"
					}
					if ix, ok := n.Fun.(*ast.IndexListExpr); ok {
						if sel, ok := ix.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "AddTool" {
							what = "AddTool"
						}
					}
				case *ast.CompositeLit:
					if sel, ok := n.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "CallToolResult" {
						what = "CallToolResult"
					}
				}
				if what == "" {
					return true
				}
				found[what]++
				if !allowed[what][name] {
					t.Errorf("%s: %s in %q, outside the one place every tool answer goes through", fset.Position(n.Pos()), what, name)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found["AddTool"] != 1 || found["CallToolResult"] < 2 {
		t.Errorf("found %v: the scan no longer sees the one place", found)
	}
}

// What a model reads of a daemon behind TLS it cannot trust says what went wrong without
// this server's internal mark (": not sent"), and a certificate for other names is told by
// kind: the names on the certificate and the name dialed are the daemon's address as much
// as the address is (hunt-quality-49).
func TestATLSFailureIsToldWithoutTheMarkOrTheNames(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	untrusted := connect(t, local(srv.URL))
	f := untrusted.fail("run_code", map[string]any{"code": "1"})
	if f.Ran != "no" || strings.Contains(f.Summary, "not sent") {
		t.Errorf("an untrusted certificate: %+v", f)
	}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	cfg := local("https://localhost:" + port)
	cfg.HTTPClient = srv.Client() // trusts the certificate, which names example.com and 127.0.0.1
	misnamed := connect(t, cfg)
	res := misnamed.call("run_code", map[string]any{"code": "1"})
	info := misnamed.call("server_info", nil)
	for what, said := range map[string]string{"run_code": text(res), "server_info": text(info)} {
		if strings.Contains(said, "example.com") || strings.Contains(said, "localhost") || strings.Contains(said, "not sent") {
			t.Errorf("%s names the certificate's names or the daemon's: %s", what, said)
		}
		if !strings.Contains(said, "certificate is not valid for the name") {
			t.Errorf("%s does not say what went wrong: %s", what, said)
		}
	}
	if !res.IsError {
		t.Fatalf("run_code against a misnamed certificate succeeded: %s", text(res))
	}
}

// A granted call refused because the daemon changed (here: below the floor it now meets)
// makes the next Describe read afresh, as a fresh call's refusal does (hunt-quality-49).
func TestAGrantedRefusalThatSaysTheDaemonChangedForgetsItsDescribe(t *testing.T) {
	d := fakedaemon.ServeGranted(t, "docker")
	cfg := grantedConfig(d.URL, fakedaemon.GrantProfile)
	cfg.MinimumIsolation = sandbox.IsolationVM
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := connectServer(t, s)
	c.ok("server_info", nil)
	if !server.DescribeCached(s) {
		t.Fatal("server_info left no Describe to use")
	}
	f := c.fail("run_code", map[string]any{"code": "1", "language": "javascript"})
	if f.Ran != "no" || f.Refusal != "isolation" {
		t.Fatalf("a granted call below the floor: %+v", f)
	}
	if server.DescribeCached(s) {
		t.Error("a granted refusal that says the daemon changed kept the Describe")
	}
}
