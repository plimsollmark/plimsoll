package client

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// moduleFake is a sandbox.Sandbox whose only real operation is RunModule: it
// records the request it received and answers with a canned result, so the test
// can check both directions of the wire mapping.
type moduleFake struct {
	got    sandbox.ModuleRequest
	result sandbox.ModuleResult
}

func (f *moduleFake) Name() string                           { return "modfake" }
func (f *moduleFake) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationVM }
func (f *moduleFake) SupportsModules() bool                  { return true }
func (f *moduleFake) RunJavaScript(context.Context, sandbox.Request) (sandbox.Result, error) {
	return sandbox.Result{}, sandbox.ErrUnsupported
}
func (f *moduleFake) RunProject(context.Context, sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	return sandbox.ProjectResult{}, sandbox.ErrUnsupported
}
func (f *moduleFake) RunModule(_ context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	f.got = req
	return f.result, nil
}

func startModuleServer(t *testing.T, fake *moduleFake) string {
	t.Helper()
	svc := rpc.NewSandboxService(fake)
	mux := http.NewServeMux()
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRemoteRunModuleRoundTrip(t *testing.T) {
	fake := &moduleFake{result: sandbox.ModuleResult{
		Runs:      []sandbox.ModuleRun{{Status: 2, Outputs: []float64{1, math.Pi, -0.5, 1e-300}}, {Status: -104}},
		Width:     2,
		Sandbox:   "modfake",
		Isolation: sandbox.IsolationVM,
		Outcome:   sandbox.ProjectOutcomeCompleted,
		Stdout:    "summary",
	}}
	r, err := New(startModuleServer(t, fake))
	if err != nil {
		t.Fatal(err)
	}
	info, err := r.Describe(context.Background())
	if err != nil || !info.SupportsModule {
		t.Fatalf("Describe = %+v, %v; want SupportsModule", info, err)
	}
	rows := [][]float64{{0.1, 2, 0}, {math.Nextafter(5, 6), 2, 0}}
	res, err := r.RunModule(context.Background(), sandbox.ModuleRequest{Model: "vanderpol", Rows: rows, EndTime: 20, Step: 0.01, MinimumIsolation: sandbox.IsolationVM})
	if err != nil {
		t.Fatal(err)
	}
	if fake.got.Model != "vanderpol" || fake.got.EndTime != 20 || fake.got.Step != 0.01 || fake.got.MinimumIsolation != sandbox.IsolationVM || len(fake.got.Rows) != 2 {
		t.Fatalf("server received %+v", fake.got)
	}
	for i := range rows {
		for j := range rows[i] {
			if math.Float64bits(fake.got.Rows[i][j]) != math.Float64bits(rows[i][j]) {
				t.Fatalf("row %d value %d changed on the wire: %v -> %v", i, j, rows[i][j], fake.got.Rows[i][j])
			}
		}
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || res.Width != 2 || res.Sandbox != "modfake" || res.Isolation != sandbox.IsolationVM || res.Stdout != "summary" {
		t.Fatalf("result header = %+v", res)
	}
	if len(res.Runs) != 2 || res.Runs[0].Status != 2 || res.Runs[1].Status != -104 || len(res.Runs[1].Outputs) != 0 {
		t.Fatalf("runs = %+v", res.Runs)
	}
	for k, want := range fake.result.Runs[0].Outputs {
		if math.Float64bits(res.Runs[0].Outputs[k]) != math.Float64bits(want) {
			t.Fatalf("output %d = %v, want %v bit-exact", k, res.Runs[0].Outputs[k], want)
		}
	}
}

func TestRemoteRunModuleWeakEvidenceIsDataLoss(t *testing.T) {
	// The server's static tier admits a vm floor; the provider's evidence says
	// container. Execution may have happened, so the client reports DataLoss.
	fake := &moduleFake{result: sandbox.ModuleResult{Sandbox: "modfake", Isolation: sandbox.IsolationContainer, Outcome: sandbox.ProjectOutcomeCompleted}}
	r, err := New(startModuleServer(t, fake))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.RunModule(context.Background(), sandbox.ModuleRequest{Model: "m", Rows: [][]float64{{1}}, EndTime: 1, Step: 0.1, MinimumIsolation: sandbox.IsolationVM})
	if connect.CodeOf(err) != connect.CodeDataLoss || !errors.Is(err, sandbox.ErrIsolationEvidenceMismatch) {
		t.Fatalf("err = %v, want DataLoss wrapping ErrIsolationEvidenceMismatch", err)
	}
}

func TestRemoteRunModuleUnsupportedOnWasmAndValidatedLocally(t *testing.T) {
	r, err := New(startServer(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.RunModule(context.Background(), sandbox.ModuleRequest{Model: "m", Rows: [][]float64{{1}}, EndTime: 1, Step: 0.1}); !errors.Is(err, sandbox.ErrUnsupported) {
		t.Fatalf("wasm server: err = %v, want ErrUnsupported", err)
	}
	// A malformed table never leaves the process: no server is listening here.
	r, err = New("http://127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.RunModule(context.Background(), sandbox.ModuleRequest{Model: "m", Rows: [][]float64{{1, 2}, {1}}, EndTime: 1, Step: 0.1}); !errors.Is(err, sandbox.ErrInvalidRequest) {
		t.Fatalf("ragged table: err = %v, want ErrInvalidRequest", err)
	}
}
