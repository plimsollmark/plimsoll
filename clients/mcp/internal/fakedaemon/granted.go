package fakedaemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

const (
	// GrantProfile is the one grant profile a daemon from ServeGranted serves.
	GrantProfile = "echo-api"
	// GrantToken is the bearer token a daemon from ServeGranted accepts.
	GrantToken = "fake-daemon-token"
)

// granted is the session provider under a provider's name, stating project grants. A
// granted fresh project is answered as Provider answers one, with its stdout led by
// "granted <its routes>|" and, when the plimsoll_host module came with it, "module|".
type granted struct {
	*Provider
	name string
}

func (g granted) Name() string                 { return g.name }
func (granted) SupportsJavaScriptGrants() bool { return false }
func (granted) SupportsProjectGrants() bool    { return true }

func (g granted) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	res, err := g.Provider.RunProject(ctx, req)
	if err != nil || req.Grant == nil || len(res.Steps) == 0 {
		return res, err
	}
	var routes []string
	for _, r := range req.Grant.Allow {
		routes = append(routes, r.Method+" "+r.Path)
	}
	lead := "granted " + strings.Join(routes, ",") + "|"
	for _, f := range req.Files {
		if f.Path == sandbox.HostClientPythonPath && f.Content == sandbox.HostClientPython {
			lead += "module|"
		}
	}
	res.Steps[0].Stdout = lead + res.Steps[0].Stdout
	return res, nil
}

type verifier struct{}

func (verifier) VerifyToken(_ context.Context, token string) (rpc.Principal, bool, error) {
	if token != GrantToken {
		return rpc.Principal{}, false, nil
	}
	return rpc.Principal{UserID: "mcp-test", Scopes: []string{rpc.ScopeCodeRun}}, true, nil
}

// ServeGranted starts a daemon whose provider is named provider (docker, whose Python
// steps reach the broker, or e2b, whose do not), stating project grants, behind
// GrantToken, serving one profile, GrantProfile, with sessions on.
func ServeGranted(t testing.TB, provider string) *Daemon {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grants.json")
	b, _ := json.Marshal(map[string]any{"profiles": map[string]any{GrantProfile: map[string]any{
		"base_url": "https://api.echo.invalid", "allow": []string{"GET /v1/lights/*"}, "allowed_callers": []string{"mcp-test"},
	}}})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := grants.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{Sessions: &sandboxtest.Sessions{}}
	svc := rpc.NewSandboxService(granted{p, provider})
	svc.Grants = reg
	svc.Sessions = rpc.SessionConfig{MaxSessions: 4, Lifetime: time.Hour, IdleTimeout: time.Hour}
	calls := &callCount{n: map[string]int{}}
	url, stop := serveWith(t, svc, false, calls, verifier{})
	return &Daemon{URL: url, Provider: p, Service: svc, stop: stop, calls: calls}
}
