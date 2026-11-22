package clientsuite

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The grant-echo daemons are what a code tool's granted call is tested against with no
// sandbox and no API: the tool-echo provider (toolecho.go), named as a provider whose
// Python steps can reach the broker ("docker") or one whose cannot ("e2b"), stating
// project grants, behind the real handler with a bearer token (a grant needs an
// authenticated caller) and one grant profile, GrantEchoProfile. A granted project is
// answered with the tool-echo plan plus "grant": the routes of the grant the handler
// resolved, so a suite sees that the profile, and only the one the application chose,
// reached the provider. Any other profile name is the handler's own permission refusal.

// GrantEchoProfile is the one profile the grant-echo daemons serve.
const GrantEchoProfile = "echo-api"

// grantEcho is the tool-echo provider under another name, stating project grants.
type grantEcho struct {
	*toolEcho
	name string
}

func (g grantEcho) Name() string                 { return g.name }
func (grantEcho) SupportsJavaScriptGrants() bool { return false }
func (grantEcho) SupportsProjectGrants() bool    { return true }
func (g grantEcho) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	res, err := g.toolEcho.RunProject(ctx, req)
	res.Sandbox = g.name
	if err != nil || len(res.Steps) != 1 || req.Grant == nil {
		return res, err
	}
	var plan map[string]any
	if json.Unmarshal([]byte(res.Steps[0].Stdout), &plan) != nil {
		return res, nil // a marker's answer, not the plan
	}
	var allow []string
	for _, r := range req.Grant.Allow {
		allow = append(allow, r.Method+" "+r.Path)
	}
	plan["grant"] = map[string]any{"allow": allow}
	b, _ := json.Marshal(plan)
	res.Steps[0].Stdout = string(b)
	return res, nil
}

var _ sandbox.GrantCapable = grantEcho{}

// serveGrantEcho serves a grant-echo daemon whose provider is named name, and returns its
// URL and its token.
func serveGrantEcho(name string) func(t *testing.T) []string {
	return func(t *testing.T) []string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "grants.json")
		profile := map[string]any{"profiles": map[string]any{GrantEchoProfile: map[string]any{
			"base_url":        "https://api.echo.invalid",
			"allow":           []string{"GET /v1/lights/*", "POST /v1/lights/*/on"},
			"allowed_callers": []string{"client-suite"},
		}}}
		b, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		reg, err := grants.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		svc := Quiet(rpc.NewSandboxService(grantEcho{&toolEcho{holds: newHolds()}, name}))
		svc.Grants = reg
		return []string{Serve(t, svc, verifier{token: authToken}, nil), authToken}
	}
}
