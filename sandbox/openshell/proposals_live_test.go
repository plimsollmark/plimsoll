package openshell

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// proposalsProbe looks, from inside a sandbox, for the two things a supervisor with
// agent policy proposals on gives its sandbox (crates/openshell-supervisor-network/src/
// policy_local.rs at v0.1.10): the policy_advisor skill file, and a policy.local API that
// answers. With the setting off the skill is not installed and every policy.local route
// answers 404 feature_disabled; reaching nothing at all is off too, as far as code in
// the sandbox can tell.
const proposalsProbe = `const fs=require("fs"),http=require("http");
const skill=fs.existsSync("/etc/openshell/skills/policy_advisor.md")?"present":"absent";
const req=http.get({host:"policy.local",path:"/v1/policy/current",timeout:5000},r=>{let b="";r.on("data",d=>b+=d);r.on("end",()=>{console.log(JSON.stringify({skill,status:r.statusCode,body:b.slice(0,300)}))})});
req.on("timeout",()=>req.destroy(new Error("timeout")));
req.on("error",e=>console.log(JSON.stringify({skill,error:e.code||e.message})));`

// TestOpenShellProposalsOffByDefaultLive is the measurement a gateway release needs
// before omittedMeansOff may list it: a sandbox nobody configured reports
// agent_policy_proposals_enabled with no value, and the sandbox has neither the skill
// nor a policy.local that serves the proposal API. A gateway that sets the key
// explicitly measures nothing about the default, so the test says so and returns.
func TestOpenShellProposalsOffByDefaultLive(t *testing.T) {
	p := liveProvider(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := p.checkDriver(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := p.create(ctx)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer p.destroyAndWait(b)
	cfg, err := p.readConfig(ctx, b.name)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	setting, reported := cfg.GetSettings()[agentProposalsSetting]
	if !reported {
		t.Fatalf("gateway %q does not report %s", p.gatewayVersion(), agentProposalsSetting)
	}
	if setting.GetValue() != nil {
		t.Logf("gateway %q sets %s explicitly (%v): the default was not measured", p.gatewayVersion(), agentProposalsSetting, setting.GetValue())
		return
	}
	out, err := p.exec(ctx, b, []string{"/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "node", "-e", proposalsProbe}, nil, nil, 1<<16, 1<<16)
	if err != nil || out.exitCode != 0 {
		t.Fatalf("probe: exit %d, %v, stderr %q", out.exitCode, err, out.stderr)
	}
	got := strings.TrimSpace(string(out.stdout))
	t.Logf("gateway %q, %s reported with no value: %s", p.gatewayVersion(), agentProposalsSetting, got)
	if !strings.Contains(got, `"skill":"absent"`) {
		t.Errorf("the policy_advisor skill is installed, so proposals are on: %s", got)
	}
	if strings.Contains(got, `"status":`) && (!strings.Contains(got, `"status":404`) || !strings.Contains(got, "feature_disabled")) {
		t.Errorf("policy.local answered other than 404 feature_disabled, so proposals may be on: %s", got)
	}
}

// TestOpenShellExecEnvironmentLive measures what an exec starts with: the gateway's own
// few variables, never the image's (the image sets NODE_VERSION, YARN_VERSION and the
// thread counts; docker/python.Dockerfile). plimsoll's own programs start under env -i
// either way; this records whether a release has begun passing the image's.
func TestOpenShellExecEnvironmentLive(t *testing.T) {
	p := liveProvider(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := p.checkDriver(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := p.create(ctx)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer p.destroyAndWait(b)
	out, err := p.exec(ctx, b, []string{"/usr/bin/env"}, nil, nil, 1<<16, 1<<16)
	if err != nil || out.exitCode != 0 {
		t.Fatalf("env: exit %d, %v, stderr %q", out.exitCode, err, out.stderr)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out.stdout)), "\n") {
		name, _, _ := strings.Cut(line, "=")
		names = append(names, name)
	}
	slices.Sort(names)
	t.Logf("gateway %q hands an exec: %v", p.gatewayVersion(), names)
	for _, image := range []string{"NODE_VERSION", "YARN_VERSION", "OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS"} {
		if slices.Contains(names, image) {
			t.Errorf("the exec has the image's %s: the gateway passes the image's environment", image)
		}
	}
}
