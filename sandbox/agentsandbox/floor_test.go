package agentsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// serviceRuns are a snippet and a project sent through the daemon's service, with no
// caller minimum.
var serviceRuns = []struct {
	name    string
	payload func(*plimsollv1.RunRequest)
}{
	{"snippet", func(r *plimsollv1.RunRequest) {
		r.Payload = &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}
	}},
	{"project", func(r *plimsollv1.RunRequest) {
		r.Payload = &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{
			Files: []*plimsollv1.ProjectFile{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}}}
	}},
}

func serviceRun(svc *rpc.SandboxService, payload func(*plimsollv1.RunRequest)) (*plimsollv1.RunResponse, error) {
	req := &plimsollv1.RunRequest{Protocol: protocol.Number}
	payload(req)
	resp, err := svc.Run(context.Background(), connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// wireRefusal is the not-dispatched reason a service error carries on the wire.
func wireRefusal(err error) plimsollv1.NotDispatchedReason {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSPECIFIED
	}
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if nd, ok := v.(*plimsollv1.NotDispatched); ok {
				return nd.GetReason()
			}
		}
	}
	return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSPECIFIED
}

// A hardened daemon proved gVisor; the runtime class's handler then becomes runc. The
// provider here has bound no class (no smoke test), so the daemon's floor alone decides:
// a caller that sets no minimum is refused, not dispatched, for the isolation reason, on a
// snippet and a project, before a claim is made. A daemon with no floor runs both at the
// container tier, as before.
func TestTheDaemonFloorRefusesAClassWeakenedAfterStartup(t *testing.T) {
	for _, floor := range []sandbox.IsolationClass{sandbox.IsolationKernel, sandbox.IsolationUnknown} {
		t.Run("floor "+floor.String(), func(t *testing.T) {
			p, api, sd := testProvider(t)
			runtimeDefault(api)
			if err := p.Preflight(context.Background()); err != nil || p.IsolationClass() != sandbox.IsolationKernel {
				t.Fatalf("startup under runsc: %v, %s", err, p.IsolationClass())
			}
			api.mu.Lock()
			api.handler = "runc"
			api.mu.Unlock()
			svc := rpc.NewSandboxService(p)
			svc.Floor = floor
			for _, r := range serviceRuns {
				resp, err := serviceRun(svc, r.payload)
				api.mu.Lock()
				claims := len(api.created)
				api.mu.Unlock()
				sd.mu.Lock()
				starts, checks := len(sd.starts), sd.tierChecks
				sd.mu.Unlock()
				if floor == sandbox.IsolationUnknown {
					if err != nil || resp.GetIsolation() != "container" {
						t.Fatalf("%s with no daemon floor: %v, isolation %q; want it run at container, as before", r.name, err, resp.GetIsolation())
					}
					continue
				}
				if connect.CodeOf(err) != connect.CodeFailedPrecondition || wireRefusal(err) != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION {
					t.Fatalf("%s under the floor: %v; want an isolation refusal, not dispatched", r.name, err)
				}
				if claims != 0 || starts != 0 || checks != 0 {
					t.Fatalf("%s under the floor: %d claims, %d starts, %d tier checks; want none", r.name, claims, starts, checks)
				}
			}
			drained(t, p)
		})
	}
}

// The check before a claim sees runsc and the claimed pod's read-back sees runc (the class
// replaced between the two). The pod is held to the daemon's floor: refused, not
// dispatched, for the isolation reason, after the tier check and before any of the run's
// commands, on a snippet and a project.
func TestEachPodIsHeldToTheDaemonFloor(t *testing.T) {
	p, api, sd := testProvider(t)
	runtimeDefault(api)
	if err := p.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := rpc.NewSandboxService(p)
	svc.Floor = sandbox.IsolationKernel
	for i, r := range serviceRuns {
		api.mu.Lock()
		first := api.classReads + 1
		api.classHook = func(read int, rc *runtimeClass) {
			if read > first {
				rc.Handler = "runc"
			}
		}
		api.mu.Unlock()
		_, err := serviceRun(svc, r.payload)
		if wireRefusal(err) != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION || !strings.Contains(err.Error(), "container is below") {
			t.Fatalf("%s on a pod read back under runc: %v; want an isolation refusal, not dispatched", r.name, err)
		}
		sd.mu.Lock()
		starts, checks := len(sd.starts), sd.tierChecks
		sd.mu.Unlock()
		if starts != 0 || checks != i+1 {
			t.Fatalf("%s: %d starts, %d tier checks; want only the tier check", r.name, starts, checks)
		}
		drained(t, p)
	}
}

// After the smoke test, only the runtime class it ran on: a class replaced under the same
// name (a new UID, which is how a handler changes, since Kubernetes keeps a handler
// immutable), or one whose overhead or scheduling changed, is refused before any claim,
// for a snippet and a project, with or without a daemon floor; Preflight fails, a second
// smoke test does not bind it, and restoring the original does not clear the refusal.
// Metadata alone does not change the binding.
func TestOnlyTheProvenRuntimeClassRuns(t *testing.T) {
	cases := []struct {
		name   string
		change func(rc *runtimeClass)
	}{
		{"replaced with handler runc", func(rc *runtimeClass) { rc.Meta.UID, rc.Handler = "replacement-uid", "runc" }},
		{"replaced with the same handler", func(rc *runtimeClass) { rc.Meta.UID = "replacement-uid" }},
		{"handler changed in place", func(rc *runtimeClass) { rc.Handler = "runc" }},
		{"overhead changed", func(rc *runtimeClass) { rc.Overhead = json.RawMessage(`{"podFixed":{"memory":"600Mi"}}`) }},
		{"scheduling changed", func(rc *runtimeClass) {
			rc.Scheduling = json.RawMessage(`{"nodeSelector":{"pool":"other"}}`)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, api, sd := testProvider(t)
			runtimeDefault(api)
			fakeSmoke(t, p, sd, nil)
			if err := p.SmokeTest(context.Background()); err != nil {
				t.Fatal(err)
			}
			drained(t, p)
			api.mu.Lock()
			api.classHook = func(_ int, rc *runtimeClass) { tc.change(rc) }
			claims := len(api.created)
			api.mu.Unlock()
			sd.mu.Lock()
			starts, checks := len(sd.starts), sd.tierChecks
			sd.mu.Unlock()
			// The provider's own answer names the class; the service keeps a provider's error
			// text for its log, and a caller reads the reason.
			if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "runtime class gvisor changed") {
				t.Fatalf("a snippet after the class %s: %v; want an environment refusal naming the class", tc.name, err)
			}
			_, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}})
			if refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "runtime class gvisor changed") {
				t.Fatalf("a project after the class %s: %v; want an environment refusal naming the class", tc.name, err)
			}
			// Through the service: with no daemon floor the provider refuses (environment);
			// under the floor the pipeline already refuses, since the failed check left the
			// provider's evidence unknown (isolation).
			for floor, want := range map[sandbox.IsolationClass]plimsollv1.NotDispatchedReason{
				sandbox.IsolationUnknown: plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ENVIRONMENT,
				sandbox.IsolationKernel:  plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ISOLATION,
			} {
				svc := rpc.NewSandboxService(p)
				svc.Floor = floor
				for _, r := range serviceRuns {
					_, err := serviceRun(svc, r.payload)
					if got := wireRefusal(err); got != want {
						t.Fatalf("%s after the class %s (floor %s): %v, reason %v; want %v, not dispatched", r.name, tc.name, floor, err, got, want)
					}
				}
			}
			api.mu.Lock()
			afterClaims := len(api.created)
			api.mu.Unlock()
			sd.mu.Lock()
			afterStarts, afterChecks := len(sd.starts), sd.tierChecks
			sd.mu.Unlock()
			if afterClaims != claims || afterStarts != starts || afterChecks != checks {
				t.Fatalf("claimed %d pods, sent %d commands and %d tier checks after the change; want none", afterClaims-claims, afterStarts-starts, afterChecks-checks)
			}
			if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "runtime class gvisor changed") {
				t.Fatalf("Preflight after the change: %v", err)
			}
			if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), "runtime class gvisor changed") {
				t.Fatalf("a second smoke test bound the changed class: %v", err)
			}
			api.mu.Lock()
			api.classHook = nil
			api.mu.Unlock()
			if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "runtime class gvisor changed") {
				t.Fatalf("restoring the class cleared the refusal: %v", err)
			}
			drained(t, p)
		})
	}

	p, api, sd := testProvider(t)
	fakeSmoke(t, p, sd, nil)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	drained(t, p)
	api.mu.Lock()
	api.classHook = func(_ int, rc *runtimeClass) {
		rc.Meta.Labels = map[string]string{"operator-note": "updated"}
		rc.Meta.Annotations = map[string]string{"note": "relabeled"}
	}
	api.mu.Unlock()
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatalf("a metadata-only change: %v", err)
	}
	drained(t, p)
}

// The class is fixed before the boundary test and checked in both claimed pods and after
// the runner test: a class replaced while the smoke test runs fails the proof, and nothing
// is proven.
func TestTheRuntimeClassCannotChangeWhileTheSmokeTestProvesIt(t *testing.T) {
	for _, duringRunner := range []bool{false, true} {
		t.Run(fmt.Sprintf("during runner=%t", duringRunner), func(t *testing.T) {
			p, api, sd := testProvider(t)
			fakeSmoke(t, p, sd, nil)
			answer := sd.run
			sd.run = func(argv []string, stdin []byte) (string, string, int32) {
				out, stderr, exit := answer(argv, stdin)
				if strings.Contains(strings.Join(argv, " "), runnerPath) == duringRunner {
					api.mu.Lock()
					api.classUID = "recreated-during-smoke"
					api.mu.Unlock()
				}
				return out, stderr, exit
			}
			if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), "runtime class gvisor changed") {
				t.Fatalf("replaced during the smoke test: %v", err)
			}
			drained(t, p)
			p.mu.Lock()
			proven := p.proven
			p.mu.Unlock()
			if proven != "" {
				t.Fatal("recorded a smoke proof across a runtime class change")
			}
		})
	}
}
