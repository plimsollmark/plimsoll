package wslc

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The live tests of gVisor inside each per-run VM, run by `make wslc-gvisor-suite` (not by
// `make wslc-suite`, which needs no runsc). On a Windows host with WSL 3.0.5 or later, from a
// WSL distribution, with WSLC_LIVE=1, SANDBOX_WSLC_IMAGE, and the operator's runsc:
//
//	SANDBOX_WSLC_RUNSC_PATH     the runsc binary (docker's configured runtime path, or `command -v runsc`)
//	SANDBOX_WSLC_RUNSC_SHA512   sha512sum of it
//	SANDBOX_WSLC_RUNSC_HELPERS  NAME=SHA512 for each file runsc needs from gvisor-bin/ beside it
//
// Each test skips without WSLC_LIVE=1 (the skip comes first), fails without the rest of its
// configuration, and cleans up after itself even when it fails. At most two VMs at once.

// gvisorEnv is this process's environment with the per-run mode, gVisor on and two sessions
// at most.
func gvisorEnv(k string) string {
	if k == "SANDBOX_WSLC_GVISOR" {
		return "1"
	}
	return perRunEnv(k)
}

// liveGVisorProvider is a per-run provider with gVisor from this process's environment, not
// yet started. Whatever it leaves is swept when the test ends.
func liveGVisorProvider(t *testing.T) *Provider {
	t.Helper()
	if !liveRequested() {
		t.Skip("set WSLC_LIVE=1 (make wslc-gvisor-suite) on a host with wslc.exe")
	}
	for _, name := range []string{"SANDBOX_WSLC_IMAGE", "SANDBOX_WSLC_RUNSC_PATH", "SANDBOX_WSLC_RUNSC_SHA512"} {
		if os.Getenv(name) == "" {
			t.Fatalf("WSLC_LIVE=1 needs %s for the gVisor tests (docs/wslc.md)", name)
		}
	}
	prov, err := FromEnv(gvisorEnv)
	if err != nil {
		t.Fatal(err)
	}
	p := prov.Sandbox.(*Provider)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		p.drain()
		if p.pr.root.linux == "" {
			if err := p.resolveRoot(ctx); err != nil {
				t.Errorf("cleanup: %v", err)
				return
			}
		}
		// Ends every session with the prefix and deletes every directory and archive of this
		// provider's (nothing here is live once the test is over), sparing the template.
		if _, err := p.sweep(false); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return p
}

// liveGVisor is a gVisor provider whose startup checks (Preflight and the smoke test, which
// proves gVisor from inside and from the VM's side in two fresh VMs) have passed.
func liveGVisor(t *testing.T) *Provider {
	t.Helper()
	p := liveGVisorProvider(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := p.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.SmokeTest(ctx); err != nil {
		t.Fatal(err)
	}
	return p
}

// A run under gVisor with the provider's own flags prints gVisor's kernel string, states the
// vm tier and the policy that says gVisor was proven on for it, and the smoke test's evidence
// names the runtime, the runsc version and digest and the platform. The startup smoke test
// is itself the proof from inside and from the VM's side, so reaching here means it passed.
func TestGVisorLiveRunPrintsGVisorKernel(t *testing.T) {
	p := liveGVisor(t)
	ev, ok := p.Evidence()
	g := ev.GVisor
	if !ok || g == nil {
		t.Fatalf("no gVisor evidence: %+v", ev)
	}
	if g.Runtime != "runsc" || g.Platform != gvisorPlatform || g.RunscSHA512 != p.cfg.RunscSHA512 || g.SentrySeccomp != "2" {
		t.Fatalf("gVisor evidence: %+v", g)
	}
	t.Logf("gVisor evidence: runtime %s, %s, sha512 %s, platform %s, Sentry seccomp %s, %d Sentry processes, helpers %v; template %d bytes built in %v; seccomp inside %q",
		g.Runtime, g.RunscVersion, g.RunscSHA512, g.Platform, g.SentrySeccomp, g.SentryCount, g.Helpers, ev.TemplateBytes, ev.TemplateBuild, ev.Seccomp)
	if p.IsolationClass() != sandbox.IsolationVM {
		t.Fatalf("tier %v", p.IsolationClass())
	}
	if q := p.Qualification(); !strings.HasSuffix(q, GVisorQualification) {
		t.Fatalf("qualification %q", q)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for i := 0; i < 2; i++ {
		start := time.Now()
		res, err := p.RunJavaScript(ctx, sandbox.Request{
			Code:             "console.log(require('fs').readFileSync('/proc/version', 'utf8').trim() + ' uid ' + process.getuid())",
			MinimumIsolation: sandbox.IsolationVM})
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(string(res.Stdout))
		t.Logf("run %d took %v to its result: %s", i+1, time.Since(start), out)
		if res.ExitCode != 0 || !strings.Contains(strings.ToLower(out), "gvisor") || !strings.HasSuffix(out, "uid 61000") {
			t.Fatalf("a run under gVisor: %+v", res)
		}
		if res.Policy != PolicyGVisor || res.Isolation != sandbox.IsolationVM {
			t.Fatalf("the run's evidence: policy %q, isolation %v", res.Policy, res.Isolation)
		}
	}
	pr, err := p.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"node -e 'console.log(1+1)'"}})
	if err != nil || pr.Outcome != sandbox.ProjectOutcomeCompleted || pr.Policy != PolicyGVisor {
		t.Fatalf("a project under gVisor: %+v %v", pr, err)
	}
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if left := liveLeft(t, p); len(left) != 0 {
		t.Fatalf("left after the teardowns: %v", left)
	}
}

// The no-fallback case on the real WSLC: a session whose docker settings were not rewritten
// (WSLC rewrites them at every boot, so this is a booted VM nobody touched) reads runc, and
// the run is refused before any container starts, marked not dispatched with reason
// environment. The refusal's own text carries what the VM answered, so a read-back that
// could not tell runc from runsc would show here; the control is the same provider, one
// line later, running under gVisor.
func TestGVisorLiveSessionWithoutRewriteIsRefused(t *testing.T) {
	p := liveGVisor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	p.pr.mu.Lock()
	p.pr.skipGVisorWrite = true
	p.pr.mu.Unlock()
	res, err := p.RunJavaScript(ctx, sandbox.Request{Code: "console.log('this must never run')"})
	if reason, marked := sandbox.NotDispatchedReason(err); !marked || reason != sandbox.RefusalEnvironment {
		t.Fatalf("a session whose settings were not rewritten: %+v, error %v (marked %v, reason %v), want not dispatched (environment)", res, err, marked, reason)
	}
	if !strings.Contains(err.Error(), `"runc"`) {
		t.Fatalf("the refusal does not say the VM read runc: %v", err)
	}
	if strings.Contains(string(res.Stdout), "must never run") || res.Policy != "" {
		t.Fatalf("a refused run produced a result: %+v", res)
	}
	t.Logf("refused as required: %v", err)
	// The control: settings written again, the same provider runs under gVisor.
	p.pr.mu.Lock()
	p.pr.skipGVisorWrite = false
	p.pr.mu.Unlock()
	res, err = p.RunJavaScript(ctx, sandbox.Request{Code: "console.log(require('fs').readFileSync('/proc/version', 'utf8'))"})
	if err != nil || !strings.Contains(strings.ToLower(string(res.Stdout)), "gvisor") || res.Policy != PolicyGVisor {
		t.Fatalf("the control run: %+v %v", res, err)
	}
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if left := liveLeft(t, p); len(left) != 0 {
		t.Fatalf("left after the teardowns: %v", left)
	}
}

// Nothing is left behind by gVisor runs, by a refused one, or by two at once: after the
// teardowns no session with the provider's prefix is listed and the run root holds nothing
// but the template. The refused run's session is a booted VM that never ran a container, torn
// down by the same path as every other.
func TestGVisorLiveNothingLeftBehind(t *testing.T) {
	p := liveGVisor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			res, err := p.RunJavaScript(ctx, sandbox.Request{Code: "console.log('left-behind check')"})
			if err == nil && (res.ExitCode != 0 || res.Policy != PolicyGVisor) {
				err = fmt.Errorf("exit %d, policy %q", res.ExitCode, res.Policy)
			}
			errs <- err
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("a concurrent run: %v", err)
		}
	}
	p.pr.mu.Lock()
	p.pr.skipGVisorWrite = true
	p.pr.mu.Unlock()
	if _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}); err == nil {
		t.Fatal("a session without the rewrite ran")
	}
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if left := liveLeft(t, p); len(left) != 0 {
		t.Fatalf("left after the teardowns: %v", left)
	}
}
