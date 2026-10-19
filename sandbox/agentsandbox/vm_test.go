package agentsandbox

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// kataAnswer is the tier check's answer from a Kata pod: its VM's boot line, a boot ID of
// its own and no seccomp filter (Kata applies none in the guest by default).
const kataAnswer = "kernel " + kataBoot + "\nboot " + fakeBoot + "\nSeccomp:\t0\n"

// Kata's Cloud Hypervisor handlers, for both of its runtimes, and AKS Pod Sandboxing's kata
// are the vm tier, with no seccomp profile required of the template; a vm floor is then met,
// and each run reads its pod's node once for the node's boot ID. Kata handlers plimsoll has
// not run stay refused.
func TestKataHandlersAreTheVMTier(t *testing.T) {
	for _, h := range []string{"kata", "kata-clh", "kata-clh-runtime-rs"} {
		t.Run(h, func(t *testing.T) {
			p, api, sd := testProvider(t)
			api.handler = h
			sd.tierAnswer = kataAnswer
			if err := p.Preflight(context.Background()); err != nil || p.IsolationClass() != sandbox.IsolationVM {
				t.Fatalf("preflight: %v, %s", err, p.IsolationClass())
			}
			res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM})
			if err != nil || res.Isolation != sandbox.IsolationVM || api.nodeReads != 1 || len(sd.starts) != 1 {
				t.Fatalf("a vm floor: %+v, %v; %d node reads, %d starts", res, err, api.nodeReads, len(sd.starts))
			}
			pr, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}, MinimumIsolation: sandbox.IsolationVM})
			if err != nil || pr.Isolation != sandbox.IsolationVM || api.nodeReads != 2 {
				t.Fatalf("a project: %+v, %v; %d node reads", pr, err, api.nodeReads)
			}
			drained(t, p)
		})
	}
	for _, h := range []string{"kata-qemu", "kata-qemu-runtime-rs", "kata-fc"} {
		p, api, _ := testProvider(t)
		api.handler = h
		if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "has not tested") || p.IsolationClass() != sandbox.IsolationUnknown {
			t.Errorf("%s: %v, %s", h, err, p.IsolationClass())
		}
	}
}

// Under a gVisor or runc handler a vm floor is refused before any claim: the floor is
// compared with the tier the handler claims.
func TestAVMFloorIsRefusedBelowTheVMTier(t *testing.T) {
	p, api, _ := testProvider(t)
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM})
	if !errors.Is(err, sandbox.ErrInsufficientIsolation) || len(api.created) != 0 {
		t.Fatalf("a vm floor on gVisor: %v, %d claims", err, len(api.created))
	}
	drained(t, p)
}

// Each pod under a Kata handler is held to a VM of its own before any code is sent: its
// kernel log begins with a Linux boot and its boot ID is not its node's. A node whose Kata
// handler runs runc (the pod shares the node's kernel), gVisor's log, a node that cannot
// be read or reports no boot ID, and a pod with no node are refused, not dispatched, with
// nothing of the run's sent.
func TestEachPodIsHeldToTheVMTier(t *testing.T) {
	cases := []struct {
		name, answer, want string
		api                func(*fakeAPI)
	}{
		{"the node's kernel under a Kata handler", "kernel " + kataBoot + "\nboot " + fakeNodeBoot + "\nSeccomp:\t2\n", "is its node's", nil},
		{"the node's kernel with its log wrapped", "kernel [178086.727419] eth0: link up\nboot " + fakeNodeBoot + "\nSeccomp:\t2\n", "not a Linux kernel's boot", nil},
		{"gVisor under a Kata handler", "kernel [   0.000000] Starting gVisor...\nboot " + fakeBoot + "\nSeccomp:\t0\n", "not a Linux kernel's boot", nil},
		{"no boot ID in the guest", "kernel " + kataBoot + "\nboot \nSeccomp:\t0\n", "not a boot ID", nil},
		{"a node with no boot ID", kataAnswer, "reports no boot ID", func(f *fakeAPI) { f.nodeBoot = "" }},
		{"a pod with no node", kataAnswer, "names node", func(f *fakeAPI) { f.podHook = func(pd *pod) { pd.Spec.NodeName = "" } }},
		{"an unreadable node", kataAnswer, "read node node-2", func(f *fakeAPI) { f.podHook = func(pd *pod) { pd.Spec.NodeName = "node-2" } }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, api, sd := testProvider(t)
			api.handler = "kata-clh-runtime-rs"
			sd.tierAnswer = c.answer
			if c.api != nil {
				c.api(api)
			}
			_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			if err == nil || refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), c.want) || len(sd.starts) != 0 {
				t.Fatalf("a snippet: %v; %d starts", err, len(sd.starts))
			}
			drained(t, p)
		})
	}
}

// Under the vm tier no volume keeps its size limit (Kata mounts each memory-backed emptyDir
// as a tmpfs of the VM's own), so a disk budget is refused at Preflight rather than
// promised; the same budget is accepted under gVisor.
func TestTheVMTierRefusesADiskBudget(t *testing.T) {
	p, api, _ := testProvider(t)
	p.cfg.DiskMB = 256
	if err := p.Preflight(context.Background()); err != nil {
		t.Fatalf("gVisor with a budget: %v", err)
	}
	api.handler = "kata-clh"
	if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "SANDBOX_DISK_MB is 256") {
		t.Fatalf("Kata with a budget: %v", err)
	}
}
