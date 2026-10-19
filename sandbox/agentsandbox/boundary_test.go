package agentsandbox

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

func TestClaimedPodKeepsTheProvenBoundary(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*pod)
	}{
		{"symlinked termination path and added root", func(pd *pod) {
			pd.Spec.Containers[0].VolumeMounts = append(pd.Spec.Containers[0].VolumeMounts, volumeMount{Name: "work", MountPath: "/run"})
			pd.Spec.Containers[0].TerminationMessagePath = "/var/run/termination-log"
		}},
		{"termination path alone", func(pd *pod) { pd.Spec.Containers[0].TerminationMessagePath = "/var/run/termination-log" }},
		{"another volume limit", func(pd *pod) {
			pd.Spec.Volumes[0]["emptyDir"] = json.RawMessage(`{"medium":"Memory","sizeLimit":"1Gi"}`)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, api, sd := testProvider(t)
			if err := p.Preflight(context.Background()); err != nil {
				t.Fatal(err)
			}
			p.mu.Lock()
			p.proven = p.templateSum
			p.mu.Unlock()
			if err := p.bindPolicies(context.Background()); err != nil {
				t.Fatal(err)
			}
			api.podHook = c.change
			_, snippetErr := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			_, projectErr := p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "x.js", Content: "1"}}, Steps: []string{"node x.js"}})
			for _, err := range []error{snippetErr, projectErr} {
				if err == nil || refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "execution boundary differs") {
					t.Fatalf("unproved pod: %v", err)
				}
			}
			drained(t, p)
			if sd.tierChecks != 0 || len(sd.starts) != 0 {
				t.Fatalf("dispatched to changed pod: %d checks, %d guests", sd.tierChecks, len(sd.starts))
			}
		})
	}
}

func TestClaimedPodAllowsBenignDefaultsAndOrdering(t *testing.T) {
	p, api, sd := testProvider(t)
	api.podHook = func(pd *pod) {
		pd.Spec.NodeName = "another-node"
		pd.Spec.ServiceAccountName = "default"
		pd.Spec.SchedulerName = "default-scheduler"
		c := &pd.Spec.Containers[0]
		c.Resources.Requests = c.Resources.Limits
		c.TerminationMessagePolicy = "File"
		c.ReadinessProbe = &probe{PeriodSeconds: 2, TimeoutSeconds: 1, SuccessThreshold: 1, FailureThreshold: 3}
		slices.Reverse(c.VolumeMounts)
		slices.Reverse(c.SecurityContext.Capabilities.Add)
	}
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	drained(t, p)
	if len(sd.starts) != 1 {
		t.Fatalf("guest starts: %d", len(sd.starts))
	}
}

func TestEveryClaimChecksItsActualMountTable(t *testing.T) {
	for _, mounts := range []string{
		strings.Join(kataMounts, "\n") + "\n/dev/sda /work/termination-log ext4 rw 0 0\n",
		strings.Join(kataMounts, "\n") + "\n/dev/sda /work/escaped\\040name ext4 rw 0 0\n",
		"",
		strings.Join(kataMounts, "\n") + "\n/dev/sda /work ext4 rw 0 0\n",
		strings.Repeat("x", tierCheckBytes+1),
	} {
		p, _, sd := testProvider(t)
		sd.mountAnswer = mounts
		_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
		if err == nil || refusal(err) != sandbox.RefusalEnvironment {
			t.Fatalf("unsafe mount table dispatched: %v", err)
		}
		drained(t, p)
		if len(sd.starts) != 0 {
			t.Fatal("guest code started")
		}
	}
}

func TestClaimedPodCannotSubstituteAnImageBehindATag(t *testing.T) {
	p, api, _ := testProvider(t)
	p.cfg.Image = "example:test"
	api.tmplHook = func(s *podSpec) { s.Containers[0].Image = p.cfg.Image }
	changed := false
	api.podHook = func(pd *pod) {
		pd.Spec.Containers[0].Image = p.cfg.Image
		if changed {
			pd.Status.ContainerStatuses[0].ImageID = "example@sha256:" + strings.Repeat("a", 64)
		}
	}
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	drained(t, p)
	changed = true
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if err == nil || refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "image differs") {
		t.Fatalf("changed tag: %v", err)
	}
	drained(t, p)
}

// The actual kind gVisor pod reports 9p for a memory-backed emptyDir. That
// representation is valid at the kernel tier; it cannot establish a VM's own tmpfs.
func TestPodMountProofFollowsTheVerifiedTier(t *testing.T) {
	shared := []string{"none / 9p ro 0 0", "none /work 9p rw 0 0", "shm /dev/shm tmpfs rw 0 0"}
	roots := []string{"/work", "/dev/shm"}
	for _, tier := range []sandbox.IsolationClass{sandbox.IsolationKernel, sandbox.IsolationContainer, sandbox.IsolationVM} {
		err := checkPodMounts(tier, shared, roots)
		if (tier == sandbox.IsolationKernel) != (err == nil) {
			t.Fatalf("9p at %s: %v", tier, err)
		}
		nested := append(slices.Clone(shared), "/dev/sda /work/log ext4 rw 0 0")
		if err := checkPodMounts(tier, nested, roots); err == nil {
			t.Fatalf("nested mount accepted at %s", tier)
		}
	}
}
