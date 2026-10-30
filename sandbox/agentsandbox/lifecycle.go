package agentsandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
)

const (
	// Claim labels: every claim this provider makes says it is plimsoll's, which
	// instance made it, and how long its run may take (seconds), so ReconcileOrphans can
	// find a crashed instance's leftovers. The same names the openshell provider uses.
	runLabel      = "plimsoll.run"
	instanceLabel = "plimsoll.instance"
	lifetimeLabel = "plimsoll.lifetime"
	// staleMargin is how long past its declared lifetime another instance's claim is
	// left alone, and how long past the run's end the claim's own shutdown time falls:
	// the controller deletes a claim at its shutdownTime (policy Delete), which bounds a
	// leak by itself, and the margin keeps clock skew from ending a live run.
	staleMargin = 5 * time.Minute
	// maxSkew is how far the API server's clock may be from this process's before a
	// claim is refused: past it, the claim's shutdownTime could fall inside its own run.
	maxSkew = time.Minute
	// deleteBudget bounds one claim's delete, retries included.
	deleteBudget = 60 * time.Second
	maxListPages = 50
	pollEvery    = 50 * time.Millisecond
)

// box is one claimed sandbox, read back.
type box struct {
	claim       string
	ip          string
	environment string // the digest of the image the pod runs
	tier        sandbox.IsolationClass
	node        string   // the node the pod runs on
	roots       []string // writable roots from this actual pod, not the template
	instance    string   // "k8s-pod-uid:" and the UID the API server gave the pod
}

// claimSandbox makes one claim on the warm pool for a run of at most lifetime, waits for
// its sandbox's pod, and reads the pod back. The claim's name is chosen and tracked before
// the create is sent, so the caller deletes it (deleteLater) whenever b.claim is set,
// whatever the error: a create whose answer was lost may still have made it.
func (p *Provider) claimSandbox(ctx context.Context, lifetime time.Duration) (b box, err error) {
	b.claim = "plimsoll-" + randHex(8)
	p.leases.Track(b.claim)
	issued := time.Now()
	c := claim{
		APIVersion: "extensions.agents.x-k8s.io/v1beta1", Kind: "SandboxClaim",
		Meta: objectMeta{Name: b.claim, Labels: map[string]string{
			runLabel: "1", instanceLabel: p.instance, lifetimeLabel: strconv.Itoa(int(lifetime.Seconds()) + 1)}},
	}
	c.Spec.WarmPoolRef.Name = p.cfg.WarmPool
	c.Spec.Lifecycle = &claimLifecycle{ShutdownTime: issued.Add(lifetime + staleMargin).UTC().Format(time.RFC3339), ShutdownPolicy: "Delete"}
	var made claim
	if err := p.kube.do(ctx, http.MethodPost, claimsPath(p.cfg.Namespace), nil, c, &made); err != nil {
		return b, fmt.Errorf("agentsandbox: create claim: %w", err)
	}
	if made.Meta.CreationTimestamp != nil {
		skew, ok := clockSkew(issued, time.Now(), *made.Meta.CreationTimestamp)
		p.noteSkew(skew)
		if !ok {
			return b, fmt.Errorf("agentsandbox: the API server's clock is %s from this process's (more than %s)", skew.Round(time.Second), maxSkew)
		}
	}
	for {
		var cur claim
		if err := p.kube.get(ctx, claimPath(p.cfg.Namespace, b.claim), &cur); err != nil {
			return b, fmt.Errorf("agentsandbox: read claim: %w", err)
		}
		if conditionTrue(cur.Status.Conditions, "Ready") && cur.Status.Sandbox.Name != "" && len(cur.Status.Sandbox.PodIPs) > 0 {
			return p.readBack(ctx, b, cur)
		}
		if err := providerkit.Sleep(ctx, pollEvery); err != nil {
			return b, fmt.Errorf("agentsandbox: claim %s not ready: %w", b.claim, err)
		}
	}
}

// readBack checks the claim's sandbox and pod before any code is sent, and returns the
// box with the pod's address and the evidence for its tier.
func (p *Provider) readBack(ctx context.Context, b box, c claim) (box, error) {
	if !validName(c.Status.Sandbox.Name) {
		return b, fmt.Errorf("agentsandbox: claim %s names sandbox %q", b.claim, c.Status.Sandbox.Name)
	}
	var sb sandboxObject
	if err := p.kube.get(ctx, sandboxPath(p.cfg.Namespace, c.Status.Sandbox.Name), &sb); err != nil {
		return b, fmt.Errorf("agentsandbox: read sandbox: %w", err)
	}
	if !sb.Meta.controlledBy("SandboxClaim", c.Meta.UID) {
		return b, fmt.Errorf("agentsandbox: sandbox %s is not controlled by claim %s", sb.Meta.Name, b.claim)
	}
	if ref := sb.Meta.Annotations["agents.x-k8s.io/sandbox-template-ref"]; ref != p.templateName() {
		return b, fmt.Errorf("agentsandbox: sandbox %s comes from template %q, not %q", sb.Meta.Name, ref, p.templateName())
	}
	// The pod carries its sandbox's name unless the sandbox names another (a pod adopted
	// before agent-sandbox's warm pool made full Sandbox objects).
	podName := sb.Meta.Name
	if n := sb.Meta.Annotations["agents.x-k8s.io/pod-name"]; n != "" {
		podName = n
	}
	if !validName(podName) {
		return b, fmt.Errorf("agentsandbox: sandbox %s names pod %q", sb.Meta.Name, podName)
	}
	var pd pod
	if err := p.kube.get(ctx, podPath(p.cfg.Namespace, podName), &pd); err != nil {
		return b, fmt.Errorf("agentsandbox: read pod: %w", err)
	}
	fail := func(err error) (box, error) {
		return b, fmt.Errorf("agentsandbox: pod %s: %w", podName, err)
	}
	if !pd.Meta.controlledBy("Sandbox", sb.Meta.UID) || pd.Meta.DeletionTimestamp != nil || pd.Status.Phase != "Running" {
		return fail(errors.New("not a running pod of the claimed sandbox"))
	}
	tier, err := p.runtimeTier(ctx)
	if err != nil {
		return b, err
	}
	if err := p.checkPodSpec(pd.Spec, tier); err != nil {
		return fail(err)
	}
	if err := p.checkPodBoundary(pd.Spec); err != nil {
		return fail(err)
	}
	mounts, err := podMounts(pd.Spec)
	if err != nil {
		return fail(err)
	}
	roots, err := writableRoots(mounts)
	if err != nil {
		return fail(err)
	}
	if len(pd.Status.ContainerStatuses) != 1 || !pd.Status.ContainerStatuses[0].Ready {
		return fail(errors.New("sandboxd is not ready"))
	}
	m := imageDigestRE.FindStringSubmatch(pd.Status.ContainerStatuses[0].ImageID)
	if m == nil {
		return fail(fmt.Errorf("image ID %q names no digest", pd.Status.ContainerStatuses[0].ImageID))
	}
	if d, ok := pinnedDigest(p.cfg.Image); ok && d != m[1] {
		return fail(fmt.Errorf("it runs image %s, not the pinned %s", m[1], d))
	}
	ip, err := podIP(c, pd)
	if err != nil {
		return fail(err)
	}
	policies, policySum, err := p.readPolicies(ctx)
	if err != nil {
		return b, err
	}
	if err := p.checkPolicySet(policySum); err != nil {
		return fail(err)
	}
	if err := p.checkNetworkPolicies(pd.Meta.Labels, policies); err != nil {
		return fail(err)
	}
	if tier == sandbox.IsolationVM && !validName(pd.Spec.NodeName) {
		return fail(fmt.Errorf("it names node %q", pd.Spec.NodeName))
	}
	if err := p.checkPodImage(m[1]); err != nil {
		return fail(err)
	}
	instance := sandbox.PodInstance(pd.Meta.UID)
	if instance == "" {
		return fail(fmt.Errorf("its UID %q is not a UID", pd.Meta.UID))
	}
	b.roots = roots
	b.ip, b.environment, b.tier, b.node, b.instance = ip, m[1], tier, pd.Spec.NodeName, instance
	return b, nil
}

// handlerTiers are the runtime class handlers plimsoll has run, and the tier each one
// claims: runsc (gVisor) the kernel tier, runc the container tier, and Kata Containers'
// Cloud Hypervisor shims, as kata-deploy 4.2.0 names them for the Go runtime and for
// runtime-rs, the vm tier (each pod its own VM and kernel; run on kind, 2026-10-18), and
// kata, the handler of AKS Pod Sandboxing's kata-vm-isolation class (Kata on Cloud
// Hypervisor over Hyper-V; run on AKS, 2026-10-18). kata is a generic name another cluster
// may map to another Kata shim; the per-pod check holds that one to the vm tier the same
// way. Any other handler is refused until plimsoll has tested it: Kata's QEMU shims never
// started a pod on kind (the agent in the VM did not answer within the shim's 10 s). An
// operator may declare further gVisor handlers (Config.RunscHandlers), which each provider
// adds to its own copy of this table at the kernel tier; this table is never written.
var handlerTiers = map[string]sandbox.IsolationClass{
	"runsc":               sandbox.IsolationKernel,
	"runc":                sandbox.IsolationContainer,
	"kata":                sandbox.IsolationVM,
	"kata-clh":            sandbox.IsolationVM,
	"kata-clh-runtime-rs": sandbox.IsolationVM,
}

// runtimeTier reads the runtime class, holds it to the one bound to the startup smoke test
// (checkClass), and returns the tier the provider's table gives its handler. Every check and every
// pod's read-back calls it, so a class replaced after startup is refused before a claim,
// and before any code if it changes between the check and the pod.
func (p *Provider) runtimeTier(ctx context.Context) (sandbox.IsolationClass, error) {
	rc, sum, err := p.readClass(ctx)
	if err != nil {
		return sandbox.IsolationUnknown, err
	}
	if err := p.checkClass(sum); err != nil {
		return sandbox.IsolationUnknown, err
	}
	if tier, ok := p.handlers[rc.Handler]; ok {
		return tier, nil
	}
	return sandbox.IsolationUnknown, fmt.Errorf("agentsandbox: runtime class %s has handler %q, which plimsoll has not tested and this daemon does not declare as gVisor (SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS)", p.cfg.RuntimeClass, truncate(rc.Handler, 80))
}

// readClass reads the runtime class and digests what the smoke test's proof depends on:
// its UID (a class deleted and made again under the same name is another object; the
// handler is immutable, so that is how a class's handler changes), the handler, and the
// overhead and scheduling, which decide where its pods run. Metadata such as labels is
// left out.
func (p *Provider) readClass(ctx context.Context) (runtimeClass, string, error) {
	var rc runtimeClass
	if err := p.kube.get(ctx, runtimeClassPath(p.cfg.RuntimeClass), &rc); err != nil {
		return rc, "", fmt.Errorf("agentsandbox: read runtime class: %w", err)
	}
	raw, err := json.Marshal(struct {
		UID        string          `json:"uid"`
		Handler    string          `json:"handler"`
		Overhead   json.RawMessage `json:"overhead,omitempty"`
		Scheduling json.RawMessage `json:"scheduling,omitempty"`
	}{rc.Meta.UID, rc.Handler, rc.Overhead, rc.Scheduling})
	if err != nil {
		return rc, "", fmt.Errorf("agentsandbox: runtime class %s: %w", p.cfg.RuntimeClass, err)
	}
	sum := sha256.Sum256(raw)
	return rc, hex.EncodeToString(sum[:]), nil
}

// checkClass refuses a runtime class other than the one bound to the startup smoke test.
// Once a difference is seen it stays a refusal until a restart, as a changed policy set
// does: pods the warm pool made from the other class may still be waiting.
func (p *Provider) checkClass(sum string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.classChanged || p.classSum != "" && sum != p.classSum {
		p.classChanged = true
		return fmt.Errorf("agentsandbox: runtime class %s changed from the one bound to the startup smoke test (its UID, handler, overhead or scheduling); restart plimsolld to prove it", p.cfg.RuntimeClass)
	}
	return nil
}

// bindClass fixes the runtime class before the smoke test's behavioral tests, and checks
// it again after them. It never replaces a class already bound to this provider instance.
func (p *Provider) bindClass(ctx context.Context) error {
	_, sum, err := p.readClass(ctx)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if p.classSum == "" {
		p.classSum = sum
	}
	p.mu.Unlock()
	return p.checkClass(sum)
}

// tierCheck is the first command plimsoll sends to a claimed pod, before any of the run's
// code, as the guest: the first line of the kernel log, the kernel's boot ID and the
// seccomp mode of the guest's processes. The pod is fresh, so nothing of a guest's has run
// in it yet.
var tierCheck = guestArgv(nil, "sh", "-c", `printf 'kernel %s\n' "$(dmesg 2>/dev/null | head -n 1)"; printf 'boot %s\n' "$(cat /proc/sys/kernel/random/boot_id)"; grep '^Seccomp:' /proc/self/status; printf 'mounts\n'; cat /proc/mounts`)

// tierCheckBytes gives the mount table headroom over the measured 2 KiB kind report,
// while bounding metadata before any guest code. A larger report fails closed.
const tierCheckBytes = 64 << 10

// proveTier holds a claimed pod to its tier from inside, with the smoke test's kernel and
// seccomp checks. The read-back reads the runtime class's handler, a name each node maps to
// a runtime in configuration the API does not show, and the startup smoke test proves that
// mapping only on the nodes its two pods landed on. Live on kind (2026-10-18), with the
// node's runsc handler remapped to runc after startup, a daemon whose smoke test had passed
// under gVisor signed a run at the kernel tier that ran on the host's kernel with no seccomp
// filter. Under the vm tier the guest's boot ID is also compared with the one its node's
// kubelet reports, read from the node object. A pod that fails is refused before any code
// is sent.
func (p *Provider) proveTier(ctx context.Context, b box) error {
	out, err := p.exec(ctx, b.ip, tierCheck, nil, tierCheckBytes, tierCheckBytes)
	if err != nil {
		return fmt.Errorf("agentsandbox: claim %s: tier check: %w", b.claim, err)
	}
	t, ok := parseTierCheck(out.stdout)
	if out.exitCode != 0 || out.stdoutTruncated || !ok {
		return fmt.Errorf("agentsandbox: claim %s: tier check exited %d with %q", b.claim, out.exitCode, truncate(out.stdout, 120))
	}
	nodeBoot := ""
	if b.tier == sandbox.IsolationVM {
		var n node
		if err := p.kube.get(ctx, nodePath(b.node), &n); err != nil {
			return fmt.Errorf("agentsandbox: claim %s: read node %s for its boot ID: %w", b.claim, b.node, err)
		}
		nodeBoot = n.Status.NodeInfo.BootID
	}
	if err := errors.Join(checkKernel(b.tier, t.kernel), checkSeccompMode(b.tier, t.seccomp), checkOwnKernel(b.tier, t.boot, nodeBoot), checkPodMounts(b.tier, t.mounts, b.roots)); err != nil {
		return fmt.Errorf("agentsandbox: claim %s: %w", b.claim, err)
	}
	return nil
}

// parseTierCheck reads the three identity lines and the complete mount table.
func parseTierCheck(stdout []byte) (t tierReport, ok bool) {
	lines := strings.Split(strings.TrimSuffix(string(stdout), "\n"), "\n")
	if len(lines) < 5 || lines[3] != "mounts" || !strings.HasPrefix(lines[0], "kernel ") || !strings.HasPrefix(lines[1], "boot ") || !strings.HasPrefix(lines[2], "Seccomp:") {
		return t, false
	}
	return tierReport{kernel: strings.TrimPrefix(lines[0], "kernel "), boot: strings.TrimPrefix(lines[1], "boot "),
		seccomp: strings.TrimSpace(strings.TrimPrefix(lines[2], "Seccomp:")), mounts: lines[4:]}, true
}

// tierReport is what the tier check reads in the guest.
type tierReport struct {
	mounts  []string // complete /proc/mounts from the claimed pod
	kernel  string   // the kernel log's first line, empty when the guest cannot read it
	boot    string   // the guest kernel's boot ID
	seccomp string   // the seccomp mode of the guest's processes
}

// deleteLater deletes the claim off the caller's path and holds the run's admitted
// capacity until the pod is gone (sandbox.HoldCapacity, providerkit.Quarantine): the pod,
// and anything the run left running in it, lives until then. Call it before the call
// returns.
func (p *Provider) deleteLater(ctx context.Context, b box) {
	hold := sandbox.HoldCapacity(ctx)
	p.cleanup.Hold(b.claim, func() {
		hold()
		// Drain seeing no lease also means the admitted capacity has been returned.
		p.leases.Untrack(b.claim)
	})
	go p.destroy(b.claim)
}

// destroy deletes a claim in the foreground, so the claim lasts until its sandbox and pod
// are gone, and waits for that, retrying. Failure leaves both its lease and capacity held
// for ReconcileOrphans, which retries pending deletions independently of their timestamps.
func (p *Provider) destroy(name string) {
	n, err := providerkit.Delete(p.deleteTimeout, func(ctx context.Context) error { return p.deleteAndWait(ctx, name) })
	if !p.cleanup.Done(name, err == nil) {
		slog.Error("agentsandbox: claim deletion pending; capacity held until ReconcileOrphans confirms it gone", "claim", name, "attempts", n, "error", err)
	}
}

func (p *Provider) deleteAndWait(ctx context.Context, name string) error {
	err := p.kube.do(ctx, http.MethodDelete, claimPath(p.cfg.Namespace, name), nil,
		map[string]string{"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground"}, nil)
	if err != nil && !isNotFound(err) {
		return err
	}
	for {
		err := p.kube.get(ctx, claimPath(p.cfg.Namespace, name), &claim{})
		if isNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := providerkit.Sleep(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
}

// Drain waits until no claim this provider made is left undeleted, or ctx ends. A daemon
// calls it on shutdown, after it stops accepting runs.
func (p *Provider) Drain(ctx context.Context) error {
	for p.leases.Len() > 0 {
		if err := providerkit.Sleep(ctx, 50*time.Millisecond); err != nil {
			return fmt.Errorf("agentsandbox: claims still undeleted: %v: %w", p.leases.Keys(), err)
		}
	}
	return nil
}

// ReconcileOrphans deletes the plimsoll claims no live run can be using: this instance's
// pending deletions (capacity still held), its own that no run tracks, and
// another instance's once the API server's creation time plus the lifetime it declared
// plus staleMargin has passed, read on the API server's clock. One with no valid
// declaration is never touched, and none of another instance's is before a create has
// measured the clocks. It returns confirmed pending deletions plus orphan deletions the
// API server accepted. A pending claim already absent from a list is still checked by name.
func (p *Provider) ReconcileOrphans(ctx context.Context) (int, error) {
	deleted, pendingErr := p.cleanup.Retry(func(name string) error {
		dctx, cancel := context.WithTimeout(ctx, p.deleteTimeout)
		defer cancel()
		return p.deleteAndWait(dctx, name)
	})
	if pendingErr != nil {
		pendingErr = fmt.Errorf("agentsandbox: claim deletion pending: %w", pendingErr)
	}
	cont := ""
	for page := 0; page < maxListPages; page++ {
		q := url.Values{"labelSelector": {runLabel + "=1"}, "limit": {"100"}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var l claimList
		if err := p.kube.do(ctx, http.MethodGet, claimsPath(p.cfg.Namespace), q, nil, &l); err != nil {
			return deleted, errors.Join(pendingErr, fmt.Errorf("agentsandbox: list claims: %w", err))
		}
		for _, c := range l.Items {
			if !p.orphaned(c, time.Now()) {
				continue
			}
			err := p.kube.do(ctx, http.MethodDelete, claimPath(p.cfg.Namespace, c.Meta.Name), nil,
				map[string]string{"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground"}, nil)
			if err != nil && !isNotFound(err) {
				slog.Error("agentsandbox: failed to delete orphaned claim", "claim", c.Meta.Name, "error", err)
				continue
			}
			slog.Warn("agentsandbox: deleted orphaned claim", "claim", c.Meta.Name, "instance", c.Meta.Labels[instanceLabel])
			deleted++
		}
		if cont = l.Metadata.Continue; cont == "" {
			return deleted, pendingErr
		}
	}
	return deleted, errors.Join(pendingErr, fmt.Errorf("agentsandbox: list claims: more than %d pages", maxListPages))
}

func (p *Provider) orphaned(c claim, now time.Time) bool {
	labels := c.Meta.Labels
	if labels[runLabel] != "1" || !validName(c.Meta.Name) {
		return false
	}
	if labels[instanceLabel] == p.instance {
		return !p.leases.Tracked(c.Meta.Name)
	}
	secs, err := strconv.ParseUint(labels[lifetimeLabel], 10, 32)
	if err != nil || secs == 0 || c.Meta.CreationTimestamp == nil {
		return false
	}
	skew, known := p.apiSkew()
	if !known {
		return false
	}
	return now.Add(skew).After(c.Meta.CreationTimestamp.Add(time.Duration(secs)*time.Second + staleMargin))
}

// clockSkew estimates the API server's clock minus this process's from one create: the
// server stamped the claim between issued and ready on its own clock, in whole seconds, so
// a time inside that window (widened by a second) is no skew. ok is false past maxSkew.
func clockSkew(issued, ready, created time.Time) (time.Duration, bool) {
	var skew time.Duration
	switch {
	case created.Before(issued.Add(-time.Second)):
		skew = created.Sub(issued.Add(-time.Second))
	case created.After(ready.Add(time.Second)):
		skew = created.Sub(ready.Add(time.Second))
	}
	return skew, skew <= maxSkew && skew >= -maxSkew
}

type skewNote struct {
	mu    sync.Mutex
	skew  time.Duration
	known bool
}

func (p *Provider) noteSkew(d time.Duration) {
	p.skew.mu.Lock()
	p.skew.skew, p.skew.known = d, true
	p.skew.mu.Unlock()
}

func (p *Provider) apiSkew() (time.Duration, bool) {
	p.skew.mu.Lock()
	defer p.skew.mu.Unlock()
	return p.skew.skew, p.skew.known
}
