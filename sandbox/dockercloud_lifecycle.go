package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	pathpkg "path"
	"strconv"
	"strings"
	"time"
)

// requestedSize is the CPU count and memory a create asks for: the operator's
// envelope, or the Micro size where it is unset.
func (d *DockerCloud) requestedSize() (uint32, int) {
	cpus, memMiB := uint32(d.MaxVCPU), d.MaxMemoryMB
	if cpus == 0 {
		cpus = dcDefaultCPUs
	}
	if memMiB == 0 {
		memMiB = dcDefaultMemoryMiB
	}
	return cpus, memMiB
}

// ---- lifecycle ----

// dcVM is a live sandbox handle. name is ours and known before create; id and
// endpoint come from the service.
type dcVM struct {
	name     string
	id       string
	endpoint string
}

func (d *DockerCloud) instance() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.instanceID == "" {
		d.instanceID = randID()
	}
	return d.instanceID
}

func (d *DockerCloud) namePrefix() string { return dcNamePrefix + d.instance() + "-" }

// create starts a sandbox, waits for it to run, and verifies it. Deny-all egress
// comes from the account's cloud network policy, not from the request (see
// dcConnect.createSandbox); every run reads the effective policy back before any
// guest code runs (verifyEgressDenied). On any failure after the request is sent it deletes
// the sandbox by name, since the service may have created it even when the answer
// never arrived.
//
// While the create's outcome is unknown (its answer is not a refusal, or its
// operation is still running when the run gives up), a delete that finds no sandbox
// proves nothing: the create can still finish after it, and that sandbox bills until
// the next reconciliation or its TTL. So unless the delete removed the sandbox, the
// run is charged as one whose delete gave up (TeardownGaveUp).
func (d *DockerCloud) create(ctx context.Context, budget time.Duration) (dcVM, error) {
	vm := dcVM{name: d.namePrefix() + randID()}
	d.leases.Track(vm.name) // before the request, so the reconciler never races this create
	ok, unknown, unsent := false, false, false
	defer func() {
		switch {
		case ok:
		case unsent:
			d.leases.Untrack(vm.name) // nothing was sent, so nothing can exist
		case !d.destroy(ctx, vm) && unknown:
			slog.Error("dockercloud: a create whose outcome is unknown left no sandbox to delete; it may still appear, and orphan reconciliation or its cloud TTL will reap it",
				"sandbox", vm.name)
			TeardownGaveUp(ctx)
		}
	}()

	cpus, memMiB := d.requestedSize()
	reported, err := d.wire().createSandbox(ctx, dcCreateSpec{
		name:      vm.name,
		image:     strings.TrimSpace(d.Image),
		startCmd:  dcStartCmd,
		ttl:       budget + dcTTLSlack,
		cpus:      cpus,
		memoryMiB: memMiB,
	})
	if err != nil {
		unsent, unknown = dcCreateOutcome(err)
		var ce *dcCreateError
		if errors.As(err, &ce) {
			vm.id = ce.id // the cleanup deletes by ID when the service named one
		}
		return dcVM{}, err
	}
	sb := reported.view()
	vm.id = sb.id
	if vm.id == "" {
		return dcVM{}, errors.New("dockercloud create sandbox: running sandbox has no id")
	}
	if sb.name != "" && sb.name != vm.name {
		return dcVM{}, fmt.Errorf("dockercloud create sandbox: service reports name %q, requested %q", sb.name, vm.name)
	}
	if err := d.verifySandbox(reported); err != nil {
		return dcVM{}, err
	}
	vm.endpoint = strings.TrimRight(sb.endpoint, "/")
	ok = true
	return vm, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// verifySandbox checks what the service reports about a new sandbox before any
// guest code runs: an endpoint the token may be sent to, resources within the
// configured maximum, and (when the image is pinned) the digest it booted.
func (d *DockerCloud) verifySandbox(reported dcReported) error {
	sb := reported.view()
	if sb.endpoint == "" {
		return errors.New("dockercloud create sandbox: no sandbox endpoint reported")
	}
	if sb.endpointRefused != nil {
		return sb.endpointRefused
	}
	if _, err := parseDockerCloudURL(sb.endpoint, "sandbox endpoint"); err != nil {
		return fmt.Errorf("dockercloud create sandbox: %w", err)
	}
	// Checked against what was requested, including the Micro default when the
	// operator set no envelope: a sandbox that reports no size, or a larger one than
	// requested, is refused (it could bill, or hold, more than asked for).
	wantCPU, wantMiB := d.requestedSize()
	if sb.cpus == nil || sb.memoryMiB == nil {
		return errors.New("dockercloud verify resources: sandbox reports no CPU or memory size")
	}
	if *sb.cpus == 0 || uint64(*sb.cpus) > uint64(wantCPU) {
		return fmt.Errorf("dockercloud sandbox exceeds CPU cap: reported %v, requested %d", derefUint(sb.cpus), wantCPU)
	}
	if *sb.memoryMiB == 0 || uint64(*sb.memoryMiB) > uint64(wantMiB) {
		return fmt.Errorf("dockercloud sandbox exceeds memory cap: reported %v MiB, requested %d", derefUint(sb.memoryMiB), wantMiB)
	}
	if image := strings.TrimSpace(d.Image); isDigestPinned(image) {
		want := image[strings.LastIndex(image, "@")+1:]
		if !sb.reportsBootedDigest {
			// The REST API reports no booted digest (probe 2026-10-04), so the most it
			// can show is that the service recorded the pinned reference it was sent.
			// That is the request, not evidence of what booted: hardened mode needs the
			// Connect transport, which reports the booted digest.
			if !strings.HasSuffix(strings.ToLower(sb.recordedImage), "@"+strings.ToLower(want)) {
				return fmt.Errorf("dockercloud sandbox recorded image %q, configured %s", truncateForError(sb.recordedImage), image)
			}
			return nil
		}
		// A pinned image is a claim about what boots, so it needs evidence: a
		// sandbox that reports no booted digest is refused, not waved through.
		if sb.imageDigest == "" {
			return errors.New("dockercloud sandbox reported no booted image digest; cannot prove the pinned image is the one running")
		}
		if !strings.EqualFold(sb.imageDigest, want) {
			// The cloud reports the platform manifest it booted, not a multi-platform
			// index (verified 2026-09-24: an index pin booted its linux/amd64 entry).
			return fmt.Errorf("dockercloud sandbox booted image digest %s, configured %s; pin the image's linux/amd64 manifest digest, not a multi-platform index", sb.imageDigest, want)
		}
	}
	return nil
}

func derefUint(p *protoUint) string {
	if p == nil {
		return "nothing"
	}
	return strconv.FormatUint(uint64(*p), 10)
}

// destroy deletes the sandbox, retrying, on its own context so it still runs after
// the run's context is cancelled or expired. A NOT_FOUND is success. The name is
// untracked whatever happens: once the run is over, anything still alive under
// this instance's name prefix is an orphan, and ReconcileOrphans (or the cloud TTL)
// reaps it. removed reports that a delete operation completed for a sandbox that
// existed; a NOT_FOUND and a delete that gave up both leave it false.
func (d *DockerCloud) destroy(ctx context.Context, vm dcVM) (removed bool) {
	defer d.leases.Untrack(vm.name)
	const attempts = meteredDeleteAttempts
	for i := 0; i < attempts; i++ {
		attempt, cancel := context.WithTimeout(context.Background(), meteredDeleteBudget)
		existed, err := d.wire().deleteSandbox(attempt, vm, "delete-"+vm.name)
		cancel()
		if err == nil {
			return existed
		}
		if i == attempts-1 {
			slog.Error("dockercloud: failed to delete sandbox; orphan reconciliation or its cloud TTL will reap it",
				"sandbox", vm.name, "id", vm.id, "attempts", attempts, "error", err)
			TeardownGaveUp(ctx) // it bills until that TTL: the run's deadline plus 30 s
			return false
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	return false
}

// ReconcileOrphans deletes every sandbox named with this instance's prefix that no
// run is tracking: a create whose answer never arrived and whose delete-by-name
// also failed, or a teardown whose retries all failed. Names are tracked before a
// create is sent, so an in-flight run is never touched, and sandboxes of other
// instances (even under the same token) never match the prefix.
func (d *DockerCloud) ReconcileOrphans(ctx context.Context) (int, error) {
	if strings.TrimSpace(d.Token) == "" {
		return 0, errors.New("DOCKER_SBX_TOKEN is not set")
	}
	prefix := d.namePrefix()
	deleted := 0
	token := ""
	for page := 0; page < dcMaxListPages; page++ {
		sandboxes, next, err := d.wire().listSandboxes(ctx, token)
		if err != nil {
			return deleted, fmt.Errorf("dockercloud list sandboxes: %w", err)
		}
		for _, sb := range sandboxes {
			name := sb.name
			if !strings.HasPrefix(name, prefix) || d.leases.Tracked(name) {
				continue
			}
			if _, err := d.wire().deleteSandbox(ctx, dcVM{name: name, id: sb.id}, "reap-"+name); err != nil {
				slog.Error("dockercloud: failed to delete orphaned sandbox", "sandbox", name, "error", err)
				continue
			}
			slog.Warn("dockercloud: deleted orphaned sandbox", "sandbox", name, "created_at", sb.createdAt)
			deleted++
		}
		if next == "" {
			return deleted, nil
		}
		token = next
	}
	return deleted, fmt.Errorf("dockercloud list sandboxes: more than %d pages", dcMaxListPages)
}

// ---- startup smoke test ----

// SmokeTest proves the configured account, image and endpoint serve this provider's
// contract by exercising one throwaway sandbox end to end: capabilities, create
// with the deny-all policy, the effective policy read back, directory creation and
// upload into the project dir, and a probe run through the exact project-step path
// (the exec wrapper around `sh <script>`), which reports the node runtime, the
// working directory and, from inside the guest, whether egress is really denied;
// then a hung command and a flood prove the in-guest time limit and output cap.
// It creates one billable sandbox, so the daemon runs it once at startup and never
// on a poll path.
func (d *DockerCloud) SmokeTest(ctx context.Context) error {
	if err := d.Preflight(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, dcSmokeTimeout)
	defer cancel()
	if err := d.wire().checkCapabilities(ctx); err != nil {
		return fmt.Errorf("dockercloud smoke: %w", err)
	}
	vm, err := d.create(ctx, remainingBudget(ctx, dcSmokeTimeout))
	if err != nil {
		return fmt.Errorf("dockercloud smoke: %w", err)
	}
	defer d.destroy(ctx, vm)
	if err := d.verifyEgressDenied(ctx, vm); err != nil {
		return fmt.Errorf("dockercloud smoke: %w", err)
	}
	dir := d.projectDir()
	const stepPath = "/tmp/plimsoll-smoke-step.sh"
	if err := d.mkdirs(ctx, vm, map[string]struct{}{dir: {}}); err != nil {
		return fmt.Errorf("dockercloud smoke: create project dir: %w", err)
	}
	files := []File{
		{Path: pathpkg.Join(dir, "plimsoll-smoke.cjs"), Content: vmSmokeProbe},
		{Path: stepPath, Content: "node plimsoll-smoke.cjs\n"},
	}
	if err := d.wire().upload(ctx, vm, files); err != nil {
		return fmt.Errorf("dockercloud smoke: stage probe: %w", err)
	}
	out, err := d.execGuarded(ctx, vm, []string{"sh", stepPath}, dir)
	if err != nil {
		return fmt.Errorf("dockercloud smoke: run probe: %w", err)
	}
	if out.exitCode != 0 {
		// 127 is the missing-tool signature: sh could not find node or timeout.
		return fmt.Errorf("dockercloud smoke: probe exited %d on image %q (an image missing node, timeout or head cannot serve runs): %s",
			out.exitCode, d.Image, strings.TrimSpace(out.stderr))
	}
	var report struct {
		Node       string   `json:"node"`
		Cwd        string   `json:"cwd"`
		EgressOpen []string `json:"egressOpen"`
	}
	if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
		return fmt.Errorf("dockercloud smoke: unparseable probe report %q: %w", out.stdout, err)
	}
	if report.Node == "" {
		return errors.New("dockercloud smoke: probe reported no node version")
	}
	if report.Cwd != dir {
		return fmt.Errorf("dockercloud smoke: probe ran in %q, not the project dir %q; the step working directory is not honored", report.Cwd, dir)
	}
	if len(report.EgressOpen) > 0 {
		return fmt.Errorf("dockercloud smoke: egress is OPEN to %s; the deny-all network policy is not in force", strings.Join(report.EgressOpen, ", "))
	}

	// The bounds the API does not give must actually hold in this guest. busybox
	// `timeout` fails open when kill(2) is refused (its watcher reads the error as
	// "the process is gone"), so a hung command must really be killed at the limit,
	// and a flood must really be capped.
	hang, err := d.execLimited(ctx, vm, []string{"sleep", "30"}, "", 1)
	if err != nil {
		return fmt.Errorf("dockercloud smoke: time-limit probe: %w", err)
	}
	if !hang.timedOut {
		return fmt.Errorf("dockercloud smoke: the in-guest time limit is not in force (sleep exited %d instead of being killed at 1s)", hang.exitCode)
	}
	flood, err := d.execLimited(ctx, vm, []string{"yes"}, "", 10)
	if err != nil {
		return fmt.Errorf("dockercloud smoke: output-cap probe: %w", err)
	}
	if !flood.stdoutTruncated || flood.exitCode == 0 || len(flood.stdout) != d.maxOutput() {
		return fmt.Errorf("dockercloud smoke: the in-guest output cap is not in force (exit %d, %d bytes, truncated=%v)",
			flood.exitCode, len(flood.stdout), flood.stdoutTruncated)
	}
	return nil
}
