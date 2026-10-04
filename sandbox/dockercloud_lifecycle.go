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

// ref is the SandboxRef JSON for this sandbox: by id once known, else by name.
func (vm dcVM) ref() map[string]string {
	if vm.id != "" {
		return map[string]string{"id": vm.id}
	}
	return map[string]string{"name": vm.name}
}

type dcSandbox struct {
	Core struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Status    protoEnum `json:"status"`
		CreatedAt time.Time `json:"createdAt"`
		Resources *struct {
			Cpus      *protoUint `json:"cpus"`
			MemoryMib *protoUint `json:"memoryMib"`
		} `json:"resources"`
		Endpoint *struct {
			URI      string    `json:"uri"`
			Protocol protoEnum `json:"protocol"`
		} `json:"endpoint"`
	} `json:"core"`
	Cloud *struct {
		ImageDigest string `json:"imageDigest"`
	} `json:"cloud"`
}

func (s dcSandbox) running() bool {
	return s.Core.Status.is("SANDBOX_STATUS_RUNNING", 3) && s.Core.Endpoint != nil && s.Core.Endpoint.URI != ""
}

func (s dcSandbox) terminal() bool {
	return s.Core.Status.is("SANDBOX_STATUS_FAILED", 6) || s.Core.Status.is("SANDBOX_STATUS_STOPPED", 5) || s.Core.Status.is("SANDBOX_STATUS_STOPPING", 4)
}

type dcOperation struct {
	ID    string `json:"id"`
	Done  bool   `json:"done"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Response json.RawMessage `json:"response"`
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
// comes from the account's cloud network policy, not from the request (see the
// comment in the body); every run reads the effective policy back before any
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

	in := map[string]any{
		"name":      vm.name,
		"requestId": vm.name,
		// No inline networkPolicies. Verified live on 2026-09-24: a create carrying
		// {"mode": NETWORK_POLICY_MODE_DENY_ALL} fails with Connect code 13
		// "internal error", although capabilities report can_attach_policies. The
		// account's cloud policy default supplies deny-all instead (the operator runs
		// `sbx --cloud policy init deny-all` once); with it in force the effective
		// policy reads DENY_ALL and, from inside the guest, HTTP is unreachable, TLS
		// is refused, a TCP connection is reset on its first byte and UDP gets no
		// answer. verifyEgressDenied refuses any sandbox where that is not so.
		"cloud": map[string]any{
			"imageRef":   strings.TrimSpace(d.Image),
			"startCmd":   dcStartCmd,
			"timeout":    protoDuration(budget + dcTTLSlack),
			"onTimeout":  "ON_TIMEOUT_DELETE",
			"autoResume": false,
			// Pinned so the booted platform, and with it the manifest digest checked in
			// verifySandbox, cannot change under the operator.
			"platform": map[string]any{"os": "linux", "architecture": "amd64"},
		},
	}
	// The service refuses a raw-image create without cpus (verified live
	// 2026-09-24: "'cpus' is required when using 'imageRef'"), so an unset
	// SANDBOX_CPUS or SANDBOX_MEMORY_MB requests the smallest size, Micro.
	cpus, memMiB := d.requestedSize()
	in["resources"] = map[string]any{
		"cpus":      cpus,
		"memoryMib": strconv.Itoa(memMiB), // uint64: a string in protojson
	}

	var op dcOperation
	if err := d.call(ctx, dcProcCreateSandbox, in, &op); err != nil {
		unsent = dcUnsent(err)
		unknown = !unsent && !dcRefused(err)
		return dcVM{}, fmt.Errorf("dockercloud create sandbox: %w", err)
	}
	op, err := d.waitOperation(ctx, op)
	if err != nil {
		unknown = true // the create's operation may still be running
		return dcVM{}, fmt.Errorf("dockercloud create sandbox: %w", err)
	}
	if op.Error != nil {
		return dcVM{}, fmt.Errorf("dockercloud create sandbox: operation failed (code %d): %s", op.Error.Code, truncateForError(op.Error.Message))
	}
	var sb dcSandbox
	if len(op.Response) == 0 || json.Unmarshal(op.Response, &sb) != nil || !sb.running() {
		// The operation's response is a google.protobuf.Any; if it does not already
		// carry a running sandbox, read the sandbox itself.
		sb, err = d.waitRunning(ctx, vm)
		if err != nil {
			return dcVM{}, err
		}
	}
	vm.id = sb.Core.ID
	if vm.id == "" {
		return dcVM{}, errors.New("dockercloud create sandbox: running sandbox has no id")
	}
	if sb.Core.Name != "" && sb.Core.Name != vm.name {
		return dcVM{}, fmt.Errorf("dockercloud create sandbox: service reports name %q, requested %q", sb.Core.Name, vm.name)
	}
	if err := d.verifySandbox(sb); err != nil {
		return dcVM{}, err
	}
	vm.endpoint = strings.TrimRight(sb.Core.Endpoint.URI, "/")
	ok = true
	return vm, nil
}

// waitOperation blocks until op is done, using WaitOperation's server-side wait
// and falling back to polling GetOperation where it is not served.
func (d *DockerCloud) waitOperation(ctx context.Context, op dcOperation) (dcOperation, error) {
	poll := false
	for !op.Done {
		if op.ID == "" {
			return op, errors.New("operation is not done and has no id to wait on")
		}
		if err := ctx.Err(); err != nil {
			return op, err
		}
		var next dcOperation
		if !poll {
			wait := min(remainingBudget(ctx, 10*time.Second), 10*time.Second)
			err := d.call(ctx, dcProcWaitOperation, map[string]any{"id": op.ID, "timeout": protoDuration(wait)}, &next)
			if dcCodeIs(err, "unimplemented") {
				poll = true
				continue
			}
			if err != nil {
				return op, err
			}
		} else {
			if err := sleepCtx(ctx, 250*time.Millisecond); err != nil {
				return op, err
			}
			if err := d.call(ctx, dcProcGetOperation, map[string]any{"id": op.ID}, &next); err != nil {
				return op, err
			}
		}
		op = next
	}
	return op, nil
}

// waitRunning polls GetSandbox until the sandbox runs with an endpoint.
func (d *DockerCloud) waitRunning(ctx context.Context, vm dcVM) (dcSandbox, error) {
	for {
		var sb dcSandbox
		if err := d.call(ctx, dcProcGetSandbox, map[string]any{"sandbox": vm.ref()}, &sb); err != nil {
			return dcSandbox{}, fmt.Errorf("dockercloud get sandbox: %w", err)
		}
		if sb.running() {
			return sb, nil
		}
		if sb.terminal() {
			return dcSandbox{}, fmt.Errorf("dockercloud create sandbox: sandbox reached status %s instead of running", sb.Core.Status)
		}
		if err := sleepCtx(ctx, 250*time.Millisecond); err != nil {
			return dcSandbox{}, err
		}
	}
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
func (d *DockerCloud) verifySandbox(sb dcSandbox) error {
	ep := sb.Core.Endpoint
	if ep == nil || ep.URI == "" {
		return errors.New("dockercloud create sandbox: no sandbox endpoint reported")
	}
	// Assumption (live probe): the cloud reports protocol CONNECT (or leaves it
	// unset). A unix-socket endpoint is the local backend's and is refused.
	if ep.Protocol != "" && !ep.Protocol.is("SANDBOX_ENDPOINT_PROTOCOL_CONNECT", 1) {
		return fmt.Errorf("dockercloud create sandbox: endpoint protocol %s is not Connect over HTTP", ep.Protocol)
	}
	if _, err := parseDockerCloudURL(ep.URI, "sandbox endpoint"); err != nil {
		return fmt.Errorf("dockercloud create sandbox: %w", err)
	}
	// Checked against what was requested, including the Micro default when the
	// operator set no envelope: a sandbox that reports no size, or a larger one than
	// requested, is refused (it could bill, or hold, more than asked for).
	wantCPU, wantMiB := d.requestedSize()
	r := sb.Core.Resources
	if r == nil || r.Cpus == nil || r.MemoryMib == nil {
		return errors.New("dockercloud verify resources: sandbox reports no CPU or memory size")
	}
	if *r.Cpus == 0 || uint64(*r.Cpus) > uint64(wantCPU) {
		return fmt.Errorf("dockercloud sandbox exceeds CPU cap: reported %v, requested %d", derefUint(r.Cpus), wantCPU)
	}
	if *r.MemoryMib == 0 || uint64(*r.MemoryMib) > uint64(wantMiB) {
		return fmt.Errorf("dockercloud sandbox exceeds memory cap: reported %v MiB, requested %d", derefUint(r.MemoryMib), wantMiB)
	}
	if image := strings.TrimSpace(d.Image); isDigestPinned(image) {
		// A pinned image is a claim about what boots, so it needs evidence: a
		// sandbox that reports no booted digest is refused, not waved through.
		if sb.Cloud == nil || sb.Cloud.ImageDigest == "" {
			return errors.New("dockercloud sandbox reported no booted image digest; cannot prove the pinned image is the one running")
		}
		want := image[strings.LastIndex(image, "@")+1:]
		if !strings.EqualFold(sb.Cloud.ImageDigest, want) {
			// The cloud reports the platform manifest it booted, not a multi-platform
			// index (verified 2026-09-24: an index pin booted its linux/amd64 entry).
			return fmt.Errorf("dockercloud sandbox booted image digest %s, configured %s; pin the image's linux/amd64 manifest digest, not a multi-platform index", sb.Cloud.ImageDigest, want)
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
		existed, err := d.deleteSandbox(attempt, vm.ref(), "delete-"+vm.name)
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

// deleteSandbox deletes one sandbox and waits for the deletion. A NOT_FOUND, from the
// call or its operation, is success with existed false: nothing was there to delete.
func (d *DockerCloud) deleteSandbox(ctx context.Context, ref map[string]string, requestID string) (existed bool, err error) {
	// DeleteSandbox answers an Operation; an accepted request is not a completed
	// deletion. Wait for it, and treat a failed operation as a failed delete so
	// destroy retries and the reaper does not count the sandbox as gone.
	var op dcOperation
	err = d.call(ctx, dcProcDeleteSandbox, map[string]any{"sandbox": ref, "force": true, "requestId": requestID}, &op)
	if dcCodeIs(err, "not_found") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	op, err = d.waitOperation(ctx, op)
	if dcCodeIs(err, "not_found") {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("dockercloud delete sandbox: %w", err)
	}
	if op.Error != nil {
		return false, fmt.Errorf("dockercloud delete sandbox: operation failed (code %d): %s", op.Error.Code, truncateForError(op.Error.Message))
	}
	return true, nil
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
		in := map[string]any{"pageSize": 100}
		if token != "" {
			in["pageToken"] = token
		}
		var out struct {
			Sandboxes     []dcSandbox `json:"sandboxes"`
			NextPageToken string      `json:"nextPageToken"`
		}
		if err := d.call(ctx, dcProcListSandboxes, in, &out); err != nil {
			return deleted, fmt.Errorf("dockercloud list sandboxes: %w", err)
		}
		for _, sb := range out.Sandboxes {
			name := sb.Core.Name
			if !strings.HasPrefix(name, prefix) || d.leases.Tracked(name) {
				continue
			}
			ref := map[string]string{"name": name}
			if sb.Core.ID != "" {
				ref = map[string]string{"id": sb.Core.ID}
			}
			if _, err := d.deleteSandbox(ctx, ref, "reap-"+name); err != nil {
				slog.Error("dockercloud: failed to delete orphaned sandbox", "sandbox", name, "error", err)
				continue
			}
			slog.Warn("dockercloud: deleted orphaned sandbox", "sandbox", name, "created_at", sb.Core.CreatedAt)
			deleted++
		}
		if out.NextPageToken == "" {
			return deleted, nil
		}
		token = out.NextPageToken
	}
	return deleted, fmt.Errorf("dockercloud list sandboxes: more than %d pages", dcMaxListPages)
}

// ---- startup smoke test ----

// dockerCloudRequiredPermissions are the owner-scope permissions a run needs.
var dockerCloudRequiredPermissions = []struct {
	name   string
	number int
}{
	{"PERMISSION_SANDBOXES_READ", 1},
	{"PERMISSION_SANDBOXES_CREATE", 2},
	// PERMISSION_SANDBOXES_EXEC and the FILES permissions are not required: the
	// cloud does not list them for a Cloud Sandboxes token, yet serves exec on the
	// sandbox endpoint (verified live 2026-09-24). The exec and upload calls fail
	// loudly if a token really lacks them.
	{"PERMISSION_SANDBOXES_DELETE", 9},
	{"PERMISSION_NETWORK_POLICIES_READ", 18},
}

// checkCapabilities asks the backend what it serves this token: the permissions a
// run needs and the resource range. Egress is not checked here; it is read back
// per sandbox.
func (d *DockerCloud) checkCapabilities(ctx context.Context) error {
	var caps struct {
		Permissions []protoEnum `json:"permissions"`
		Resources   *struct {
			CPUMin       protoUint `json:"cpuMin"`
			CPUMax       protoUint `json:"cpuMax"`
			MemoryMibMin protoUint `json:"memoryMibMin"`
			MemoryMibMax protoUint `json:"memoryMibMax"`
		} `json:"resources"`
	}
	if err := d.call(ctx, dcProcGetCapabilities, map[string]any{}, &caps); err != nil {
		return fmt.Errorf("get capabilities: %w", err)
	}
	// An empty list is read as "not reported", not as "no permissions"; the create
	// and exec calls then fail loudly if the token really lacks them.
	if len(caps.Permissions) > 0 {
		var missing []string
		for _, want := range dockerCloudRequiredPermissions {
			found := false
			for _, have := range caps.Permissions {
				if have.is(want.name, want.number) {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, want.name)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("token lacks permissions: %s", strings.Join(missing, ", "))
		}
	}
	if r := caps.Resources; r != nil {
		if cpus := uint64(d.MaxVCPU); cpus > 0 && r.CPUMax > 0 && (cpus < uint64(r.CPUMin) || cpus > uint64(r.CPUMax)) {
			return fmt.Errorf("SANDBOX_CPUS=%d is outside the backend's range %d..%d", cpus, r.CPUMin, r.CPUMax)
		}
		if mem := uint64(d.MaxMemoryMB); mem > 0 && r.MemoryMibMax > 0 && (mem < uint64(r.MemoryMibMin) || mem > uint64(r.MemoryMibMax)) {
			return fmt.Errorf("SANDBOX_MEMORY_MB=%d is outside the backend's range %d..%d MiB", mem, r.MemoryMibMin, r.MemoryMibMax)
		}
	}
	return nil
}

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
	if err := d.checkCapabilities(ctx); err != nil {
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
	if err := d.upload(ctx, vm, files); err != nil {
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
