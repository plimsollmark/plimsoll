package openshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/datamodelv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/sandboxv1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const (
	// workspace is the OpenShell workspace every request names; the gateway requires
	// a named workspace on every call.
	workspace = "default"
	// instanceLabel carries the provider instance on every sandbox it creates.
	instanceLabel = "plimsoll.instance"
	// runLabel marks every sandbox plimsoll creates for a run, whatever the instance,
	// so ReconcileOrphans can find what another instance left behind.
	runLabel = "plimsoll.run"
	// lifetimeLabel declares, in whole seconds from creation, how long the creator may
	// use the sandbox: the run's deadline. OpenShell sandboxes never expire, so one
	// whose creator crashed would live until someone deleted it by hand; any instance
	// may reap a sandbox that has outlived its declaration.
	lifetimeLabel = "plimsoll.lifetime"
	// staleMargin is added to a declared lifetime before another instance's sandbox
	// counts as abandoned (Provider.staleAfter; the live suite shortens it). It is far above the clock skew between NTP-synchronized
	// hosts and above deleteBudget, the time the creator's own delete may still be
	// retrying; a larger margin costs only that an orphan lives that much longer.
	staleMargin = 5 * time.Minute
	// defaultLifetime is declared when the creating context has no deadline (a run
	// always has one): the longest project budget plus the runner's grace.
	defaultLifetime = projectMax + runnerGrace
	// namePrefix starts every sandbox name. A name is at most 19 characters (the
	// gateway refuses longer ones), so the prefix leaves room for 14 hex digits.
	namePrefix = "plp-"
	// readyPoll is how often create reads a new sandbox's phase; ready arrives about
	// 0.55 s after create on the docker driver with a local image.
	readyPoll = 50 * time.Millisecond
	// stdinFrame is the size of one stdin message. The gateway decodes at most 1 MiB
	// per message; the stream as a whole has no cap (measured to 64 MiB).
	stdinFrame = 64 << 10
	// relayBackstop is added to the remaining run budget for the exec's
	// execution_timeout. It never kills anything (the gateway only stops relaying);
	// it ends the gateway's side of a relay whose cancellation never arrived.
	relayBackstop = 10 * time.Second
	// deleteBudget bounds one background delete, retries included. The delete call
	// alone takes about 5 s for a sandbox older than a second.
	deleteBudget = 60 * time.Second
	// maxListPages bounds ReconcileOrphans' walk over ListSandboxes pages.
	maxListPages = 50
	// agentProposalsSetting is the effective setting that lets code inside a sandbox
	// propose policy changes, which a gateway in auto approval mode can apply while
	// the sandbox runs. The read-back policy is evidence only while it is off.
	agentProposalsSetting = "agent_policy_proposals_enabled"
)

func ws() *datamodelv1.WorkspaceSelector {
	return &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: workspace}}
}

// ---- isolation evidence ----

// checkDriver reads the gateway's compute driver and records the tier it implies:
// container for docker, and a refusal for anything else, including a gateway that
// will not say. IsolationClass reports the result until the next check.
func (p *Provider) checkDriver(ctx context.Context) (sandbox.IsolationClass, error) {
	tier, version, err := p.readDriver(ctx)
	if err != nil {
		tier = sandbox.IsolationUnknown
	}
	p.mu.Lock()
	lost := p.tier != sandbox.IsolationUnknown && tier == sandbox.IsolationUnknown
	regained := p.tierLost && tier != sandbox.IsolationUnknown
	if lost {
		p.tierLost = true
	}
	if regained {
		p.tierLost = false
	}
	p.tier, p.version = tier, version
	p.mu.Unlock()
	// A daemon refuses every request that states a minimum isolation while the tier
	// is unknown, before the provider is asked, so the change is worth a line each way.
	if lost {
		slog.Warn("openshell: the driver check failed, so the isolation tier is unknown; requests that state a minimum isolation are refused until a check passes", "error", err)
	}
	if regained {
		slog.Info("openshell: the driver check passed again; the isolation tier is restored", "tier", tier.String(), "gateway_version", version)
	}
	return tier, err
}

// gatewayVersion is the version the last driver check reported.
func (p *Provider) gatewayVersion() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

func (p *Provider) readDriver(ctx context.Context) (sandbox.IsolationClass, string, error) {
	resp, err := p.client.GetGatewayInfo(ctx, connect.NewRequest(&openshellv1.GetGatewayInfoRequest{}))
	if err != nil {
		if code := connect.CodeOf(err); code == connect.CodePermissionDenied || code == connect.CodeUnauthenticated {
			return sandbox.IsolationUnknown, "", fmt.Errorf("openshell: the gateway refused GetGatewayInfo (%v), so this identity cannot learn the compute driver and the isolation tier is unknown; refusing to serve (under OIDC the call needs the platform_admin role): %w", code, err)
		}
		return sandbox.IsolationUnknown, "", fmt.Errorf("openshell gateway info: %w", err)
	}
	version := resp.Msg.GetGatewayVersion()
	drivers := resp.Msg.GetComputeDrivers()
	if len(drivers) != 1 {
		return sandbox.IsolationUnknown, version, fmt.Errorf("openshell: the gateway reports %d compute drivers, want exactly one", len(drivers))
	}
	d := drivers[0]
	if d.GetName() != "docker" || d.GetCapabilities().GetDriverName() != "docker" {
		return sandbox.IsolationUnknown, version, fmt.Errorf("openshell: the gateway runs compute driver %q (reported as %q); only docker has been tested with plimsoll, so it is refused", d.GetName(), d.GetCapabilities().GetDriverName())
	}
	rc := d.GetCapabilities().GetResourceCapabilities()
	if !rc.GetMemory().GetLimitSupported() || !rc.GetCpu().GetLimitSupported() {
		return sandbox.IsolationUnknown, version, errors.New("openshell: the gateway's docker driver does not report per-sandbox memory and CPU limit support, which every run requests")
	}
	return sandbox.IsolationContainer, version, nil
}

// ---- lifecycle: create, exec, delete ----

// box is a live sandbox: the name this provider chose and the id the gateway gave it.
type box struct {
	name string
	id   string
}

// create starts a sandbox with the run policy and resources, waits until it is ready,
// and refuses it unless the gateway reads back exactly what was requested. The name is
// tracked before the request is sent, so ReconcileOrphans never races a create, and
// any failure after that deletes the sandbox (off the caller's path), since the
// gateway may have created it even when its answer never arrived.
//
// The split into create, exec and delete is deliberate: a session (session.go) is the
// same create and exec without the per-run delete.
func (p *Provider) create(ctx context.Context) (box, error) {
	lifetime := defaultLifetime
	if dl, ok := ctx.Deadline(); ok {
		lifetime = time.Until(dl)
	}
	b, _, err := p.createBox(ctx, lifetime, nil, nil)
	return b, err
}

// createBox is create with the lifetime to declare, the main process (nil leaves the
// gateway's default, a login shell) and extra labels.
func (p *Provider) createBox(ctx context.Context, lifetime time.Duration, command []string, extra map[string]string) (box, map[string]string, error) {
	b := box{name: namePrefix + randHex(7)}
	labels := map[string]string{
		instanceLabel: p.instance,
		runLabel:      "1",
		lifetimeLabel: strconv.FormatInt(max(1, int64((lifetime+time.Second-1)/time.Second)), 10),
	}
	for k, v := range extra {
		labels[k] = v
	}
	p.track(b.name)
	ok := false
	defer func() {
		if !ok {
			p.deleteLater(b)
		}
	}()
	_, err := p.client.CreateSandbox(ctx, connect.NewRequest(&openshellv1.CreateSandboxRequest{
		WorkspaceScope: ws(),
		Name:           b.name,
		Labels:         labels,
		Spec: &openshellv1.SandboxSpec{
			Template: &openshellv1.SandboxTemplate{Image: p.cfg.Image, Resources: p.resources},
			Policy:   p.policy,
			Command:  command,
		},
	}))
	if err != nil {
		return box{}, nil, fmt.Errorf("openshell create sandbox: %w", err)
	}
	sb, err := p.waitReady(ctx, b.name)
	if err != nil {
		return box{}, nil, err
	}
	b.id = sb.GetMetadata().GetId()
	if err := p.verifySandbox(sb, labels, command); err != nil {
		return box{}, nil, err
	}
	if err := p.verifyConfig(ctx, b.name); err != nil {
		return box{}, nil, err
	}
	ok = true
	return b, labels, nil
}

func (p *Provider) waitReady(ctx context.Context, name string) (*openshellv1.Sandbox, error) {
	for {
		resp, err := p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: name}))
		if err != nil {
			return nil, fmt.Errorf("openshell get sandbox: %w", err)
		}
		sb := resp.Msg.GetSandbox()
		switch phase := sb.GetStatus().GetPhase(); phase {
		case openshellv1.SandboxPhase_SANDBOX_PHASE_READY:
			return sb, nil
		case openshellv1.SandboxPhase_SANDBOX_PHASE_UNSPECIFIED,
			openshellv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING,
			openshellv1.SandboxPhase_SANDBOX_PHASE_STARTING,
			openshellv1.SandboxPhase_SANDBOX_PHASE_UNKNOWN:
		default:
			return nil, fmt.Errorf("openshell create sandbox: sandbox reached phase %v instead of ready: %s", phase, conditionSummary(sb))
		}
		if err := sleepCtx(ctx, readyPoll); err != nil {
			return nil, err
		}
	}
}

// conditionSummary is a bounded description of a sandbox's conditions for an error.
func conditionSummary(sb *openshellv1.Sandbox) string {
	s := ""
	for _, c := range sb.GetStatus().GetConditions() {
		s += fmt.Sprintf("[%s=%s %s: %s]", c.GetType(), c.GetStatus(), c.GetReason(), c.GetMessage())
		if len(s) > 512 {
			return s[:512] + "..."
		}
	}
	return s
}

// verifySandbox checks the sandbox record against the request: every label sent, the
// configured image, the requested limits, the policy as sent, no credential providers
// attached, and, when command is not nil, the main process.
func (p *Provider) verifySandbox(sb *openshellv1.Sandbox, labels map[string]string, command []string) error {
	meta, spec := sb.GetMetadata(), sb.GetSpec()
	for key, want := range labels {
		if got := meta.GetLabels()[key]; got != want {
			return fmt.Errorf("openshell verify sandbox: label %s reads back %q, requested %q", key, got, want)
		}
	}
	switch {
	case meta.GetId() == "":
		return errors.New("openshell verify sandbox: the ready sandbox has no id")
	case spec.GetTemplate().GetImage() != p.cfg.Image:
		return fmt.Errorf("openshell verify sandbox: image reads back %q, requested %q", spec.GetTemplate().GetImage(), p.cfg.Image)
	case !proto.Equal(spec.GetTemplate().GetResources(), p.resources):
		return fmt.Errorf("openshell verify sandbox: resources read back as %v, requested %v", spec.GetTemplate().GetResources().AsMap(), p.resources.AsMap())
	case !proto.Equal(spec.GetPolicy(), p.policy):
		return errors.New("openshell verify sandbox: the sandbox spec's policy differs from the policy sent")
	case len(spec.GetProviders()) > 0:
		return fmt.Errorf("openshell verify sandbox: credential providers %v are attached; plimsoll attaches none", spec.GetProviders())
	case command != nil && !slices.Equal(spec.GetCommand(), command):
		return fmt.Errorf("openshell verify sandbox: the main process reads back as %q, requested %q", spec.GetCommand(), command)
	}
	return nil
}

// verifyConfig reads the sandbox's effective configuration back and refuses the run
// on any difference from what was sent: the policy must come from the sandbox (a
// gateway-wide policy would replace it), hash to the value computed from the policy
// sent, equal it field for field, and be admitted; and the setting that lets code
// inside the sandbox propose policy changes must be off.
func (p *Provider) verifyConfig(ctx context.Context, name string) error {
	resp, err := p.client.GetSandboxConfig(ctx, connect.NewRequest(&sandboxv1.GetSandboxConfigRequest{WorkspaceScope: ws(), Name: name}))
	if err != nil {
		return fmt.Errorf("openshell read policy back: %w", err)
	}
	cfg := resp.Msg
	switch {
	case cfg.GetPolicySource() != sandboxv1.PolicySource_POLICY_SOURCE_SANDBOX:
		return fmt.Errorf("openshell read policy back: the effective policy comes from %v, not from the sandbox; a gateway-wide policy replaces the one plimsoll sent", cfg.GetPolicySource())
	case cfg.GetPolicyHash() != p.policyHash:
		return fmt.Errorf("openshell read policy back: hash %q, the policy sent hashes to %q", cfg.GetPolicyHash(), p.policyHash)
	case !proto.Equal(cfg.GetPolicy(), p.policy):
		return errors.New("openshell read policy back: the effective policy differs from the policy sent")
	case !cfg.GetConfigurationAdmitted():
		return fmt.Errorf("openshell read policy back: the configuration is not admitted: %q", cfg.GetConfigurationError())
	}
	if v := cfg.GetSettings()[agentProposalsSetting].GetValue(); v.GetBoolValue() || v.GetStringValue() == "true" {
		return fmt.Errorf("openshell read policy back: %s is on, so code in the sandbox could propose policy changes after the read-back", agentProposalsSetting)
	}
	return nil
}

// execOutput is one command's captured result. exited says the gateway delivered an
// exit status; without one, the output is whatever arrived before the stream ended.
type execOutput struct {
	stdout, stderr                   []byte
	stdoutTruncated, stderrTruncated bool
	exitCode                         int
	exited                           bool
}

// exec runs argv in the sandbox over ExecSandboxInteractive, always the streaming RPC:
// unary ExecSandbox caps stdin below 1 MiB, and cancelling it leaves the command
// running. stdin goes in stdinFrame messages, then the request side is half-closed,
// which the gateway turns into end of input. Each output stream keeps its first
// stdoutCap or stderrCap bytes and flags any it drops, the docker provider's
// semantics; the rest is read and discarded so the exit status still arrives.
//
// The exit status is authoritative: a command that exits without reading its stdin
// makes the send side fail while the exit event still arrives. ctx ending cancels the
// stream, which kills the command and its process group on the docker driver, so ctx's
// deadline is the run's kill switch. Measured on v0.1.2 (TestMeasureOpenShellCallBoundary):
// a descendant that detached with setsid survives the cancel, and after a normal exit
// nothing still running is killed; a per-run sandbox's delete ends both.
func (p *Provider) exec(ctx context.Context, b box, argv []string, env map[string]string, stdin []byte, stdoutCap, stderrCap int) (execOutput, error) {
	return p.execWatch(ctx, b, argv, env, stdin, stdoutCap, stderrCap, nil)
}

// execWatch is exec with watch, when not nil, given each stdout chunk as it arrives:
// how a caller learns that a long-running command (the grant relay) is ready while
// the command runs on.
func (p *Provider) execWatch(ctx context.Context, b box, argv []string, env map[string]string, stdin []byte, stdoutCap, stderrCap int, watch func([]byte)) (execOutput, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream := p.client.ExecSandboxInteractive(streamCtx)
	start := &openshellv1.ExecSandboxRequest{
		WorkspaceScope: ws(),
		Sandbox:        b.name,
		Command:        argv,
		Environment:    env,
		NoLoginShell:   true,
	}
	if deadline, ok := ctx.Deadline(); ok {
		start.ExecutionTimeout = durationpb.New(max(time.Until(deadline), 0) + relayBackstop)
	}
	sent := make(chan error, 1)
	go func() {
		err := stream.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Start{Start: start}})
		for off := 0; err == nil && off < len(stdin); off += stdinFrame {
			err = stream.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Stdin{Stdin: stdin[off:min(off+stdinFrame, len(stdin))]}})
		}
		if cerr := stream.CloseRequest(); err == nil {
			err = cerr
		}
		sent <- err
	}()

	stdout, stderr := capture{limit: stdoutCap}, capture{limit: stderrCap}
	var out execOutput
	var recvErr error
	for !out.exited {
		ev, err := stream.Receive()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				recvErr = err
			}
			break
		}
		switch pl := ev.GetPayload().(type) {
		case *openshellv1.ExecSandboxEvent_Stdout:
			stdout.write(pl.Stdout.GetData())
			if watch != nil {
				watch(pl.Stdout.GetData())
			}
		case *openshellv1.ExecSandboxEvent_Stderr:
			stderr.write(pl.Stderr.GetData())
		case *openshellv1.ExecSandboxEvent_Exit:
			// The exit event follows the last output byte (measured: no output event
			// ever arrived after it, including after 10 MB of stdout).
			out.exitCode, out.exited = int(pl.Exit.GetExitCode()), true
		}
	}
	cancel()
	sendErr := <-sent
	_ = stream.CloseResponse()
	out.stdout, out.stdoutTruncated = stdout.buf, stdout.dropped
	out.stderr, out.stderrTruncated = stderr.buf, stderr.dropped
	switch {
	case out.exited:
		return out, nil
	case recvErr != nil:
		return out, fmt.Errorf("openshell exec: %w", recvErr)
	case sendErr != nil:
		return out, fmt.Errorf("openshell exec: the stream ended without an exit status: %w", sendErr)
	default:
		return out, errors.New("openshell exec: the stream ended without an exit status")
	}
}

// capture keeps the first limit bytes written to it and records whether it dropped
// any. The retained prefix is never annotated in-band.
type capture struct {
	buf     []byte
	limit   int
	dropped bool
}

func (c *capture) write(p []byte) {
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
			c.dropped = true
		} else {
			c.buf = append(c.buf, p...)
		}
	} else if len(p) > 0 {
		c.dropped = true
	}
}

// deleteLater deletes b off the caller's path: the delete call takes about 5 s once a
// sandbox is a second old, and a run's result does not wait for it. The name stays
// tracked until the delete has finished or given up.
func (p *Provider) deleteLater(b box) {
	go p.destroy(b)
}

// destroy deletes a sandbox on its own context, so it still runs after the run's
// context has ended, retrying, and waits until the gateway no longer has it. The name
// is untracked whatever happens: anything still alive under this instance's label
// after that is an orphan, and ReconcileOrphans reaps it.
func (p *Provider) destroy(b box) {
	defer p.untrack(b.name)
	ctx, cancel := context.WithTimeout(context.Background(), deleteBudget)
	defer cancel()
	const attempts = 3
	for i := 1; ; i++ {
		err := p.deleteAndWait(ctx, b.name)
		if err == nil {
			return
		}
		if i == attempts || ctx.Err() != nil {
			slog.Error("openshell: failed to delete sandbox; ReconcileOrphans will reap it",
				"sandbox", b.name, "id", b.id, "attempts", i, "error", err)
			return
		}
		if sleepCtx(ctx, time.Duration(i)*time.Second) != nil {
			return
		}
	}
}

// deleteAndWait deletes a sandbox by name and, when the gateway only accepted the
// deletion, watches the name until the record is gone.
func (p *Provider) deleteAndWait(ctx context.Context, name string) error {
	resp, err := p.client.DeleteSandbox(ctx, connect.NewRequest(&openshellv1.DeleteSandboxRequest{WorkspaceScope: ws(), Name: name, AllowMissing: true}))
	if err != nil {
		return err
	}
	switch o := resp.Msg.GetOutcome(); o {
	case openshellv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED, openshellv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT:
		return nil
	case openshellv1.DeletionOutcome_DELETION_OUTCOME_ACCEPTED:
	default:
		return fmt.Errorf("openshell delete sandbox: outcome %v", o)
	}
	for {
		_, err := p.client.GetSandbox(ctx, connect.NewRequest(&openshellv1.GetSandboxRequest{WorkspaceScope: ws(), Name: name}))
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		if err := sleepCtx(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
}

func (p *Provider) track(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tracked[name] = struct{}{}
}

func (p *Provider) untrack(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tracked, name)
}

func (p *Provider) isTracked(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.tracked[name]
	return ok
}

func (p *Provider) trackedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tracked)
}

// Drain ends every open session, then waits until no sandbox this provider created is
// left undeleted (every run has ended and every background delete has finished or
// given up), or ctx ends. A daemon calls it on shutdown, after it stops accepting runs.
func (p *Provider) Drain(ctx context.Context) error {
	for _, s := range p.openSessions() {
		s.finish(sandbox.SessionShutdown, "")
	}
	for p.trackedCount() > 0 {
		if err := sleepCtx(ctx, 50*time.Millisecond); err != nil {
			return fmt.Errorf("openshell: %d sandboxes still undeleted: %w", p.trackedCount(), err)
		}
	}
	return nil
}

// ReconcileOrphans deletes the plimsoll sandboxes no live run can be using:
//   - this instance's own that no run tracks: a create whose answer never arrived, or a
//     delete whose retries all failed. Names are tracked before a create is sent, so an
//     in-flight run is never touched;
//   - another instance's, once the gateway's creation time plus the lifetime its
//     creator declared plus staleMargin has passed: what a crashed daemon left behind.
//     One with no creation time or no valid declaration is never touched.
//
// A sandbox already being deleted is left alone. It returns how many deletions the
// gateway accepted.
func (p *Provider) ReconcileOrphans(ctx context.Context) (int, error) {
	deleted := 0
	token := ""
	for page := 0; page < maxListPages; page++ {
		resp, err := p.client.ListSandboxes(ctx, connect.NewRequest(&openshellv1.ListSandboxesRequest{
			WorkspaceScope: ws(),
			PageSize:       100,
			PageToken:      token,
			LabelSelector:  runLabel + "=1",
		}))
		if err != nil {
			return deleted, fmt.Errorf("openshell list sandboxes: %w", err)
		}
		for _, sb := range resp.Msg.GetSandboxes() {
			name := sb.GetMetadata().GetName()
			if !p.orphaned(sb, time.Now()) {
				continue
			}
			dr, err := p.client.DeleteSandbox(ctx, connect.NewRequest(&openshellv1.DeleteSandboxRequest{WorkspaceScope: ws(), Name: name, AllowMissing: true}))
			if err != nil {
				slog.Error("openshell: failed to delete orphaned sandbox", "sandbox", name, "error", err)
				continue
			}
			if o := dr.Msg.GetOutcome(); o == openshellv1.DeletionOutcome_DELETION_OUTCOME_ACCEPTED || o == openshellv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED {
				slog.Warn("openshell: deleted orphaned sandbox", "sandbox", name, "instance", sb.GetMetadata().GetLabels()[instanceLabel],
					"created", sb.GetMetadata().GetCreatedTime().AsTime())
				deleted++
			}
		}
		if token = resp.Msg.GetNextPageToken(); token == "" {
			return deleted, nil
		}
	}
	return deleted, fmt.Errorf("openshell list sandboxes: more than %d pages", maxListPages)
}

// orphaned reports whether ReconcileOrphans may delete sb at now.
func (p *Provider) orphaned(sb *openshellv1.Sandbox, now time.Time) bool {
	meta := sb.GetMetadata()
	labels := meta.GetLabels()
	if labels[runLabel] != "1" || sb.GetStatus().GetPhase() == openshellv1.SandboxPhase_SANDBOX_PHASE_DELETING {
		return false
	}
	if labels[instanceLabel] == p.instance {
		return !p.isTracked(meta.GetName())
	}
	// Unsigned and 32-bit: no sign, and seconds times a nanosecond cannot overflow.
	secs, err := strconv.ParseUint(labels[lifetimeLabel], 10, 32)
	if err != nil || secs == 0 || meta.GetCreatedTime() == nil {
		return false
	}
	return now.After(meta.GetCreatedTime().AsTime().Add(time.Duration(secs)*time.Second + p.staleAfter))
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
