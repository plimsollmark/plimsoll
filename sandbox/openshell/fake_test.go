package openshell

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/datamodelv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1/openshellv1connect"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/sandboxv1"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// fakeGateway is an in-process OpenShell gateway: the generated handler served over
// HTTP/2 with TLS by httptest, holding sandboxes in memory. Tests script exec
// behavior with run and bend the read-back with the mutate hooks.
type fakeGateway struct {
	openshellv1connect.UnimplementedOpenShellHandler

	mu    sync.Mutex
	boxes map[string]*fakeBox
	calls []string
	execs []*fakeExec

	info         func() (*openshellv1.GetGatewayInfoResponse, error)
	failPhase    openshellv1.SandboxPhase // a phase to report instead of READY
	mutateSpec   func(*openshellv1.Sandbox)
	mutateConfig func(*sandboxv1.GetSandboxConfigResponse)
	// deletePolls is how many GetSandbox calls still find a sandbox after its
	// deletion was accepted; deleteErr fails every DeleteSandbox.
	deletePolls int
	deleteErr   error
	// configErr, when set, fails every GetSandboxConfig; createDelay delays every
	// CreateSandbox.
	configErr   error
	createDelay time.Duration
	run         func(e *fakeExec) error
	forward     *fakeForwarding // SSH sessions and ForwardTcp (grant_test.go); nil refuses them
	// allowDriverConfig is the gateway's allow_driver_config: off, a create carrying a
	// driver config is refused, as v0.1.2 refuses it.
	allowDriverConfig bool
}

type fakeBox struct {
	sb             *openshellv1.Sandbox
	deleted        bool
	pollsAfterGone int
	stopped        bool                     // StopSandbox stopped it and no StartSandbox has run
	phase          openshellv1.SandboxPhase // reported instead of READY when set (a session test's ERROR)
}

// fakeExec is one ExecSandboxInteractive call as the fake saw it.
type fakeExec struct {
	ctx   context.Context
	start *openshellv1.ExecSandboxRequest
	stdin chan []byte // closed at the client's half-close or the stream's end
	send  func(*openshellv1.ExecSandboxEvent) error

	mu        sync.Mutex
	received  []byte
	cancelled bool // the stream's context ended before the script returned
}

func (e *fakeExec) readAll() []byte {
	for chunk := range e.stdin {
		e.mu.Lock()
		e.received = append(e.received, chunk...)
		e.mu.Unlock()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]byte(nil), e.received...)
}

func (e *fakeExec) stdout(b []byte) error {
	return e.send(&openshellv1.ExecSandboxEvent{Payload: &openshellv1.ExecSandboxEvent_Stdout{Stdout: &openshellv1.ExecSandboxStdout{Data: b}}})
}

func (e *fakeExec) stderr(b []byte) error {
	return e.send(&openshellv1.ExecSandboxEvent{Payload: &openshellv1.ExecSandboxEvent_Stderr{Stderr: &openshellv1.ExecSandboxStderr{Data: b}}})
}

func (e *fakeExec) exit(code int32) error {
	return e.send(&openshellv1.ExecSandboxEvent{Payload: &openshellv1.ExecSandboxEvent_Exit{Exit: &openshellv1.ExecSandboxExit{ExitCode: code}}})
}

func (e *fakeExec) wasCancelled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cancelled
}

func dockerInfo() (*openshellv1.GetGatewayInfoResponse, error) {
	return &openshellv1.GetGatewayInfoResponse{
		GatewayVersion: "0.1.2-fake",
		ComputeDrivers: []*openshellv1.ComputeDriverInfo{{
			Name: "docker",
			Capabilities: &openshellv1.ComputeDriverCapabilities{
				DriverName: "docker",
				ResourceCapabilities: &openshellv1.ResourceCapabilities{
					Cpu:    &openshellv1.CpuResourceCapabilities{LimitSupported: true},
					Memory: &openshellv1.MemoryResourceCapabilities{LimitSupported: true},
				},
			},
		}},
	}, nil
}

// newFake starts a fake gateway and returns a provider wired to it. The provider's
// background deletes are drained on cleanup.
func newFake(t *testing.T) (*fakeGateway, *Provider) {
	t.Helper()
	f := &fakeGateway{boxes: map[string]*fakeBox{}, info: dockerInfo}
	path, handler := openshellv1connect.NewOpenShellHandler(f)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client := openshellv1connect.NewOpenShellClient(srv.Client(), srv.URL, connect.WithGRPC(), connect.WithReadMaxBytes(maxMessageBytes))
	p, err := newProvider(Config{GatewayURL: srv.URL, CAFile: "ca.pem", CertFile: "cert.pem", KeyFile: "key.pem", Image: "plimsoll/sandbox:test"}, client)
	if err != nil {
		t.Fatal(err)
	}
	// Every Preflight checks the fake again, as the driver tests expect;
	// TestPreflightIsCached turns the cache back on.
	p.pfTTL = 0
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.Drain(ctx); err != nil {
			t.Errorf("drain: %v", err)
		}
	})
	return f, p
}

func (f *fakeGateway) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeGateway) called(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}

func (f *fakeGateway) lastExec() *fakeExec {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.execs) == 0 {
		return nil
	}
	return f.execs[len(f.execs)-1]
}

// live returns the names of sandboxes that exist and are not deleted.
func (f *fakeGateway) live() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for name, b := range f.boxes {
		if !b.deleted {
			names = append(names, name)
		}
	}
	return names
}

// add places a sandbox created now directly, as if another client or an earlier
// process made it.
func (f *fakeGateway) add(name string, labels map[string]string, phase openshellv1.SandboxPhase) {
	f.addAt(name, labels, phase, timestamppb.Now())
}

// addAt is add with the gateway's creation time; nil leaves it unset.
func (f *fakeGateway) addAt(name string, labels map[string]string, phase openshellv1.SandboxPhase, created *timestamppb.Timestamp) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.boxes[name] = &fakeBox{sb: &openshellv1.Sandbox{
		Metadata: &datamodelv1.ObjectMeta{Id: name + "-id", Name: name, Labels: labels, CreatedTime: created},
		Status:   &openshellv1.SandboxStatus{Phase: phase},
	}}
}

func (f *fakeGateway) GetGatewayInfo(context.Context, *connect.Request[openshellv1.GetGatewayInfoRequest]) (*connect.Response[openshellv1.GetGatewayInfoResponse], error) {
	f.record("GetGatewayInfo")
	resp, err := f.info()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

func requireWorkspace(sel *datamodelv1.WorkspaceSelector) error {
	if sel.GetWorkspace() != workspace {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("workspace_scope must name a workspace"))
	}
	return nil
}

func (f *fakeGateway) CreateSandbox(_ context.Context, req *connect.Request[openshellv1.CreateSandboxRequest]) (*connect.Response[openshellv1.SandboxResponse], error) {
	f.record("CreateSandbox")
	if err := requireWorkspace(req.Msg.GetWorkspaceScope()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	delay := f.createDelay
	f.mu.Unlock()
	time.Sleep(delay)
	if len(req.Msg.GetName()) > 19 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name exceeds maximum length"))
	}
	if len(req.Msg.GetSpec().GetTemplate().GetDriverConfig().GetFields()) > 0 && !f.allowDriverConfig {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("driver_config is disabled on this gateway; the administrator must enable allow_driver_config"))
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	sb := &openshellv1.Sandbox{
		Metadata: &datamodelv1.ObjectMeta{Id: hex.EncodeToString(id), Name: req.Msg.GetName(), Labels: req.Msg.GetLabels(), CreatedTime: timestamppb.Now()},
		Spec:     proto.Clone(req.Msg.GetSpec()).(*openshellv1.SandboxSpec),
		Status:   &openshellv1.SandboxStatus{Phase: openshellv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	f.mu.Lock()
	f.boxes[sb.GetMetadata().GetName()] = &fakeBox{sb: sb}
	f.mu.Unlock()
	return connect.NewResponse(&openshellv1.SandboxResponse{Sandbox: sb}), nil
}

func (f *fakeGateway) GetSandbox(_ context.Context, req *connect.Request[openshellv1.GetSandboxRequest]) (*connect.Response[openshellv1.SandboxResponse], error) {
	f.record("GetSandbox")
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.boxes[req.Msg.GetName()]
	if !ok || (b.deleted && b.pollsAfterGone <= 0) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	if b.deleted {
		b.pollsAfterGone--
	}
	sb := proto.Clone(b.sb).(*openshellv1.Sandbox)
	switch {
	case b.deleted:
		sb.Status.Phase = openshellv1.SandboxPhase_SANDBOX_PHASE_DELETING
	case f.failPhase != openshellv1.SandboxPhase_SANDBOX_PHASE_UNSPECIFIED:
		sb.Status.Phase = f.failPhase
		sb.Status.Conditions = []*openshellv1.SandboxCondition{{Type: "Ready", Status: "False", Reason: "ImagePullFailed", Message: "no such image"}}
	case b.stopped:
		sb.Status.Phase = openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPED
	case b.phase != openshellv1.SandboxPhase_SANDBOX_PHASE_UNSPECIFIED:
		sb.Status.Phase = b.phase
	default:
		sb.Status.Phase = openshellv1.SandboxPhase_SANDBOX_PHASE_READY
	}
	if f.mutateSpec != nil {
		f.mutateSpec(sb)
	}
	return connect.NewResponse(&openshellv1.SandboxResponse{Sandbox: sb}), nil
}

func (f *fakeGateway) GetSandboxConfig(_ context.Context, req *connect.Request[sandboxv1.GetSandboxConfigRequest]) (*connect.Response[sandboxv1.GetSandboxConfigResponse], error) {
	f.record("GetSandboxConfig")
	f.mu.Lock()
	b, ok := f.boxes[req.Msg.GetName()]
	configErr := f.configErr
	f.mu.Unlock()
	if configErr != nil {
		return nil, configErr
	}
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	policy := proto.Clone(b.sb.GetSpec().GetPolicy()).(*sandboxv1.SandboxPolicy)
	hash, err := policyHash(policy)
	if err != nil {
		return nil, err
	}
	resp := &sandboxv1.GetSandboxConfigResponse{
		Policy:                policy,
		Version:               1,
		PolicyHash:            hash,
		PolicySource:          sandboxv1.PolicySource_POLICY_SOURCE_SANDBOX,
		ConfigurationAdmitted: true,
		Settings:              map[string]*sandboxv1.EffectiveSetting{agentProposalsSetting: {}},
	}
	if f.mutateConfig != nil {
		f.mutateConfig(resp)
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeGateway) DeleteSandbox(_ context.Context, req *connect.Request[openshellv1.DeleteSandboxRequest]) (*connect.Response[openshellv1.DeleteSandboxResponse], error) {
	f.record("DeleteSandbox")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	b, ok := f.boxes[req.Msg.GetName()]
	if !ok || b.deleted {
		if !req.Msg.GetAllowMissing() {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
		}
		return connect.NewResponse(&openshellv1.DeleteSandboxResponse{Outcome: openshellv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}), nil
	}
	b.deleted, b.pollsAfterGone = true, f.deletePolls
	return connect.NewResponse(&openshellv1.DeleteSandboxResponse{Outcome: openshellv1.DeletionOutcome_DELETION_OUTCOME_ACCEPTED, SandboxId: b.sb.GetMetadata().GetId()}), nil
}

func (f *fakeGateway) ListSandboxes(_ context.Context, req *connect.Request[openshellv1.ListSandboxesRequest]) (*connect.Response[openshellv1.ListSandboxesResponse], error) {
	f.record("ListSandboxes")
	key, value, _ := strings.Cut(req.Msg.GetLabelSelector(), "=")
	f.mu.Lock()
	defer f.mu.Unlock()
	resp := &openshellv1.ListSandboxesResponse{}
	for _, b := range f.boxes {
		if b.deleted || (key != "" && b.sb.GetMetadata().GetLabels()[key] != value) {
			continue
		}
		resp.Sandboxes = append(resp.Sandboxes, proto.Clone(b.sb).(*openshellv1.Sandbox))
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeGateway) ExecSandboxInteractive(ctx context.Context, stream *connect.BidiStream[openshellv1.ExecSandboxInput, openshellv1.ExecSandboxEvent]) error {
	f.record("ExecSandboxInteractive")
	first, err := stream.Receive()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first message must be a start payload"))
	}
	if err := requireWorkspace(start.GetWorkspaceScope()); err != nil {
		return err
	}
	f.mu.Lock()
	b, ok := f.boxes[start.GetSandbox()]
	notReady := ok && (b.stopped || b.phase != openshellv1.SandboxPhase_SANDBOX_PHASE_UNSPECIFIED)
	f.mu.Unlock()
	if !ok || b.deleted {
		return connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	if notReady {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox is not ready"))
	}
	e := &fakeExec{ctx: ctx, start: start, stdin: make(chan []byte), send: stream.Send}
	f.mu.Lock()
	f.execs = append(f.execs, e)
	f.mu.Unlock()
	// The reader hands stdin to the script until the client half-closes or the
	// stream ends. The handler waits for it, so the stream is never used after the
	// handler returns.
	stop := make(chan struct{})
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		defer close(e.stdin)
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			select {
			case e.stdin <- msg.GetStdin():
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	err = f.run(e)
	close(stop)
	reader.Wait()
	return err
}

func (f *fakeGateway) StopSandbox(_ context.Context, req *connect.Request[openshellv1.StopSandboxRequest]) (*connect.Response[openshellv1.SandboxResponse], error) {
	f.record("StopSandbox")
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.boxes[req.Msg.GetName()]
	if !ok || b.deleted {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	b.stopped = true
	return connect.NewResponse(&openshellv1.SandboxResponse{Sandbox: proto.Clone(b.sb).(*openshellv1.Sandbox)}), nil
}

func (f *fakeGateway) StartSandbox(_ context.Context, req *connect.Request[openshellv1.StartSandboxRequest]) (*connect.Response[openshellv1.SandboxResponse], error) {
	f.record("StartSandbox")
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.boxes[req.Msg.GetName()]
	if !ok || b.deleted {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	b.stopped = false
	return connect.NewResponse(&openshellv1.SandboxResponse{Sandbox: proto.Clone(b.sb).(*openshellv1.Sandbox)}), nil
}

// setPhase makes a sandbox report phase instead of READY, and refuse execs.
func (f *fakeGateway) setPhase(name string, phase openshellv1.SandboxPhase) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.boxes[name].phase = phase
}

// hang blocks until the client cancels the stream, and records that it did.
func (e *fakeExec) hang() error {
	<-e.ctx.Done()
	e.mu.Lock()
	e.cancelled = true
	e.mu.Unlock()
	return e.ctx.Err()
}

// controlled is cmd without the sessionkit.ControlArgv prefix plimsoll's own programs
// start under (/usr/bin/env -i, the control PATH, then NAME=value arguments), and
// whether it had one.
func controlled(cmd []string) ([]string, bool) {
	if len(cmd) < 3 || cmd[0] != "/usr/bin/env" || cmd[1] != "-i" || cmd[2] != "PATH="+sessionkit.ControlPath {
		return cmd, false
	}
	cmd = cmd[3:]
	for len(cmd) > 0 && envAssignment.MatchString(cmd[0]) {
		cmd = cmd[1:]
	}
	return cmd, true
}

var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
