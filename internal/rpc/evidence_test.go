package rpc

import (
	"context"
	"errors"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

const wslSentence = "Hyper-V VM per run (one WSLC session per run). Microsoft states that WSL is not a security sandbox for running untrusted code."

// A run's answer states the sentence its provider states beside the tier and this
// daemon's version, and its record (version 5) repeats both, so the client's check
// binds them to the tier it signs.
func TestARunStatesTheQualificationAndTheDaemonVersion(t *testing.T) {
	for name, tc := range map[string]struct {
		sb   sandbox.Sandbox
		want string
	}{
		// Each stand-in's result states a real tier, as every provider's does: the record
		// check refuses a record whose tier is not one of the five (release-51).
		"a provider with one":  {&qualifyingFake{fakeSandbox: fakeSandbox{jsResult: sandbox.Result{Isolation: sandbox.IsolationVM}}, sentence: wslSentence}, wslSentence},
		"a provider with none": {&fakeSandbox{jsResult: sandbox.Result{Isolation: sandbox.IsolationVM}}, ""},
	} {
		req := &plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
		resp, err := NewSandboxService(tc.sb).Run(authenticatedContext("alice"), connect.NewRequest(req))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		m := resp.Msg
		if m.GetIsolationQualification() != tc.want || m.GetDaemonVersion() != "(devel)" {
			t.Errorf("%s: qualification %q, daemon version %q; want %q and (devel), a test binary's", name, m.GetIsolationQualification(), m.GetDaemonVersion(), tc.want)
		}
		r, err := record.Check(req, m)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Version != 5 || r.IsolationQualification != tc.want || r.DaemonVersion != "(devel)" || r.Warm {
			t.Errorf("%s: record %+v", name, r)
		}
	}
}

// A provider whose sentence no record can carry gets every call refused before it
// runs, marked not dispatched, rather than answered with a tier and no sentence.
func TestAQualificationNoRecordCanCarryIsRefusedBeforeDispatch(t *testing.T) {
	for name, sentence := range map[string]string{
		"over the cap":   strings.Repeat("x", record.MaxQualificationBytes+1),
		"a line feed":    "Microsoft states.\nNothing to see.",
		"a C0 control":   "Microsoft\x00states.",
		"invalid UTF-8":  "Microsoft \xffstates.",
		"an RTL isolate": "Microsoft " + string(rune(0x2067)) + "states.",
	} {
		fake := &qualifyingFake{sentence: sentence}
		req := &plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
		_, err := NewSandboxService(fake).Run(authenticatedContext("alice"), connect.NewRequest(req))
		if reason, marked := notDispatchedOf(err); !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ENVIRONMENT {
			t.Errorf("%s: %v (marked %v, %v); want a refusal marked not dispatched, environment", name, err, marked, reason)
		}
		if fake.lastReq.Code != "" {
			t.Errorf("%s: the provider ran the call", name)
		}
	}
}

// namedFake is a provider whose name is name.
type namedFake struct {
	fakeSandbox
	name string
}

func (n *namedFake) Name() string { return n.name }

// A provider whose name no record can carry (record.ValidText) gets every call refused
// before it runs, marked not dispatched: every client's record check refuses an answer
// that names it, and by then the code would have run.
func TestAProviderNameNoRecordCanCarryIsRefusedBeforeDispatch(t *testing.T) {
	for name, provider := range map[string]string{
		"an escape":                "docker\x1b[2J",
		"a carriage return":        "docker\rvm",
		"a right-to-left override": "docker\u202e",
		"invalid UTF-8":            "docker\xff",
	} {
		fake := &namedFake{name: provider}
		req := &plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
		_, err := NewSandboxService(fake).Run(authenticatedContext("alice"), connect.NewRequest(req))
		if reason, marked := notDispatchedOf(err); !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ENVIRONMENT {
			t.Errorf("%s: %v (marked %v, %v); want a refusal marked not dispatched, environment", name, err, marked, reason)
		}
		if fake.lastReq.Code != "" {
			t.Errorf("%s: the provider ran the call", name)
		}
	}
	fake := &namedFake{fakeSandbox: fakeSandbox{jsResult: sandbox.Result{Sandbox: "fake", Isolation: sandbox.IsolationVM}}, name: "fake"}
	req := &plimsollv1.RunRequest{Protocol: protocol.Number, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	if _, err := NewSandboxService(fake).Run(authenticatedContext("alice"), connect.NewRequest(req)); err != nil {
		t.Fatalf("an ordinary name: %v", err)
	}
}

// qualifyingSessions is a session provider that states a sentence beside its tier.
type qualifyingSessions struct {
	*failingSessions
	sentence string
}

func (q *qualifyingSessions) Qualification() string { return q.sentence }

// A session states its provider's sentence at open, every call's answer and record
// repeat it, and the record of a call that may have run but got no answer, built by
// hand with no response to read, states the sentence the session stated at open
// (finding cyclonedx-18).
func TestASessionStatesTheQualificationOnEveryRecord(t *testing.T) {
	inner := &sandboxtest.Sessions{}
	svc := NewSandboxService(&qualifyingSessions{failingSessions: &failingSessions{Sessions: inner, failCall: 2}, sentence: wslSentence})
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	ctx := authenticatedContext("alice")
	open, err := svc.OpenSession(ctx, openReq())
	if err != nil {
		t.Fatal(err)
	}
	if got := open.Msg.GetIsolationQualification(); got != wslSentence {
		t.Fatalf("the open states %q, want the provider's sentence", got)
	}
	id := open.Msg.GetSessionId()
	fp := record.SessionFingerprint(id)
	firstReq := callReq(id, "1")
	first, err := svc.SessionRun(ctx, firstReq)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := record.CheckSessionCall(firstReq.Msg, first.Msg.GetRun(), fp, 0, "")
	if err != nil || r1.IsolationQualification != wslSentence || first.Msg.GetRun().GetIsolationQualification() != wslSentence {
		t.Fatalf("the answered call's record: %+v, %v", r1, err)
	}
	second := callReq(id, "2")
	_, err = svc.SessionRun(ctx, second)
	var ce *connect.Error
	var unanswered *plimsollv1.RunRecord
	if errors.As(err, &ce) {
		for _, d := range ce.Details() {
			if v, derr := d.Value(); derr == nil {
				if u, ok := v.(*plimsollv1.UnansweredCall); ok {
					unanswered = u.GetRecord()
				}
			}
		}
	}
	r2, err := record.CheckUnanswered(second.Msg, unanswered, fp, 1, r1.SHA256)
	if err != nil {
		t.Fatalf("the unanswered call's record: %v", err)
	}
	if r2.Version != 5 || r2.IsolationQualification != wslSentence || r2.DaemonVersion != "(devel)" || r2.Warm {
		t.Fatalf("the unanswered call's record states %+v; want version 5 with the session's sentence", r2)
	}
	if _, err := svc.CloseSession(ctx, closeReq(id)); err != nil {
		t.Fatal(err)
	}
}

// The two policies of a docker daemon with the sdk_env variant configured: Describe
// names the default profile and the variant, and a session's container, which never
// gets the variant, applies the default alone.
const (
	sessionOnlyPolicy = "seccomp:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	describedPolicy   = sessionOnlyPolicy + " sdk_env:seccomp:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// policySessions is a session provider that states its policy as such a daemon does:
// the provider's two profiles in Describe, its sessions' one at open, and, when
// perCall is set, that one again on every call's result (docker's sessions do; a
// provider with one policy for every sandbox, like openshell, states none per call).
type policySessions struct {
	*failingSessions
	perCall bool
}

func (*policySessions) Environments() sandbox.Environments {
	return sandbox.Environments{Policy: describedPolicy}
}

func (p *policySessions) OpenSession(ctx context.Context, opts sandbox.SessionOptions) (sandbox.Session, error) {
	s, err := p.failingSessions.OpenSession(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &policySession{Session: s, perCall: p.perCall}, nil
}

type policySession struct {
	sandbox.Session
	perCall bool
}

func (s *policySession) Environments() sandbox.Environments {
	e := s.Session.Environments()
	e.Policy = sessionOnlyPolicy
	return e
}

func (s *policySession) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	res, err := s.Session.RunJavaScript(ctx, req)
	if s.perCall {
		res.Policy = sessionOnlyPolicy
	}
	return res, err
}

// Every record of a session names the policy its session stated at open, the record
// of a call that may have run but got no answer included, never the provider's
// statement read at the call: on docker with the sdk_env variant configured that
// statement names a combination no container ran under, so one chain carried two
// policies (finding release-40).
func TestASessionStatesItsOwnPolicyOnEveryRecord(t *testing.T) {
	for name, perCall := range map[string]bool{"results name the policy": true, "results name none": false} {
		t.Run(name, func(t *testing.T) {
			inner := &sandboxtest.Sessions{}
			svc := NewSandboxService(&policySessions{failingSessions: &failingSessions{Sessions: inner, failCall: 2}, perCall: perCall})
			svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
			ctx := authenticatedContext("alice")
			open, err := svc.OpenSession(ctx, openReq())
			if err != nil {
				t.Fatal(err)
			}
			id := open.Msg.GetSessionId()
			fp := record.SessionFingerprint(id)
			firstReq := callReq(id, "1")
			first, err := svc.SessionRun(ctx, firstReq)
			if err != nil {
				t.Fatal(err)
			}
			r1, err := record.CheckSessionCall(firstReq.Msg, first.Msg.GetRun(), fp, 0, "")
			if err != nil {
				t.Fatal(err)
			}
			second := callReq(id, "2")
			_, err = svc.SessionRun(ctx, second)
			r2, err := record.CheckUnanswered(second.Msg, unansweredOf(err), fp, 1, r1.SHA256)
			if err != nil {
				t.Fatalf("the unanswered call's record: %v", err)
			}
			if r1.Policy != sessionOnlyPolicy || r2.Policy != sessionOnlyPolicy {
				t.Fatalf("the answered call's record names %q and the unanswered one's %q; want both %q, the policy the session stated at open", r1.Policy, r2.Policy, sessionOnlyPolicy)
			}
			if _, err := svc.CloseSession(ctx, closeReq(id)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// unansweredOf is the record an error carries as an UnansweredCall detail, or nil.
func unansweredOf(err error) *plimsollv1.RunRecord {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return nil
	}
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if u, ok := v.(*plimsollv1.UnansweredCall); ok {
				return u.GetRecord()
			}
		}
	}
	return nil
}

// A session cannot open on a provider whose sentence no record can carry: refused
// before a sandbox is made.
func TestASessionOpenRefusesAQualificationNoRecordCanCarry(t *testing.T) {
	inner := &sandboxtest.Sessions{}
	svc := NewSandboxService(&qualifyingSessions{failingSessions: &failingSessions{Sessions: inner}, sentence: "a\nb"})
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	_, err := svc.OpenSession(authenticatedContext("alice"), openReq())
	if _, marked := notDispatchedOf(err); !marked || len(inner.Opened()) != 0 {
		t.Fatalf("open: %v (marked %v), %d sessions opened; want a marked refusal and none", err, marked, len(inner.Opened()))
	}
}

// The daemon states plimsoll's own module version from its build information: the main
// module's for plimsolld, the dependency's (or its replacement's) inside another binary,
// "(devel)" for a build that states none, and nothing rather than a malformed value.
func TestModuleVersionReadsPlimsollsVersion(t *testing.T) {
	main := func(path, v string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Path: path, Version: v}}
	}
	dep := &debug.BuildInfo{Main: debug.Module{Path: "example.com/embedder", Version: "v1.0.0"},
		Deps: []*debug.Module{{Path: plimsollModule, Version: "v0.28.0"}}}
	replaced := &debug.BuildInfo{Main: debug.Module{Path: "example.com/embedder"},
		Deps: []*debug.Module{{Path: plimsollModule, Version: "v0.28.0", Replace: &debug.Module{Path: "../plimsoll"}}}}
	for name, tc := range map[string]struct {
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		"a release":              {main(plimsollModule, "v0.28.0"), true, "v0.28.0"},
		"an untagged commit":     {main(plimsollModule, "v0.28.1-0.20261117210242-4ca8fb4d330e+dirty"), true, "v0.28.1-0.20261117210242-4ca8fb4d330e+dirty"},
		"a test binary":          {main(plimsollModule, "(devel)"), true, "(devel)"},
		"no version at all":      {main(plimsollModule, ""), true, "(devel)"},
		"a dependency":           {dep, true, "v0.28.0"},
		"a directory replace":    {replaced, true, "(devel)"},
		"no build information":   {nil, false, ""},
		"plimsoll is not listed": {main("example.com/other", "v1.0.0"), true, "(devel)"},
		"a malformed version":    {main(plimsollModule, "v0.28.0 patched"), true, ""},
	} {
		if got := moduleVersion(tc.bi, tc.ok); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	if !record.ValidDaemonVersion(daemonVersion()) || daemonVersion() == "" {
		t.Errorf("this test binary states %q", daemonVersion())
	}
}
