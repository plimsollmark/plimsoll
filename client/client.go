// Package client dials a remote plimsolld and adapts it to sandbox.Sandbox, so
// isolated calls can swap providers behind the same interface. RPC capabilities
// use operation-specific named server profiles, not raw grants. Keyless by default;
// set WithToken to authenticate against a fail-closed server (the token needs the
// code:run scope).
package client

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Remote is a sandbox.Sandbox backed by a remote plimsolld over Connect.
type Remote struct {
	client       plimsollv1connect.SandboxServiceClient
	token        string
	jsGrant      string
	projectGrant string
}

// ErrRawGrantUnsupported prevents a capability-bearing in-process request from
// being silently downgraded to an isolated remote run. RPC grants are server-held
// named profiles selected with the operation-specific options below.
var ErrRawGrantUnsupported = errors.New("client: a raw HostAPIGrant cannot be sent over RPC; configure an operation-specific named grant profile")

// Option configures a Remote.
type Option func(*config)

type config struct {
	httpClient   connect.HTTPClient
	token        string
	jsGrant      string
	projectGrant string
	insecureHTTP bool
	opts         []connect.ClientOption
}

// maxResponseBytes is above the largest legitimate project response (bounded
// step output plus the aggregate artifact cap) while preventing a compromised or
// misconfigured server from making an embedding client buffer an unlimited unary
// response.
const maxResponseBytes = 32 << 20

// WithHTTPClient overrides the HTTP client (default: 6-minute timeout client).
func WithHTTPClient(c connect.HTTPClient) Option { return func(cfg *config) { cfg.httpClient = c } }

// WithToken sends "Authorization: Bearer <token>" on every call. Omit it for a
// keyless (dev/open) server.
func WithToken(token string) Option { return func(cfg *config) { cfg.token = token } }

// WithJavaScriptGrantProfile selects a named server-side capability only for
// RunJavaScript. Grant support differs by operation; applying one profile to every
// call made isolated project runs fail on providers that only broker snippets.
func WithJavaScriptGrantProfile(profile string) Option {
	return func(cfg *config) { cfg.jsGrant = profile }
}

// WithProjectGrantProfile selects a named server-side capability only for
// RunProject. Call Describe first: no built-in provider currently advertises this
// capability.
func WithProjectGrantProfile(profile string) Option {
	return func(cfg *config) { cfg.projectGrant = profile }
}

// WithInsecureHTTP explicitly permits cleartext HTTP to a non-loopback host.
// Omit it in production: without this opt-in New fails closed so code:run bearer
// credentials and submitted source cannot silently cross an unencrypted network.
func WithInsecureHTTP() Option {
	return func(cfg *config) { cfg.insecureHTTP = true }
}

// WithConnectOptions passes extra connect client options (e.g. gRPC, gzip).
func WithConnectOptions(o ...connect.ClientOption) Option {
	return func(cfg *config) { cfg.opts = append(cfg.opts, o...) }
}

type traceKey struct{}

// NewTraceContext returns ctx carrying an opaque correlation id that RunJavaScript
// and RunProject will send with the run. The daemon records it on that run's audit
// line and does nothing else with it, which lets a caller JOIN plimsoll's
// metadata-only record to its own record of the same request — the reason
// plimsoll can decline to keep a second copy of the path and body without
// leaving "which record did the agent read" unanswerable.
//
// It is a context value rather than a client Option because the id is per REQUEST,
// not per connection: one embedded client serves many runs, and a connection-scoped
// id would stamp them all the same. That also matches where such an id already
// lives: an upstream MCP proxy can carry one across its boundary, and its server
// can pass that same value to NewTraceContext.
//
// The id must be opaque: [A-Za-z0-9._:-] up to 64 bytes, or the server drops it.
// Put no meaning in it. The meaning belongs in the caller's log.
func NewTraceContext(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, traceKey{}, id)
}

// TraceIDFrom returns the correlation id carried by ctx, or "". A run without one
// is the normal case for a caller that does not correlate its logs.
func TraceIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(traceKey{}).(string)
	return id
}

var (
	// ErrInvalidBaseURL marks malformed, relative, or non-HTTP(S) endpoints.
	ErrInvalidBaseURL = errors.New("client: invalid plimsoll base URL")
	// ErrInsecureHTTP marks a non-loopback cleartext endpoint that was not
	// explicitly authorized with WithInsecureHTTP.
	ErrInsecureHTTP = errors.New("client: cleartext HTTP to a non-loopback plimsoll requires WithInsecureHTTP")
)

// New returns a checked Remote dialing an absolute HTTP(S) base URL. Loopback
// HTTP is allowed for local development; cleartext transport to any other host
// requires the explicit WithInsecureHTTP option.
func New(baseURL string, opts ...Option) (*Remote, error) {
	cfg := &config{httpClient: &http.Client{Timeout: 6 * time.Minute}}
	for _, o := range opts {
		o(cfg)
	}
	checkedURL, err := validateBaseURL(baseURL, cfg.insecureHTTP)
	if err != nil {
		return nil, err
	}
	connectOpts := []connect.ClientOption{connect.WithReadMaxBytes(maxResponseBytes)}
	connectOpts = append(connectOpts, cfg.opts...)
	return &Remote{
		client:       plimsollv1connect.NewSandboxServiceClient(cfg.httpClient, checkedURL, connectOpts...),
		token:        cfg.token,
		jsGrant:      cfg.jsGrant,
		projectGrant: cfg.projectGrant,
	}, nil
}

func validateBaseURL(raw string, allowInsecureHTTP bool) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return "", fmt.Errorf("%w: URL must be non-empty and contain no surrounding whitespace", ErrInvalidBaseURL)
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("%w: must be an absolute HTTP or HTTPS URL", ErrInvalidBaseURL)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("%w: scheme must be http or https", ErrInvalidBaseURL)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return "", fmt.Errorf("%w: userinfo, query, and fragment are not permitted", ErrInvalidBaseURL)
	}
	if scheme == "http" && !isLoopbackHost(u.Hostname()) && !allowInsecureHTTP {
		return "", ErrInsecureHTTP
	}
	u.Scheme = scheme
	return u.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// timeoutMs converts a Duration to the proto int32 milliseconds field, clamping
// rather than truncating: a budget beyond int32 (~24.8 days) would otherwise wrap to
// a negative/short value, silently enforcing a far shorter deadline than requested.
func timeoutMs(d time.Duration) int32 {
	ms := d.Milliseconds()
	if d <= 0 {
		return 0
	}
	if ms == 0 {
		return 1
	}
	if ms > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(ms)
}

func minimumIsolationWire(minimum sandbox.IsolationClass) string {
	if minimum == sandbox.IsolationUnknown {
		return ""
	}
	return minimum.String()
}

func (r *Remote) Name() string { return "plimsoll-rpc" }

// IsolationClass is Unknown: a remote server's provider — and thus its boundary
// tier — cannot be asserted locally before a call. Each response reports the tier
// the run actually used (Result.Isolation / ProjectResult.Isolation).
func (r *Remote) IsolationClass() sandbox.IsolationClass { return sandbox.IsolationUnknown }

func (r *Remote) auth(req interface{ Header() http.Header }) {
	if r.token != "" {
		req.Header().Set("Authorization", "Bearer "+r.token)
	}
}

// Info is a remote plimsolld's self-description: which provider is active,
// its isolation tier, and whether RunProject works there.
type Info struct {
	Sandbox                  string
	Isolation                sandbox.IsolationClass
	SupportsProject          bool
	SupportsJavaScriptGrants bool
	SupportsProjectGrants    bool
	SupportsMinimumIsolation bool
}

// Describe asks the server for its active provider's measured capabilities, so a
// consumer advertises facts instead of assuming a tier the provider may not honor.
func (r *Remote) Describe(ctx context.Context) (Info, error) {
	req := connect.NewRequest(&plimsollv1.DescribeRequest{})
	r.auth(req)
	resp, err := r.client.Describe(ctx, req)
	if err != nil {
		return Info{}, restoreSandboxError(err)
	}
	return Info{
		Sandbox:                  resp.Msg.GetSandbox(),
		Isolation:                sandbox.ParseIsolationClass(resp.Msg.GetIsolation()),
		SupportsProject:          resp.Msg.GetSupportsProject(),
		SupportsJavaScriptGrants: resp.Msg.GetSupportsJavascriptGrants(),
		SupportsProjectGrants:    resp.Msg.GetSupportsProjectGrants(),
		SupportsMinimumIsolation: resp.Msg.GetSupportsMinimumIsolation(),
	}, nil
}

func (r *Remote) RunJavaScript(ctx context.Context, in sandbox.Request) (sandbox.Result, error) {
	if err := sandbox.ValidateRequest(in); err != nil {
		return sandbox.Result{Sandbox: r.Name()}, err
	}
	if in.Grant != nil {
		return sandbox.Result{Sandbox: r.Name()}, ErrRawGrantUnsupported
	}
	req := connect.NewRequest(&plimsollv1.RunJavaScriptV2Request{
		Code:             in.Code,
		TimeoutMs:        timeoutMs(in.Timeout),
		GrantProfile:     r.jsGrant,
		MinimumIsolation: minimumIsolationWire(in.MinimumIsolation),
		TraceId:          TraceIDFrom(ctx),
	})
	r.auth(req)
	resp, err := r.client.RunJavaScriptV2(ctx, req)
	if err != nil {
		return sandbox.Result{Sandbox: r.Name()}, restoreSandboxError(err)
	}
	m := resp.Msg
	result := sandbox.Result{
		Stdout:          string(m.GetStdout()),
		Stderr:          string(m.GetStderr()),
		StdoutTruncated: m.GetStdoutTruncated(),
		StderrTruncated: m.GetStderrTruncated(),
		ExitCode:        int(m.GetExitCode()),
		TimedOut:        m.GetTimedOut(),
		Duration:        time.Duration(m.GetDurationMs()) * time.Millisecond,
		Sandbox:         m.GetSandbox(),
		Isolation:       sandbox.ParseIsolationClass(m.GetIsolation()),
		Advice:          adviceFromWire(m.GetAdvice()),
	}
	if err := sandbox.CheckResultIsolation(result.Isolation, in.MinimumIsolation); err != nil {
		return result, connect.NewError(connect.CodeDataLoss, err)
	}
	return result, nil
}

func (r *Remote) RunProject(ctx context.Context, in sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	if err := sandbox.ValidateProjectRequest(in); err != nil {
		return sandbox.ProjectResult{Sandbox: r.Name()}, err
	}
	if in.Grant != nil {
		return sandbox.ProjectResult{Sandbox: r.Name()}, ErrRawGrantUnsupported
	}
	preq := &plimsollv1.RunProjectV2Request{
		Steps:            in.Steps,
		TimeoutMs:        timeoutMs(in.Timeout),
		Artifacts:        in.Artifacts,
		GrantProfile:     r.projectGrant,
		MinimumIsolation: minimumIsolationWire(in.MinimumIsolation),
		TraceId:          TraceIDFrom(ctx),
	}
	for _, f := range in.Files {
		preq.Files = append(preq.Files, &plimsollv1.ProjectFile{Path: f.Path, Content: f.Content})
	}
	req := connect.NewRequest(preq)
	r.auth(req)
	resp, err := r.client.RunProjectV2(ctx, req)
	if err != nil {
		return sandbox.ProjectResult{Sandbox: r.Name()}, restoreSandboxError(err)
	}
	m := resp.Msg
	out := sandbox.ProjectResult{
		Sandbox:            m.GetSandbox(),
		Isolation:          sandbox.ParseIsolationClass(m.GetIsolation()),
		Outcome:            outcomeFromWire(m.GetOutcome()),
		Detail:             m.GetOutcomeDetail(),
		ArtifactsTruncated: m.GetArtifactsTruncated(),
		Advice:             adviceFromWire(m.GetAdvice()),
	}
	for _, s := range m.GetSteps() {
		out.Steps = append(out.Steps, sandbox.StepResult{
			Command:         s.GetCommand(),
			Stdout:          string(s.GetStdout()),
			Stderr:          string(s.GetStderr()),
			StdoutTruncated: s.GetStdoutTruncated(),
			StderrTruncated: s.GetStderrTruncated(),
			ExitCode:        int(s.GetExitCode()),
			TimedOut:        s.GetTimedOut(),
			Duration:        time.Duration(s.GetDurationMs()) * time.Millisecond,
		})
	}
	for _, a := range m.GetArtifacts() {
		out.Artifacts = append(out.Artifacts, sandbox.Artifact{Path: a.GetPath(), Content: a.GetContent()})
	}
	if err := sandbox.CheckResultIsolation(out.Isolation, in.MinimumIsolation); err != nil {
		return out, connect.NewError(connect.CodeDataLoss, err)
	}
	return out, nil
}

// adviceFromWire retains the caller's post-dispatch evidence for both operations.
// The service selects the audience; the client neither analyzes nor grants routes.
func adviceFromWire(in []*plimsollv1.AdviceFinding) []sandbox.AdviceFinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]sandbox.AdviceFinding, 0, len(in))
	for _, f := range in {
		out = append(out, sandbox.AdviceFinding{
			Pattern: f.GetPattern(), Severity: f.GetSeverity(), Remedy: f.GetRemedy(),
			Method: f.GetMethod(), Route: f.GetRoute(), Detail: f.GetDetail(),
			SuggestedMethod: f.GetSuggestedMethod(), SuggestedRoute: f.GetSuggestedRoute(),
			ExtraCalls:   int(f.GetExtraCalls()),
			AddedLatency: time.Duration(f.GetAddedLatencyMs()) * time.Millisecond,
			BytesMoved:   f.GetBytesMoved(),
		})
	}
	return out
}

// outcomeFromWire maps the wire enum back to the sandbox package's typed project
// outcome. An unrecognized (future) value maps to Unspecified rather than being
// guessed at; strict consumers treat that like a protocol mismatch.
func outcomeFromWire(o plimsollv1.ProjectOutcome) sandbox.ProjectOutcome {
	switch o {
	case plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED:
		return sandbox.ProjectOutcomeCompleted
	case plimsollv1.ProjectOutcome_PROJECT_OUTCOME_SETUP_FAILED:
		return sandbox.ProjectOutcomeSetupFailed
	case plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT:
		return sandbox.ProjectOutcomeTimedOut
	case plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR:
		return sandbox.ProjectOutcomeProtocolError
	default:
		return sandbox.ProjectOutcomeUnspecified
	}
}

// restoreSandboxError preserves Sandbox's local sentinel contract across RPC while
// retaining the underlying Connect error (and therefore its status code/details).
// This keeps errors.Is behavior identical when a consumer swaps a local provider
// for Remote.
func restoreSandboxError(err error) error {
	if err == nil {
		return nil
	}
	var sentinel error
	switch connect.CodeOf(err) {
	case connect.CodeCanceled:
		sentinel = context.Canceled
	case connect.CodeDeadlineExceeded:
		sentinel = context.DeadlineExceeded
	case connect.CodeFailedPrecondition:
		// FailedPrecondition also covers a per-run isolation floor. Preserve the
		// more specific sandbox sentinel when plimsolld sent it; otherwise this
		// remains the established disabled-provider condition.
		if strings.Contains(err.Error(), sandbox.ErrInsufficientIsolation.Error()) {
			sentinel = sandbox.ErrInsufficientIsolation
		} else {
			sentinel = sandbox.ErrDisabled
		}
	case connect.CodeUnimplemented:
		sentinel = sandbox.ErrUnsupported
	case connect.CodeResourceExhausted:
		sentinel = sandbox.ErrAtCapacity
	case connect.CodeInvalidArgument:
		sentinel = sandbox.ErrInvalidRequest
	}
	if sentinel == nil || errors.Is(err, sentinel) {
		return err
	}
	return errors.Join(sentinel, err)
}

// compile-time check
var _ sandbox.Sandbox = (*Remote)(nil)
