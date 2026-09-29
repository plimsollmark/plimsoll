// Package openshell runs plimsoll snippets and projects in NVIDIA OpenShell
// sandboxes, through an OpenShell gateway's gRPC API (openshell.v1, vendored at
// v0.1.2 under third_party/openshell and generated into gen/go/openshell).
//
// Every run gets its own sandbox. The provider creates it with plimsoll's policy
// (runPolicy: no network rules, so the gateway's deny-all egress default holds; a
// filesystem allowlist in which /tmp is the only writable directory), reads the policy
// back and refuses the run on any difference, execs the payload over
// ExecSandboxInteractive, returns the result, and deletes the sandbox off the result
// path. The run's deadline is enforced by cancelling the exec stream, which kills the
// command and its process group on the docker driver (a descendant that detached with
// setsid survives until the delete); the request's execution_timeout does not (the
// gateway stops waiting and invents exit 124 while the process keeps running).
//
// The tier is evidence, not configuration: GetGatewayInfo must name the docker compute
// driver, reported as container, and any other driver is refused until plimsoll has
// tested it. Host-API grants reach the shared broker through a relay in the sandbox
// that plimsoll dials into with ForwardTcp (grant.go), so a granted run keeps the
// no-grant policy; module runs are unsupported.
//
// Every sandbox carries its creator's instance label and a declared lifetime (the
// run's deadline), because OpenShell sandboxes never expire: ReconcileOrphans reaps
// its own instance's untracked sandboxes at once and any other plimsoll sandbox that
// has outlived its declaration, so a crashed daemon's leftovers do not live forever.
//
// This is its own package, not part of package sandbox, because the generated code
// registers openshell.v1 protobuf names that OpenShell's own Go SDK registers too, and
// protobuf-go refuses to start a program that links both. Only a program that imports
// this package links the registrations and connect-go.
package openshell

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1/openshellv1connect"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/sandboxv1"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// Name is the provider id.
const Name = "openshell"

const (
	// The docker provider's timeout defaults and ceilings. A run's budget includes
	// creating its sandbox (about 0.55 s on the docker driver with a local image), as a
	// docker run's includes starting its container.
	snippetDefault = 5 * time.Second
	snippetMax     = 30 * time.Second
	projectDefault = 30 * time.Second
	projectMax     = 120 * time.Second
	// runnerGrace is added to a project's budget for the outer deadline, as in the
	// docker provider: the runner enforces each step's budget itself and reports a
	// hung step, and the deadline is the backstop.
	runnerGrace = 5 * time.Second
	// maxOutputBytes caps a snippet's stdout and stderr, and a project runner's stderr,
	// per stream: the docker provider's default.
	maxOutputBytes = 64 << 10
	// maxMessageBytes bounds one gRPC message read from the gateway. Exec output
	// arrives in small events (about 4 KiB each, measured) and a sandbox record is a
	// few KiB, so this only stops a pathological message from being buffered whole.
	maxMessageBytes = 4 << 20

	// preflightTTL is how long a Preflight answer is reused: the docker provider's
	// cache window. The daemon serves /readyz without authentication, and here every
	// check is a gateway call, so without it anyone who can reach /readyz could make
	// the daemon call the gateway as fast as they can send requests.
	preflightTTL = 5 * time.Second

	defaultMemoryMB = 256
	defaultCPUs     = 1.0
	// minMemoryMB is docker's minimum container memory limit.
	minMemoryMB = 6
	// minCPUs is docker's smallest CPU limit.
	minCPUs = 0.01
)

// Config is the provider's configuration. New reads nothing from the environment.
type Config struct {
	// GatewayURL is the gateway's endpoint: an absolute https URL with a host, an
	// optional port and no path, for example https://127.0.0.1:17670.
	GatewayURL string
	// CAFile is the PEM certificate authority the gateway's server certificate must
	// chain to. CertFile and KeyFile are the PEM client certificate and key the
	// gateway's mutual TLS verifies.
	CAFile   string
	CertFile string
	KeyFile  string
	// Image is the OCI image every sandbox boots. It must carry node, sh and
	// /runner.mjs, as plimsoll/sandbox does.
	Image string
	// RequirePinnedImage refuses an Image that is not pinned by an @sha256: digest.
	RequirePinnedImage bool
	// MemoryMB and CPUs are each sandbox's limits. They are requested at create and
	// read back after it; 0 takes 256 MiB and 1 CPU. OpenShell's own default is no
	// limit at all, so a limit is always requested.
	MemoryMB int
	CPUs     float64
	// PidsLimit and DiskMB must be 0: OpenShell sets the process limit for every
	// sandbox of a gateway (the docker driver's sandbox_pids_limit), and has no disk
	// control.
	PidsLimit int
	DiskMB    int
}

func (c Config) memoryMB() int {
	if c.MemoryMB > 0 {
		return c.MemoryMB
	}
	return defaultMemoryMB
}

func (c Config) cpus() float64 {
	if c.CPUs > 0 {
		return c.CPUs
	}
	return defaultCPUs
}

// validate is the structural check New runs. It reads no file and calls nothing.
func (c Config) validate() error {
	if _, err := parseGatewayURL(c.GatewayURL); err != nil {
		return err
	}
	if c.CAFile == "" || c.CertFile == "" || c.KeyFile == "" {
		return errors.New("openshell: the gateway CA, client certificate and client key files are all required (the gateway uses mutual TLS)")
	}
	image := c.Image
	if image == "" {
		return errors.New("openshell: an image is required (it must carry node, sh and /runner.mjs)")
	}
	if strings.IndexFunc(image, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("openshell: image %q contains whitespace or control characters", image)
	}
	if c.RequirePinnedImage && !isDigestPinned(image) {
		return fmt.Errorf("openshell: image %q is not pinned to an immutable @sha256: digest, and a pinned image is required", image)
	}
	if c.MemoryMB < 0 || (c.MemoryMB > 0 && c.MemoryMB < minMemoryMB) {
		return fmt.Errorf("openshell: memory limit %d MiB must be 0 (the 256 MiB default) or at least %d MiB", c.MemoryMB, minMemoryMB)
	}
	if math.IsNaN(c.CPUs) || math.IsInf(c.CPUs, 0) || c.CPUs < 0 || (c.CPUs > 0 && c.CPUs < minCPUs) {
		return fmt.Errorf("openshell: CPU limit %v must be 0 (the 1 CPU default) or a finite number of at least %v", c.CPUs, minCPUs)
	}
	if c.PidsLimit != 0 {
		return errors.New("openshell cannot enforce a per-sandbox process limit (SANDBOX_PIDS): the gateway sets one for all of its sandboxes; leave it unset")
	}
	if c.DiskMB != 0 {
		return errors.New("openshell cannot enforce a per-sandbox disk limit (SANDBOX_DISK_MB): OpenShell has no disk control; leave it unset")
	}
	return nil
}

func parseGatewayURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("openshell: gateway URL %q must be an absolute https URL with a host and no path, credentials, query or fragment", raw)
	}
	return u, nil
}

// isDigestPinned reports whether an image reference is pinned to an immutable
// content digest (…@sha256:<hex>) rather than a mutable tag.
func isDigestPinned(image string) bool {
	const marker = "@sha256:"
	i := strings.LastIndex(image, marker)
	if i <= 0 {
		return false
	}
	digest := image[i+len(marker):]
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// httpClient builds the mutual-TLS HTTP/2 client. It never uses an environment
// proxy (the client certificate authenticates to the gateway only) and never
// follows a redirect.
func (c Config) httpClient() (*http.Client, error) {
	caPEM, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("openshell: read gateway CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("openshell: no PEM certificate in gateway CA file %s", c.CAFile)
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("openshell: load client certificate: %w", err)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// Provider runs plimsoll payloads in OpenShell sandboxes. It implements
// sandbox.Sandbox and the optional Preflighter, SmokeTester, OrphanReconciler,
// ProjectCapable, ModuleCapable, GrantCapable, Describer, Drainer and
// SessionProvider interfaces.
type Provider struct {
	cfg        Config
	client     openshellv1connect.OpenShellClient
	policy     *sandboxv1.SandboxPolicy
	policyHash string
	resources  *structpb.Struct
	// instance labels every sandbox this provider creates, so ReconcileOrphans finds
	// its own and never another instance's.
	instance string
	// killWait is how long SmokeTest waits for a cancelled command's processes to go.
	killWait time.Duration
	// staleAfter is staleMargin, a field so the live suite can wait seconds, not minutes.
	staleAfter time.Duration
	// skew is the gateway's clock minus this process's, measured at each create
	// (clockSkew). orphaned reads another instance's sandbox age on the gateway's
	// clock with it, and reaps no other instance's sandbox before a measurement.
	skewMu     sync.Mutex
	skew       time.Duration
	skewKnown  bool
	skewWarned bool

	// The Preflight cache (preflightTTL; pfTTL is a field so tests can turn it off).
	pfMu      sync.Mutex
	pfTTL     time.Duration
	pfAt      time.Time // when the last check finished; zero until one has
	pfErr     error     // its answer
	pfRunning bool      // a check is in flight

	mu       sync.Mutex
	tier     sandbox.IsolationClass // evidence from the last driver check
	tierLost bool                   // a check failed after one had passed, and none has passed since
	version  string                 // the gateway version the last driver check reported
	tracked  map[string]struct{}    // created and not yet deleted
	smoke    *smokeEvidence         // the last passing SmokeTest's measurements
	sessions map[*session]struct{}  // open sessions, which Drain ends
}

var (
	_ sandbox.Sandbox          = (*Provider)(nil)
	_ sandbox.Preflighter      = (*Provider)(nil)
	_ sandbox.SmokeTester      = (*Provider)(nil)
	_ sandbox.OrphanReconciler = (*Provider)(nil)
	_ sandbox.ProjectCapable   = (*Provider)(nil)
	_ sandbox.ModuleCapable    = (*Provider)(nil)
	_ sandbox.GrantCapable     = (*Provider)(nil)
	_ sandbox.Describer        = (*Provider)(nil)
	_ sandbox.Drainer          = (*Provider)(nil)
	_ sandbox.SessionProvider  = (*Provider)(nil)
)

// New validates cfg, loads the TLS material and returns a provider. It does not
// contact the gateway; Preflight and SmokeTest do.
func New(cfg Config) (*Provider, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	hc, err := cfg.httpClient()
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(cfg.GatewayURL, "/")
	return newProvider(cfg, openshellv1connect.NewOpenShellClient(hc, base,
		connect.WithGRPC(), connect.WithReadMaxBytes(maxMessageBytes)))
}

func newProvider(cfg Config, client openshellv1connect.OpenShellClient) (*Provider, error) {
	policy := runPolicy()
	hash, err := policyHash(policy)
	if err != nil {
		return nil, err
	}
	resources, err := resourceLimits(cfg.memoryMB(), cfg.cpus())
	if err != nil {
		return nil, err
	}
	return &Provider{
		cfg:        cfg,
		client:     client,
		policy:     policy,
		policyHash: hash,
		resources:  resources,
		instance:   randHex(8),
		killWait:   15 * time.Second,
		staleAfter: staleMargin,
		pfTTL:      preflightTTL,
		pfErr:      errors.New("openshell: no gateway check has completed yet"),
		tracked:    make(map[string]struct{}),
		sessions:   make(map[*session]struct{}),
	}, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Name is "openshell".
func (*Provider) Name() string { return Name }

// IsolationClass is the tier the last driver check established: container while the
// gateway reports the docker driver, unknown before the first check and after a
// failed one. It is configuration and gateway evidence plus the startup smoke test,
// never runtime attestation, and on the docker driver it cannot tell runc from another
// OCI runtime: OpenShell never selects or reports one.
func (p *Provider) IsolationClass() sandbox.IsolationClass {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tier
}

// SupportsProjects is true: projects run through the image's /runner.mjs.
func (*Provider) SupportsProjects() bool { return true }

// SupportsModules is false: the module worker image is a docker provider recipe.
func (*Provider) SupportsModules() bool { return false }

// Host-API grants reach the shared broker through ForwardTcp and an in-sandbox relay
// (grant.go), for snippets and projects alike.
func (*Provider) SupportsJavaScriptGrants() bool { return true }
func (*Provider) SupportsProjectGrants() bool    { return true }

// Environments states the image digest when the image is pinned by one (a digest
// reference names its content); a tag is not an identity. The policy is named by
// the hash the gateway itself reports for it, which every run's read-back
// compares.
func (p *Provider) Environments() sandbox.Environments {
	identity := ""
	if isDigestPinned(p.cfg.Image) {
		identity = "openshell-image:" + strings.ToLower(p.cfg.Image[strings.LastIndex(p.cfg.Image, "@")+1:])
	}
	return sandbox.Environments{
		JavaScript: sandbox.PayloadEnvironment{Identity: identity, MaxTimeout: snippetMax},
		Project:    sandbox.PayloadEnvironment{Identity: identity, MaxTimeout: projectMax},
		Policy:     "openshell-policy:sha256:" + p.policyHash,
	}
}

// Preflight validates the configuration and asks the gateway which compute driver it
// runs (a cheap read that creates nothing), refusing anything but docker. It proves
// the gateway is reachable with this identity; SmokeTest proves behavior.
//
// An answer is reused for preflightTTL, and a call made while a check is in flight
// gets the last answer at once (not ready, before any check has finished), so an
// unauthenticated /readyz flood costs the gateway one call per window. The check
// runs detached from the caller's cancellation, under its own 10 s bound, so a probe
// that hangs up cannot leave "context canceled" as the cached answer.
func (p *Provider) Preflight(ctx context.Context) error {
	if err := p.cfg.validate(); err != nil {
		return err
	}
	p.pfMu.Lock()
	if p.pfRunning || (!p.pfAt.IsZero() && time.Since(p.pfAt) < p.pfTTL) {
		err := p.pfErr
		p.pfMu.Unlock()
		return err
	}
	p.pfRunning = true
	p.pfMu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, err := p.checkDriver(ctx)
	p.pfMu.Lock()
	p.pfAt, p.pfErr, p.pfRunning = time.Now(), err, false
	p.pfMu.Unlock()
	return err
}

func clampTimeout(req, def, max time.Duration) time.Duration {
	if req <= 0 {
		req = def
	}
	if req > max {
		req = max
	}
	return req
}

// deadlineAware keeps the caller's deadline recognizable: a create that ran out of
// time is reported as context.DeadlineExceeded rather than as whatever transport
// error the cancelled call produced.
func deadlineAware(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %v", ctxErr, err)
	}
	return err
}

// ready runs the checks every dispatch shares after request validation: the grant's
// own validity, the request's floor against the best tier this provider can report
// (so an impossible floor costs no gateway call), the driver check, and the floor
// against that evidence.
func (p *Provider) ready(ctx context.Context, grant *sandbox.HostAPIGrant, floor sandbox.IsolationClass) (sandbox.IsolationClass, error) {
	if grant != nil {
		if err := grant.Validate(); err != nil {
			return sandbox.IsolationUnknown, sandbox.NotDispatched(sandbox.RefusalRequest, fmt.Errorf("%w: %v", sandbox.ErrInvalidRequest, err))
		}
	}
	if err := sandbox.CheckMinimumIsolation(sandbox.IsolationContainer, floor); err != nil {
		return sandbox.IsolationUnknown, err
	}
	tier, err := p.checkDriver(ctx)
	if err != nil {
		return tier, deadlineAware(ctx, err)
	}
	return tier, sandbox.CheckMinimumIsolation(tier, floor)
}

// RunJavaScript runs req.Code with `node -`, the code on stdin, in a fresh sandbox.
func (p *Provider) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	fail := sandbox.Result{Sandbox: Name, Isolation: p.IsolationClass()}
	if err := sandbox.ValidateRequest(req); err != nil {
		return fail, err
	}
	timeout := clampTimeout(req.Timeout, snippetDefault, snippetMax)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tier, err := p.ready(runCtx, req.Grant, req.MinimumIsolation)
	fail.Isolation = tier
	if err != nil {
		return fail, err
	}
	b, err := p.create(runCtx)
	if err != nil {
		return fail, deadlineAware(runCtx, err)
	}
	defer p.deleteLater(b)
	code, env := req.Code, map[string]string(nil)
	var g *grantRun
	if req.Grant != nil {
		if g, err = p.startGrant(runCtx, b, req.Grant, timeout); err != nil {
			return fail, deadlineAware(runCtx, err)
		}
		defer g.Close()
		code, env = sandbox.HostClientSnippet(req.Code, req.Grant), g.env()
	}

	start := time.Now()
	out, err := p.exec(runCtx, b, []string{"node", "-"}, env, []byte(code), maxOutputBytes, maxOutputBytes)
	res := sandbox.Result{
		Stdout:          string(out.stdout),
		Stderr:          string(out.stderr),
		StdoutTruncated: out.stdoutTruncated,
		StderrTruncated: out.stderrTruncated,
		ExitCode:        out.exitCode,
		Duration:        time.Since(start),
		Sandbox:         Name,
		Isolation:       tier,
	}
	if g != nil {
		res.CallTrace = g.broker.Trace()
	}
	if out.exited {
		return res, nil // the exit status is authoritative, whatever the send side saw
	}
	if runCtx.Err() == context.DeadlineExceeded {
		// Cancelling the stream at the deadline killed the command's process group; the
		// delete that follows the run ends anything that detached.
		res.TimedOut, res.ExitCode = true, 124
		return res, nil
	}
	// The brokered calls happened whatever became of the exec stream.
	fail.CallTrace = res.CallTrace
	if ctxErr := runCtx.Err(); ctxErr != nil {
		return fail, ctxErr
	}
	return fail, err
}

// runnerCommand starts the in-image runner with its work directory created first:
// the runner writes files under it but only creates the directories files need, and
// a project with no files would otherwise start its steps in a directory that does
// not exist. The gateway runs the command through a shell with each argument quoted.
var runnerCommand = []string{"sh", "-c", `mkdir -p "$PLIMSOLL_WORK" && exec node ` + runnerPath}

// RunProject writes the files and runs the steps through /runner.mjs in a fresh
// sandbox, with the plan on stdin as the docker provider sends it.
func (p *Provider) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	fail := sandbox.ProjectResult{Sandbox: Name, Isolation: p.IsolationClass()}
	if err := sandbox.ValidateProjectRequest(req); err != nil {
		return fail, err
	}
	timeout := clampTimeout(req.Timeout, projectDefault, projectMax)
	// Every process in the sandbox can write the runner's stdout, so the report is
	// authenticated with a per-run key that travels only in the plan (runnerwire).
	key, err := runnerwire.NewKey()
	if err != nil {
		return fail, err
	}
	plan := runnerwire.Plan{Steps: req.Steps, StepTimeout: timeout, Artifacts: req.Artifacts, HostSDK: sandbox.HostClientModule(req.Grant), ReportKey: key}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, runnerwire.File(f))
	}
	planJSON, err := plan.Encode()
	if err != nil {
		return fail, err
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout+runnerGrace)
	defer cancel()
	tier, err := p.ready(runCtx, req.Grant, req.MinimumIsolation)
	fail.Isolation = tier
	if err != nil {
		return fail, err
	}
	b, err := p.create(runCtx)
	if err != nil {
		return fail, deadlineAware(runCtx, err)
	}
	defer p.deleteLater(b)
	var g *grantRun
	if req.Grant != nil {
		if g, err = p.startGrant(runCtx, b, req.Grant, timeout+runnerGrace); err != nil {
			return fail, deadlineAware(runCtx, err)
		}
		defer g.Close()
	}
	res, err := p.runPlan(runCtx, b, tier, planJSON, key, g)
	if g != nil {
		res.CallTrace = g.broker.Trace()
	}
	return res, err
}

// runPlan execs the runner in an existing sandbox with planJSON on stdin and
// classifies what came back, as the docker provider's runPlan does. key is the
// report key planJSON carries; g, when not nil, is the run's grant, whose socket the
// steps reach through the environment.
func (p *Provider) runPlan(ctx context.Context, b box, tier sandbox.IsolationClass, planJSON, key []byte, g *grantRun) (sandbox.ProjectResult, error) {
	res := sandbox.ProjectResult{Sandbox: Name, Isolation: tier}
	env := map[string]string{"PLIMSOLL_WORK": workDir}
	if g != nil {
		for k, v := range g.env() {
			env[k] = v
		}
	}
	out, err := p.exec(ctx, b, runnerCommand, env, planJSON, runnerwire.StdoutCap, maxOutputBytes)
	if !out.exited {
		if ctx.Err() == context.DeadlineExceeded {
			res.Outcome, res.Detail = sandbox.ProjectOutcomeTimedOut, "run exceeded the time budget"
			return res, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return res, ctxErr
		}
		return res, err
	}
	report, found, parseErr := runnerwire.Parse(string(out.stdout), key)
	if !found {
		// The sandbox started the command but the runner never reported: it may have
		// been killed inside the sandbox (an OOM kill), or the image cannot run it.
		// Execution state is unknown, so this is a protocol error. The detail is
		// plimsoll's own words, never the runner's stderr: it reaches the audit line,
		// and every process in the sandbox can write that stream.
		res.Outcome, res.Detail = sandbox.ProjectOutcomeProtocolError, fmt.Sprintf("the runner did not report (it exited %d)", out.exitCode)
		return res, nil
	}
	if errors.Is(parseErr, runnerwire.ErrUnauthenticated) {
		res.Outcome, res.Detail = sandbox.ProjectOutcomeProtocolError, "no authenticated runner report"
		return res, nil
	}
	if parseErr != nil {
		res.Outcome, res.Detail = sandbox.ProjectOutcomeProtocolError, "could not parse sandbox result"
		return res, nil
	}
	for _, s := range report.Steps {
		res.Steps = append(res.Steps, sandbox.StepResult(s))
	}
	for _, a := range report.Artifacts {
		res.Artifacts = append(res.Artifacts, sandbox.Artifact(a))
	}
	res.ArtifactsTruncated = report.ArtifactsTruncated
	outcome, detail := report.Outcome()
	res.Outcome, res.Detail = sandbox.ProjectOutcomeCompleted, detail
	switch outcome {
	case runnerwire.SetupFailed:
		res.Outcome = sandbox.ProjectOutcomeSetupFailed
	case runnerwire.TimedOut:
		res.Outcome = sandbox.ProjectOutcomeTimedOut
	}
	return res, nil
}

// RunModule is unsupported: the module worker image is a docker provider recipe.
func (p *Provider) RunModule(_ context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	fail := sandbox.ModuleResult{Sandbox: Name, Isolation: p.IsolationClass()}
	if err := sandbox.ValidateModuleRequest(req); err != nil {
		return fail, err
	}
	if err := sandbox.CheckMinimumIsolation(sandbox.IsolationContainer, req.MinimumIsolation); err != nil {
		return fail, err
	}
	return fail, sandbox.NotDispatched(sandbox.RefusalUnsupported,
		fmt.Errorf("%w: openshell does not run modules", sandbox.ErrUnsupported))
}
