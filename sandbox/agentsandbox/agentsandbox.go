// Package agentsandbox runs plimsoll snippets and projects on Kubernetes agent-sandbox
// (kubernetes-sigs/agent-sandbox, v1.0.7): one SandboxClaim per run on a warm pool, the
// command sent to sandboxd (the runtime daemon in each sandbox's pod) over its gRPC process
// service, and the claim deleted after the run.
//
// agent-sandbox reports no isolation: a sandbox's boundary is whatever runtime class its
// template names, and nothing in a Sandbox's status says which. So the tier is evidence
// the provider reads, never configuration it trusts. Before any code is sent, every run
// reads its pod back (the runtime class, and that class's handler: runsc and any handler
// the operator declares as gVisor are the kernel tier, runc the container tier, the tested
// Kata handlers the VM tier, anything else refused; the image by digest; no API token
// in the pod, no host namespaces, fixed DNS, emptyDir volumes and the pod's one key volume only; sandboxd started with
// plimsoll's token digest; capabilities limited to the two the uid drop needs) and every
// network policy in the namespace that selects the pod (egress denied by one and allowed
// by none; ingress only to sandboxd's port). Unknown pod/container fields and exec handlers
// in probes or lifecycle hooks are refused; the smoke test binds policy UIDs and full specs,
// and the runtime class.
// The read-back is configuration and provider
// evidence, not attestation; the behavioural boundary test is the smoke test's.
//
// sandboxd runs as root, holding only CAP_SETUID and CAP_SETGID, and every command plimsoll
// sends is dropped to the guest uid by util-linux setpriv with no_new_privs and started
// under env -i, so guest code cannot read the root process that relayed a plan carrying the
// runner's report key. sandboxd must check plimsoll's token: without one, guest code could
// ask it, on loopback, to run a command as root. The token travels with every request, so
// each pod gets plimsoll's commands alone (the tier check, then the run's), and every request carrying the token is sent before guest
// code starts (the runner and node - both read their input to its end first): a guest
// that killed or outlived sandboxd and listened on its port would otherwise be handed it.
//
// sandboxd serves no TLS, so the image runs it on loopback behind plimsoll's TLS
// terminator, the container's command, and plimsolld reaches every pod over TLS 1.3
// alone, trusting only the deployment's CA, the configured name and, in each pod's own
// certificate, the identity of the pod it read (channel.go): the token, the code, each
// run's report key and every result are never in the clear on the pod network, never
// sent to another pod than the one read, and a pod that cannot prove itself gets
// nothing, marked not dispatched.
//
// This is its own package, as openshell is, so only a program that imports it links the
// generated process.v1 protobuf names, which agent-sandbox's own Go SDK registers too.
// Grants, module runs and sessions are not supported yet.
package agentsandbox

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
	"github.com/plimsollmark/plimsoll/sandbox/internal/lease"
	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// Name is the provider id.
const Name = "agentsandbox"

const (
	// The docker provider's timeout defaults and ceilings; a run's budget includes its
	// claim, as a docker run's includes starting its container.
	snippetDefault = 5 * time.Second
	snippetMax     = 30 * time.Second
	projectDefault = 30 * time.Second
	projectMax     = 120 * time.Second
	// runnerGrace is added to a project's budget for the outer deadline: the runner
	// enforces each step's budget and reports a hung step; the deadline is the backstop.
	runnerGrace = 5 * time.Second
	// maxOutputBytes caps a snippet's stdout and stderr, and a runner's stderr, per
	// stream: the docker provider's default.
	maxOutputBytes = 64 << 10
	// preflightTTL is how long a Preflight answer is reused, as for openshell: /readyz is
	// unauthenticated, and every check here is API calls.
	preflightTTL = 5 * time.Second
	// checkBudget bounds one evidence check, run detached from its caller.
	checkBudget = 10 * time.Second

	defaultMemoryMB = 256
	defaultCPUs     = 1.0
)

// A check's budget is held under sandbox.PreflightBound, which the daemon's readiness
// budget is derived from: a larger number here does not compile.
const _ = uint64(sandbox.PreflightBound - checkBudget)

// In the pod: the guest's uid (the docker provider's default, a uid no account uses), the
// work directory (sandboxd's --root-dir, an emptyDir), and the image's setpriv and sandboxd
// (the project runner is nativehelper.InContainer).
const (
	guestUID     = 61000
	workDir      = "/work"
	guestPath    = "/usr/local/bin:/usr/bin:/bin"
	setprivPath  = "/bin/setpriv" // util-linux's, from Alpine's setpriv package
	sandboxdPath = "/usr/local/bin/sandboxd"
)

// Config is the provider's configuration. New reads nothing from the environment.
type Config struct {
	// APIServer is the Kubernetes API server: an absolute https URL with no path (in a
	// pod, https://kubernetes.default.svc).
	APIServer string
	// CAFile is the PEM certificate authority the API server's certificate must chain to
	// (in a pod, /var/run/secrets/kubernetes.io/serviceaccount/ca.crt).
	CAFile string
	// TokenFile holds the API server's bearer token, read at every request, since a
	// projected service account token is rotated in place. Its account needs create,
	// get, list and delete on sandboxclaims; get on sandboxes, sandboxwarmpools,
	// sandboxtemplates, pods and runtimeclasses; list on networkpolicies.
	TokenFile string
	// Namespace holds the warm pool, its template and every claim.
	Namespace string
	// WarmPool names the SandboxWarmPool each run claims from.
	WarmPool string
	// RuntimeClass is the RuntimeClass the template's pods must name.
	RuntimeClass string
	// RunscHandlers are runtime class handler names, beyond runsc, that the operator
	// declares as gVisor: a containerd runtime of its own for the same shim, as one with
	// gVisor's debug log set per handler is. Each claims the kernel tier only, and the
	// startup smoke test and every pod's tier check hold it to gVisor's boot line exactly
	// as they hold runsc, so a name that maps to another runtime is refused before code
	// runs. Each must be a DNS label (the form Kubernetes requires of a handler), and
	// none may be empty, repeated, or a name handlerTiers already maps. New copies it;
	// the provider's table never changes after.
	RunscHandlers []string
	// Image is the image the template's one container must run, as the template writes
	// it. RequirePinnedImage refuses one not pinned by an @sha256: digest; a pinned image's
	// digest is checked against the pod's image ID on every run.
	Image              string
	RequirePinnedImage bool
	// SandboxdToken is the bearer token sandboxd checks. The template must start
	// sandboxd with --auth-token-sha256 set to its SHA-256 in hex.
	SandboxdToken string
	// SandboxdCAFile is the PEM certificate authority every pod's TLS certificate must
	// chain to (the deployment's own, the in-cluster issuer's; the system roots are never
	// used), read by New. SandboxdServerName is the one DNS name each certificate must
	// carry; empty is DefaultServerName. SandboxdTrustDomain is the trust domain of the
	// one URI name each must carry, the pod's identity (podIdentity); required. The pod's
	// terminator serves the certificate (channel.go).
	SandboxdCAFile      string
	SandboxdServerName  string
	SandboxdTrustDomain string
	// MemoryMB and CPUs are the limits the template's container must set: 0 is 256 MiB
	// and 1 CPU.
	MemoryMB int
	CPUs     float64
	// DiskMB, when positive, is the aggregate writable budget: the size limits of the
	// template's volumes must sum to no more than it. 0 checks no sum; every volume is
	// still a memory-backed emptyDir with a size limit.
	DiskMB int
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

func (c Config) serverName() string {
	if c.SandboxdServerName != "" {
		return c.SandboxdServerName
	}
	return DefaultServerName
}

var (
	// A namespace is a DNS label; the other names are DNS subdomains.
	labelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	nameRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	tokenRE = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{32,512}$`)
)

func validName(s string) bool { return nameRE.MatchString(s) && !strings.Contains(s, "..") }

func (c Config) validate() error {
	u, err := url.Parse(c.APIServer)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil || u.Fragment != "":
		return fmt.Errorf("agentsandbox: API server %q is not an https URL with a host and no path", c.APIServer)
	case c.CAFile == "" || c.TokenFile == "":
		return errors.New("agentsandbox: the API server's CA file and token file are required")
	case !labelRE.MatchString(c.Namespace):
		return fmt.Errorf("agentsandbox: namespace %q", c.Namespace)
	case !validName(c.WarmPool) || !validName(c.RuntimeClass):
		return fmt.Errorf("agentsandbox: warm pool %q or runtime class %q is not a valid name", c.WarmPool, c.RuntimeClass)
	case c.Image == "":
		return errors.New("agentsandbox: the image is required")
	case c.RequirePinnedImage:
		if _, ok := providerkit.PinnedDigest(c.Image); !ok {
			return fmt.Errorf("agentsandbox: image %q is not pinned by a digest, %s", c.Image, providerkit.PinForm)
		}
	}
	switch {
	case !tokenRE.MatchString(c.SandboxdToken):
		return errors.New("agentsandbox: the sandboxd token must be 32 to 512 token characters")
	case c.SandboxdCAFile == "":
		return errors.New("agentsandbox: sandboxd's CA file is required: the certificate authority its TLS certificate must chain to")
	case !validServerName(c.serverName()):
		return fmt.Errorf("agentsandbox: sandboxd's server name %q is not a DNS name", truncate(c.serverName(), 80))
	case c.SandboxdTrustDomain == "":
		return errors.New("agentsandbox: the trust domain of the pods' identities is required: each pod's certificate must name that pod alone")
	case !validServerName(c.SandboxdTrustDomain):
		return fmt.Errorf("agentsandbox: the trust domain %q is not a DNS name in lowercase", truncate(c.SandboxdTrustDomain, 80))
	case c.MemoryMB < 0 || c.CPUs < 0 || c.DiskMB < 0:
		return errors.New("agentsandbox: negative limits")
	}
	if err := checkRunscHandlers(c.RunscHandlers); err != nil {
		return fmt.Errorf("agentsandbox: declared gVisor handlers: %w", err)
	}
	return nil
}

// checkRunscHandlers refuses a declared gVisor handler list with an empty entry, a name
// that is not a DNS label, a name given twice, or a name the built-in table maps (runsc
// itself, and runc or a Kata handler, which must never be read as gVisor).
func checkRunscHandlers(names []string) error {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		switch tier, builtIn := handlerTiers[name]; {
		case name == "":
			return errors.New("an empty entry")
		case !labelRE.MatchString(name):
			return fmt.Errorf("%q is not a DNS label (lowercase letters, digits and '-', 1 to 63 characters, a letter or digit at each end)", truncate(name, 80))
		case seen[name]:
			return fmt.Errorf("%q is named twice", name)
		case builtIn:
			return fmt.Errorf("%q is a handler plimsoll already knows (the %s tier), so it cannot be declared", name, tier)
		}
		seen[name] = true
	}
	return nil
}

// Provider runs payloads on agent-sandbox.
type Provider struct {
	cfg Config
	// handlers is the tier each runtime class handler claims: handlerTiers, plus each of
	// cfg.RunscHandlers at the kernel tier. New builds it; nothing writes it after, so it
	// is read without the lock, and no provider's declarations reach another's.
	handlers map[string]sandbox.IsolationClass
	kube     *kube
	// pool is the pinned CA every pod's channel trusts (channel.go); each claim gets a
	// client of its own (channelTo).
	pool        *x509.CertPool
	tokenDigest string
	// instance labels every claim this provider makes, so ReconcileOrphans finds its own.
	instance string
	// dialAddr, when set, is the address dialed for a pod's IP (tests: a local server
	// stands in for the pod); the channel is the same pinned TLS client either way.
	dialAddr func(ip string) string

	// pf caches Preflight for preflightTTL (a field so tests can turn it off).
	pf providerkit.Check

	mu       sync.Mutex
	tier     sandbox.IsolationClass // evidence from the last check
	template string                 // the warm pool's template, from the last check
	// templateSum digests the template's name and spec, from the last check; proven is the
	// one the startup smoke test ran on, after which every other is refused.
	templateSum, proven string
	boundarySum         string           // normalized execution boundary of the checked template
	podImage            string           // image digest of the first accepted pod; every later pod must match
	policySum           string           // namespace policy UIDs and complete specs bound to the smoke test
	policyChanged       bool             // an observed difference requires a restart, even if restored
	classSum            string           // the runtime class's UID, handler, overhead and scheduling bound to the smoke test
	classChanged        bool             // as policyChanged, for the runtime class
	volumes             map[string]int64 // its container's volume mount paths and their size limits, from the last check
	smoke               *smokeEvidence   // what the last passing SmokeTest measured

	leases        lease.Set              // claims made and not yet deleted
	cleanup       providerkit.Quarantine // deletion ownership and capacity held past a failed delete
	deleteTimeout time.Duration          // one delete's budget; set by New
	skew          skewNote               // the API server's clock minus this process's, from the last create
}

var (
	_ sandbox.Sandbox          = (*Provider)(nil)
	_ sandbox.Preflighter      = (*Provider)(nil)
	_ sandbox.OrphanReconciler = (*Provider)(nil)
	_ sandbox.ProjectCapable   = (*Provider)(nil)
	_ sandbox.ModuleCapable    = (*Provider)(nil)
	_ sandbox.GrantCapable     = (*Provider)(nil)
	_ sandbox.Describer        = (*Provider)(nil)
	_ sandbox.Drainer          = (*Provider)(nil)
	_ sandbox.SmokeTester      = (*Provider)(nil)
)

// New validates cfg and returns a provider. It contacts nothing; Preflight does.
func New(cfg Config) (*Provider, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	k, err := newKube(cfg.APIServer, cfg.CAFile, cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	pool, err := readCAPool(cfg.SandboxdCAFile)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(cfg.SandboxdToken))
	// The caller's slice is not kept: Preflight validates cfg again, and an edit to it
	// after New must change neither that nor the table.
	cfg.RunscHandlers = slices.Clone(cfg.RunscHandlers)
	handlers := maps.Clone(handlerTiers)
	for _, name := range cfg.RunscHandlers {
		handlers[name] = sandbox.IsolationKernel
	}
	return &Provider{
		cfg: cfg, handlers: handlers, kube: k, pool: pool, tokenDigest: hex.EncodeToString(sum[:]),
		instance: providerkit.RandHex(8), pf: providerkit.Check{TTL: preflightTTL, Err: errors.New("agentsandbox: no check has completed yet")},
		deleteTimeout: deleteBudget,
	}, nil
}

func (*Provider) Name() string { return Name }

// IsolationClass is the tier the last check's evidence supports.
func (p *Provider) IsolationClass() sandbox.IsolationClass {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tier
}

func (p *Provider) templateName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.template
}

// mounts are the paths where the template's container mounts its volumes, with each
// volume's size limit in bytes.
func (p *Provider) mounts() map[string]int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.volumes)
}

// imageIdentity is the environment identity of an image digest, as Environments
// advertises it and as every result states it (the pod's real digest, which the read-back
// compared with the pinned one). Empty for no digest.
func imageIdentity(digest string) string {
	if digest == "" {
		return ""
	}
	return "agentsandbox-image:" + digest
}

// SupportsProjects is true: projects run through the image's project runner (the native helper).
func (*Provider) SupportsProjects() bool { return true }

// SupportsModules is false: the module worker image is a docker provider recipe.
func (*Provider) SupportsModules() bool { return false }

// Grants are not supported yet.
func (*Provider) SupportsJavaScriptGrants() bool { return false }
func (*Provider) SupportsProjectGrants() bool    { return false }

// Environments states the image digest when the image is pinned by one, which every
// run's read-back compares with the pod's image ID; a tag is not an identity.
func (p *Provider) Environments() sandbox.Environments {
	identity := ""
	if d, ok := providerkit.PinnedDigest(p.cfg.Image); ok {
		identity = imageIdentity(d)
	}
	return sandbox.Environments{
		JavaScript: sandbox.PayloadEnvironment{Identity: identity, MaxTimeout: snippetMax},
		Project:    sandbox.PayloadEnvironment{Identity: identity, MaxTimeout: projectMax},
	}
}

// Preflight validates the configuration and reads the warm pool, its template (whose pod
// spec must pass the same checks as every pod) and the runtime class, creating nothing.
// An answer is reused for preflightTTL, and the check runs detached from the caller's
// cancellation under checkBudget, so a readiness poll that hangs up cannot cache its own error.
func (p *Provider) Preflight(ctx context.Context) error {
	if err := p.cfg.validate(); err != nil {
		return err
	}
	return p.pf.Run(ctx, checkBudget, func(ctx context.Context) error {
		_, err := p.check(ctx)
		return err
	})
}

// check reads the evidence every run starts from and records the tier it supports.
// Once the startup smoke test has passed, only the template it ran on is accepted: the
// read-back rejects unknown pod and container fields, and the smoke test proved the
// boundary (where the guest can write, what it can reach) for that template alone. A changed
// template fails Preflight, so readiness, and its runs are refused, not dispatched, until
// a restart proves it, as a docker tag re-pointed after startup is.
func (p *Provider) check(ctx context.Context) (sandbox.IsolationClass, error) {
	ev, err := p.readEvidence(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil && p.proven != "" && ev.templateSum != p.proven {
		err = fmt.Errorf("agentsandbox: template %s changed after the startup smoke test proved it; plimsoll runs only on the template it proved, so restart plimsolld to prove this one", ev.template)
	}
	if err != nil {
		p.tier = sandbox.IsolationUnknown
		return p.tier, err
	}
	p.tier, p.template, p.volumes, p.templateSum, p.boundarySum = ev.tier, ev.template, ev.volumes, ev.templateSum, ev.boundarySum
	return ev.tier, nil
}

// evidence is what one check read: the tier, the warm pool's template and a digest of its
// name and spec, and the container's volume mount paths with their size limits.
type evidence struct {
	tier        sandbox.IsolationClass
	template    string
	templateSum string
	boundarySum string
	volumes     map[string]int64
}

func (p *Provider) readEvidence(ctx context.Context) (evidence, error) {
	var wp warmPool
	if err := p.kube.get(ctx, warmPoolPath(p.cfg.Namespace, p.cfg.WarmPool), &wp); err != nil {
		return evidence{}, fmt.Errorf("agentsandbox: read warm pool: %w", err)
	}
	name := wp.Spec.SandboxTemplateRef.Name
	if !validName(name) {
		return evidence{}, fmt.Errorf("agentsandbox: warm pool %s names template %q", p.cfg.WarmPool, name)
	}
	var raw json.RawMessage
	if err := p.kube.get(ctx, templatePath(p.cfg.Namespace, name), &raw); err != nil {
		return evidence{}, fmt.Errorf("agentsandbox: read template: %w", err)
	}
	var t template
	var whole struct {
		Spec json.RawMessage `json:"spec"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return evidence{}, fmt.Errorf("agentsandbox: template %s: %w", name, err)
	}
	if err := json.Unmarshal(raw, &whole); err != nil {
		return evidence{}, fmt.Errorf("agentsandbox: template %s: %w", name, err)
	}
	sum := sha256.Sum256(append([]byte(name+"\n"), whole.Spec...))
	tier, err := p.runtimeTier(ctx)
	if err != nil {
		return evidence{}, err
	}
	spec := t.Spec.PodTemplate.Spec
	if err := p.checkPodSpec(spec, tier); err != nil {
		return evidence{}, fmt.Errorf("agentsandbox: template %s: %w", name, err)
	}
	volumes, err := podMounts(spec)
	if err != nil {
		return evidence{}, fmt.Errorf("agentsandbox: template %s: %w", name, err)
	}
	boundarySum, err := podBoundary(spec)
	if err != nil {
		return evidence{}, err
	}
	return evidence{tier: tier, template: name, templateSum: hex.EncodeToString(sum[:]), boundarySum: boundarySum, volumes: volumes}, nil
}

// ready runs the checks every dispatch shares after request validation: grants are
// refused, the floor is compared with the best tier this provider can report (so an
// impossible floor costs no API call), then with the checked evidence. A failed check is
// a refusal, not dispatched.
func (p *Provider) ready(ctx context.Context, grant *sandbox.HostAPIGrant, floor sandbox.IsolationClass) (sandbox.IsolationClass, error) {
	if grant != nil {
		return sandbox.IsolationUnknown, sandbox.NotDispatched(sandbox.RefusalUnsupported,
			fmt.Errorf("%w: agentsandbox does not support grants yet", sandbox.ErrUnsupported))
	}
	if err := sandbox.CheckMinimumIsolation(sandbox.IsolationVM, floor); err != nil {
		return sandbox.IsolationUnknown, err
	}
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), checkBudget)
	tier, err := p.check(c)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return tier, sandbox.RefuseDeadline(ctx, err)
		}
		return tier, sandbox.NotDispatched(sandbox.RefusalEnvironment, providerkit.DeadlineAware(ctx, err))
	}
	return tier, sandbox.CheckMinimumIsolation(tier, floor)
}

// claimFor claims a sandbox for one run, holds its pod to its tier from inside
// (proveTier), and checks the floor against that tier. Every return with b.claim set
// needs deleteLater.
func (p *Provider) claimFor(ctx context.Context, lifetime time.Duration, floor sandbox.IsolationClass) (box, error) {
	b, err := p.claimSandbox(ctx, lifetime)
	if err == nil {
		err = p.proveTier(ctx, b)
	}
	if err != nil {
		return b, sandbox.NotDispatched(sandbox.RefusalEnvironment, providerkit.DeadlineAware(ctx, err))
	}
	if err := sandbox.CheckMinimumIsolation(b.tier, floor); err != nil {
		return b, err
	}
	return b, nil
}

// guestArgv runs argv as the guest: setpriv drops to guestUID with no supplementary
// groups and no_new_privs, and env -i starts it with PATH, HOME and env alone, not
// sandboxd's environment (which holds the pod's).
func guestArgv(env []string, argv ...string) []string {
	uid := strconv.Itoa(guestUID)
	out := []string{setprivPath, "--reuid=" + uid, "--regid=" + uid, "--clear-groups", "--no-new-privs", "--",
		"/usr/bin/env", "-i", "PATH=" + guestPath, "HOME=" + workDir}
	out = append(out, env...)
	return append(out, argv...)
}

// RunJavaScript runs req.Code with `node -`, the code on stdin, in a freshly claimed
// sandbox.
func (p *Provider) RunJavaScript(ctx context.Context, req sandbox.Request) (sandbox.Result, error) {
	fail := sandbox.Result{Sandbox: Name, Isolation: p.IsolationClass()}
	if err := sandbox.ValidateRequest(req); err != nil {
		return fail, err
	}
	if err := req.Software.Check(""); err != nil {
		return fail, err
	}
	timeout := providerkit.ClampTimeout(req.Timeout, snippetDefault, snippetMax)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tier, err := p.ready(runCtx, req.Grant, req.MinimumIsolation)
	fail.Isolation = tier
	if err != nil {
		return fail, err
	}
	b, err := p.claimFor(runCtx, timeout, req.MinimumIsolation)
	if b.claim != "" {
		defer p.deleteLater(ctx, b)
	}
	if err != nil {
		return fail, err
	}
	start := time.Now()
	out, err := p.exec(runCtx, b.ch, guestArgv(nil, sessionkit.GuestNodeArgv("-")...), []byte(req.Code), maxOutputBytes, maxOutputBytes)
	res := sandbox.Result{
		Stdout: string(out.stdout), Stderr: string(out.stderr),
		StdoutTruncated: out.stdoutTruncated, StderrTruncated: out.stderrTruncated,
		ExitCode: out.exitCode, Duration: time.Since(start), Sandbox: Name, Isolation: b.tier, Instance: b.instance,
		EnvironmentIdentity: imageIdentity(b.environment), // the signed record's environment; it was empty here (review, 2026-10-26)
	}
	if out.exited {
		return res, nil
	}
	if deadline.Expired(runCtx) == context.DeadlineExceeded {
		res.TimedOut, res.ExitCode = true, 124
		return res, nil
	}
	if ctxErr := deadline.Expired(runCtx); ctxErr != nil {
		return fail, ctxErr
	}
	return fail, err
}

// runnerCommand creates the work directory, then starts the project runner, the native
// helper, which makes itself non-dumpable before it reads its plan (no guard library: it is
// a static program); the smoke test held the image's file to the helper plimsolld carries.
var runnerCommand = []string{"sh", "-c", `mkdir -p "$PLIMSOLL_WORK" && exec ` + nativehelper.RunProjectShell}

// RunProject writes the files and runs the steps through the project runner in a freshly claimed
// sandbox, with the plan on stdin as the docker provider sends it.
func (p *Provider) RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error) {
	fail := sandbox.ProjectResult{Sandbox: Name, Isolation: p.IsolationClass()}
	if err := sandbox.ValidateProjectRequest(req); err != nil {
		return fail, err
	}
	if err := req.Software.Check(""); err != nil {
		return fail, err
	}
	timeout := providerkit.ClampTimeout(req.Timeout, projectDefault, projectMax)
	// Every process in the sandbox can write the runner's stdout, so the report is
	// authenticated with a per-run key that travels only in the plan (runnerwire).
	key, err := runnerwire.NewKey()
	if err != nil {
		return fail, err
	}
	plan := runnerwire.Plan{Steps: req.Steps, Budget: timeout, Artifacts: req.Artifacts, ReportKey: key}
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
	b, err := p.claimFor(runCtx, timeout+runnerGrace, req.MinimumIsolation)
	if b.claim != "" {
		defer p.deleteLater(ctx, b)
	}
	if err != nil {
		return fail, err
	}
	return p.runPlan(runCtx, b, planJSON, key)
}

// runPlan runs the runner with planJSON on stdin and classifies what came back, as the
// docker and openshell providers do.
func (p *Provider) runPlan(ctx context.Context, b box, planJSON, key []byte) (sandbox.ProjectResult, error) {
	res := sandbox.ProjectResult{Sandbox: Name, Isolation: b.tier, Instance: b.instance, EnvironmentIdentity: imageIdentity(b.environment)}
	argv := guestArgv([]string{"PLIMSOLL_WORK=" + workDir + "/project"}, runnerCommand...)
	out, err := p.exec(ctx, b.ch, argv, planJSON, runnerwire.StdoutCap, maxOutputBytes)
	if !out.exited {
		if deadline.Expired(ctx) == context.DeadlineExceeded {
			res.Outcome, res.Detail = sandbox.ProjectOutcomeTimedOut, "run exceeded the time budget"
			return res, nil
		}
		if ctxErr := deadline.Expired(ctx); ctxErr != nil {
			return res, ctxErr
		}
		return res, err
	}
	parsed, reported := sandbox.RunnerReport(res, string(out.stdout), key)
	if !reported {
		// The runner never reported: killed in the sandbox (an OOM kill), or the image
		// cannot run it. The detail is plimsoll's own words, never the runner's stderr,
		// which every process in the sandbox can write.
		res.Outcome, res.Detail = sandbox.ProjectOutcomeProtocolError, fmt.Sprintf("the runner did not report (it exited %d)", out.exitCode)
		return res, nil
	}
	return parsed, nil
}

// RunModule is unsupported: the module worker image is a docker provider recipe.
func (p *Provider) RunModule(_ context.Context, req sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	fail := sandbox.ModuleResult{Sandbox: Name, Isolation: p.IsolationClass()}
	if err := sandbox.ValidateModuleRequest(req); err != nil {
		return fail, err
	}
	if err := sandbox.CheckMinimumIsolation(sandbox.IsolationVM, req.MinimumIsolation); err != nil {
		return fail, err
	}
	return fail, sandbox.NotDispatched(sandbox.RefusalUnsupported, fmt.Errorf("%w: agentsandbox does not run modules", sandbox.ErrUnsupported))
}
