package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/internal/settings"
)

// dcGuardDefaultPath is the guard route when SANDBOX_DOCKERCLOUD_GUARD_URL names no
// path.
const dcGuardDefaultPath = "/v1/dockercloud/guard"

// dcDefaultPolicyURL is where the sbx CLI (v0.45.1) sends
// `PUT /sandboxes/{id}/network-policy` for --allow-network. Undocumented; see
// DockerCloud.PolicyURL.
const dcDefaultPolicyURL = "https://api.sandboxes-cloud.docker.com/v1"

func (d *DockerCloud) policyURL() string {
	if u := strings.TrimSpace(d.PolicyURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	return dcDefaultPolicyURL
}

func (d *DockerCloud) guardConfig() *guardEndpoint {
	g, err := parseGuardURL(d.GuardURL, settings.DockercloudGuardURL.Name, dcGuardDefaultPath)
	if err != nil {
		return nil
	}
	return g
}

// errDCGrantsRefused is why every host-API grant is refused on dockercloud, before
// any sandbox is created. A grant run's one network rule is the guard's host:443,
// and Docker documents that its network rules match the hostname attributed to the
// connection, such as its TLS Server Name Indication (SNI), a name the guest
// chooses (https://docs.docker.com/ai/governance/local/network-rules/). So the rule
// cannot hold a granted run to the guard. The refusal stays until Docker offers a
// rule it enforces on the server a connection reaches and a startup check under it
// proves a granted run reaches the guard and nothing else.
var errDCGrantsRefused = fmt.Errorf("%w: dockercloud refuses host-API grants: its network rules match the host name a connection announces (its TLS SNI, as Docker documents), so no rule holds a run to the guard; run granted code on docker, e2b or openshell", ErrUnsupported)

// EgressGuardPath, EgressGuardKnownToken and EgressGuardCall make dockercloud an
// EgressGuardCapable provider; plimsolld mounts the shared handler at the path, and
// mounts none while grants are refused.
func (d *DockerCloud) EgressGuardPath() string {
	if !d.grantsServed() {
		return ""
	}
	if g := d.guardConfig(); g != nil {
		return g.Path
	}
	return ""
}

func (d *DockerCloud) EgressGuardKnownToken(token string) bool { return d.guards.lookup(token) != nil }

func (d *DockerCloud) EgressGuardCall(ctx context.Context, token string, call GuardRequest) EgressGuardResponse {
	return d.guards.call(ctx, token, call)
}

// dcGuard is one grant run's guard: the endpoint the guest calls, the per-run
// credential it sends, and the broker session that enforces the grant.
type dcGuard struct {
	endpoint *guardEndpoint
	token    string
	core     *brokerSession
}

// endDCGuard ends a run's grant (a guard call after it is refused) and returns its
// trace, which then holds every call the grant served. Nil-safe and repeatable.
func endDCGuard(guard *dcGuard) *CallTrace {
	if guard == nil {
		return nil
	}
	guard.core.End()
	return guard.core.traceSnapshot()
}

// allowRule is the single network rule a grant run's sandbox gets: the guard host
// on 443, nothing else.
func (g *dcGuard) allowRule() string { return g.endpoint.Host + ":443" }

// refuseGrant is the refusal of every host-API grant (errDCGrantsRefused), marked
// not dispatched with the reason unsupported: another provider may take the run. Each
// run calls it right after the request's own validation and before its configuration
// check, so a well-formed granted run is refused for the grant whatever else is wrong
// (a malformed one is refused as a request); openGuard calls it again.
func (d *DockerCloud) refuseGrant(grant *HostAPIGrant) error {
	if grant == nil || d.grantsUnrefused {
		return nil
	}
	return refused(errDCGrantsRefused)
}

// openGuard registers a per-run guard credential for a grant. A nil grant returns a
// nil guard (a deny-all run). Every grant is refused, marked not dispatched with the
// reason unsupported, while errDCGrantsRefused stands; without a configured guard
// URL, or on REST, it would be refused too.
func (d *DockerCloud) openGuard(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (*dcGuard, func(), error) {
	if grant == nil {
		return nil, func() {}, nil
	}
	if err := d.refuseGrant(grant); err != nil {
		return nil, func() {}, err
	}
	if d.rest() {
		// The guard's rule goes on through an undocumented call (putNetworkPolicy).
		// On a REST-created sandbox the call is accepted, but the REST API then
		// refuses to report the sandbox's policy (live 2026-10-04: 409 "installed
		// network policy is unavailable for this sandbox"), so a grant run there
		// could not prove its network before running anything.
		return nil, func() {}, refused(fmt.Errorf("%w: dockercloud host-API grants cannot be verified on the REST API; use SANDBOX_DOCKERCLOUD_API=connect", ErrUnsupported))
	}
	endpoint := d.guardConfig()
	if endpoint == nil {
		return nil, func() {}, refused(fmt.Errorf("%w: dockercloud host-API grants require SANDBOX_DOCKERCLOUD_GUARD_URL", ErrUnsupported))
	}
	token, core, cleanup, err := d.guards.open(ctx, grant, timeout, nil)
	if err != nil {
		return nil, func() {}, err
	}
	return &dcGuard{endpoint: endpoint, token: token, core: core}, cleanup, nil
}

// putNetworkPolicy applies a deny-all policy with exactly the given allow rules to
// one sandbox, through the undocumented REST call the sbx CLI uses (PolicyURL). The
// response must echo the same policy; the caller still verifies the effective
// policy through the published contract before running anything.
func (d *DockerCloud) putNetworkPolicy(ctx context.Context, vm dcVM, allow []string) error {
	body, err := json.Marshal(map[string]any{"mode": "deny-all", "allowNetworks": allow})
	if err != nil {
		return err
	}
	target := d.policyURL() + "/sandboxes/" + url.PathEscape(vm.id) + "/network-policy"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	tok, err := d.bearer(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("dockercloud set network policy: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("dockercloud set network policy: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dockercloud set network policy: HTTP %d: %s", resp.StatusCode, truncateForError(strings.TrimSpace(string(raw))))
	}
	var echo struct {
		Mode          string   `json:"mode"`
		AllowNetworks []string `json:"allowNetworks"`
	}
	if err := json.Unmarshal(raw, &echo); err != nil || echo.Mode != "deny-all" || !sameStrings(echo.AllowNetworks, allow) {
		return fmt.Errorf("dockercloud set network policy: service answered %s, not the requested policy", truncateForError(string(raw)))
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// verifyEgressDenied reads the sandbox's effective network policy back from the
// service and refuses to run unless it is deny-all with nothing allowed. An older
// server drops inline policies silently (the contract's own warning on
// Capabilities.can_attach_policies), and a governance layer could add allow rules,
// so the request alone is not evidence.
func (d *DockerCloud) verifyEgressDenied(ctx context.Context, vm dcVM) error {
	return d.verifyEgress(ctx, vm, nil)
}

// dcHostModulePath is where a grant project run stages the guard client module.
const dcHostModulePath = "/tmp/plimsoll-dockercloud-host.mjs"

// sealNetwork makes the sandbox's network what the run is entitled to, and proves
// it before any caller code runs. A no-grant run must read back deny-all with
// nothing allowed. A grant run first gets exactly one rule, the guard's host:443
// (putNetworkPolicy), and must then read back exactly that. Until the rule is
// applied the sandbox is deny-all, so every failure here fails closed.
func (d *DockerCloud) sealNetwork(ctx context.Context, vm dcVM, guard *dcGuard) error {
	if guard == nil {
		return d.verifyEgressDenied(ctx, vm)
	}
	allow := []string{guard.allowRule()}
	if err := d.putNetworkPolicy(ctx, vm, allow); err != nil {
		return err
	}
	return d.verifyEgress(ctx, vm, allow)
}

// verifyEgress reads the sandbox's effective network policy back from the service
// and refuses the run unless it is deny-all with exactly the
// allowed networks: none for a no-grant run, the guard's host:443 for a grant run.
// An extra rule from any layer (kit, owner, org) refuses the run too.
func (d *DockerCloud) verifyEgress(ctx context.Context, vm dcVM, allowed []string) error {
	pol, err := d.wire().effectivePolicy(ctx, vm)
	if err != nil {
		return fmt.Errorf("dockercloud verify egress policy: %w", err)
	}
	if !pol.denyAll {
		return fmt.Errorf("dockercloud verify egress policy: effective mode is %q, not deny-all", pol.mode)
	}
	got := pol.allow
	if !sameStrings(got, allowed) {
		if len(allowed) == 0 {
			return fmt.Errorf("dockercloud verify egress policy: %d allow rule(s) in force on a no-grant run", len(got))
		}
		return fmt.Errorf("dockercloud verify egress policy: allowed %v, want exactly %v", got, allowed)
	}
	return nil
}
