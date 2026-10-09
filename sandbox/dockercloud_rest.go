package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// dcREST is the REST transport: the API Docker has documented since its launch on
// 2026-09-24 (https://docs.docker.com/reference/api/sandboxes/), whose base URL is
// https://connect.docker.com/sandboxes. "Probe (2026-10-04)" marks behavior measured
// live against one sandbox that day; the live suite is what keeps it checked.
//
// Two credentials, never mixed. The management API takes the bearer exchanged from the
// personal access token, like Connect. The sandbox endpoint, where exec and file calls
// go, refuses it (probe: 401 "invalid endpoint credential") and takes a sandbox-scoped
// credential, cached per sandbox (credential). A credential lives at most 300 s, and
// an exec still running when its credential expires is cut off (probe: 401
// ENDPOINT_CREDENTIAL_EXPIRED after 299.6 s), so a call uses a credential only if it
// outlives the call's deadline, and a run is capped at dcRESTMaxRun.
//
// It embeds the provider for its configuration and the shared token exchange.
type dcREST struct{ *DockerCloud }

var _ dcTransport = dcREST{}

const (
	// dcRESTCredentialTTL is the longest life the API grants an endpoint credential
	// (maxTtl 300s, reported per sandbox).
	dcRESTCredentialTTL = 300 * time.Second
	// dcRESTGetAttempts bounds the retries of a GET the API answered 429.
	dcRESTGetAttempts = 4
	// dcRESTDeleteRereads bounds how often a delete re-reads a sandbox whose ETag
	// changed under it.
	dcRESTDeleteRereads = 5
)

// ---- calls ----

// dcRESTCamel matches the capitals of a camelCase API error code.
var dcRESTCamel = regexp.MustCompile(`[A-Z]`)

// dcRESTErrorFrom parses an API error body. Its codes are Connect's, in camelCase
// (failedPrecondition for failed_precondition), so they become a dcRPCError and the
// refused and not-found rules apply unchanged. A body that is not the API's error (a
// proxy's page) falls back to the HTTP status; a bare 404 there is a route not served,
// never a missing sandbox.
func dcRESTErrorFrom(op string, status int, raw []byte) error {
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Code != "" {
		code := strings.ToLower(dcRESTCamel.ReplaceAllString(body.Code, "_$0"))
		return &dcRPCError{Procedure: op, HTTPStatus: status, Code: code, Message: body.Message}
	}
	code := "unknown"
	switch status {
	case http.StatusBadRequest:
		code = "invalid_argument"
	case http.StatusUnauthorized:
		code = "unauthenticated"
	case http.StatusForbidden:
		code = "permission_denied"
	case http.StatusNotFound, http.StatusNotImplemented:
		code = "unimplemented"
	case http.StatusConflict:
		code = "aborted"
	case http.StatusPreconditionFailed, http.StatusPreconditionRequired:
		code = "failed_precondition"
	case http.StatusTooManyRequests:
		code = "resource_exhausted"
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		code = "unavailable"
	}
	return &dcRPCError{Procedure: op, HTTPStatus: status, Code: code, Message: strings.TrimSpace(string(raw))}
}

// dcRESTAnswer is one answered request, its body read to a bound.
type dcRESTAnswer struct {
	status int
	header http.Header
	raw    []byte
	over   bool // the body was longer than the bound and was not kept
}

// send makes one request. token empty sends the management bearer; otherwise it is a
// sandbox endpoint credential. A failure before the request left is a dcUnsentError.
func (d dcREST) send(ctx context.Context, method, target, token string, header http.Header, body []byte, limit int64) (dcRESTAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return dcRESTAnswer{}, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if token == "" {
		if token, err = d.bearer(ctx); err != nil {
			return dcRESTAnswer{}, &dcUnsentError{err}
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if err := ctx.Err(); err != nil {
		return dcRESTAnswer{}, &dcUnsentError{err}
	}
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return dcRESTAnswer{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return dcRESTAnswer{}, err
	}
	if int64(len(raw)) > limit {
		return dcRESTAnswer{status: resp.StatusCode, header: resp.Header, over: true}, nil
	}
	return dcRESTAnswer{status: resp.StatusCode, header: resp.Header, raw: raw}, nil
}

// manage is one management call with an optional JSON body. It succeeds on any 2xx
// whose body fits dcMaxUnaryResponse; the caller reads the body. A GET the API
// answered 429 is tried again after a pause (probe: one 429 after rapid calls); no
// other method is, since a repeated POST or DELETE may act twice.
func (d dcREST) manage(ctx context.Context, op, method, path string, header http.Header, in any) (dcRESTAnswer, error) {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return dcRESTAnswer{}, err
		}
		header = header.Clone()
		if header == nil {
			header = http.Header{}
		}
		header.Set("Content-Type", "application/json")
	}
	for attempt := 1; ; attempt++ {
		ans, err := d.send(ctx, method, d.apiBase()+path, "", header, body, dcMaxUnaryResponse)
		if err != nil {
			return ans, err
		}
		if ans.over {
			return ans, fmt.Errorf("dockercloud %s: response exceeds %d bytes", op, dcMaxUnaryResponse)
		}
		if ans.status == http.StatusTooManyRequests && method == http.MethodGet && attempt < dcRESTGetAttempts {
			if err := sleepCtx(ctx, dcRESTRetryAfter(ans.header, attempt)); err != nil {
				return ans, err
			}
			continue
		}
		if ans.status < 200 || ans.status > 299 {
			return ans, dcRESTErrorFrom(op, ans.status, ans.raw)
		}
		return ans, nil
	}
}

// dcRESTRetryAfter is the pause before retry attempt+1: the API's Retry-After in whole
// seconds when it sends one, at most 5 s, else a second per attempt so far.
func dcRESTRetryAfter(h http.Header, attempt int) time.Duration {
	if secs, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After"))); err == nil && secs >= 0 {
		return min(time.Duration(secs)*time.Second, 5*time.Second)
	}
	return time.Duration(attempt) * time.Second
}

func dcRESTSandboxPath(uid string) string { return "/v1/sandboxes/" + url.PathEscape(uid) }

// ---- sandboxes ----

type dcRESTSandbox struct {
	UID         string `json:"uid"`
	DisplayName string `json:"displayName"`
	Core        struct {
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"createdAt"`
		Etag      string    `json:"etag"`
		ImageRef  string    `json:"imageRef"`
		Resources *struct {
			Cpus      *protoUint `json:"cpus"`
			MemoryMib *protoUint `json:"memoryMib"`
		} `json:"resources"`
		Endpoint *struct {
			URI          string   `json:"uri"`
			Protocol     string   `json:"protocol"`
			Capabilities []string `json:"capabilities"`
		} `json:"endpoint"`
	} `json:"core"`
	Failure *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"failure"`
}

// dcRESTEndpointNeeds are the endpoint capabilities a run uses.
var dcRESTEndpointNeeds = []string{"exec", "upload", "download"}

func (s dcRESTSandbox) view() dcSandboxView {
	v := dcSandboxView{id: s.UID, name: s.DisplayName, recordedImage: s.Core.ImageRef}
	if ep := s.Core.Endpoint; ep != nil {
		v.endpoint = ep.URI
		switch {
		case ep.Protocol != "" && ep.Protocol != "http":
			// unixSocket is a local backend's endpoint, not the cloud's.
			v.endpointRefused = fmt.Errorf("dockercloud create sandbox: endpoint protocol %s is not HTTP", truncateForError(ep.Protocol))
		default:
			for _, need := range dcRESTEndpointNeeds {
				found := false
				for _, c := range ep.Capabilities {
					found = found || c == need
				}
				if !found {
					v.endpointRefused = fmt.Errorf("dockercloud create sandbox: the sandbox endpoint does not serve %s", need)
					break
				}
			}
		}
	}
	if r := s.Core.Resources; r != nil {
		v.cpus, v.memoryMiB = r.Cpus, r.MemoryMib
	}
	return v
}

func (s dcRESTSandbox) running() bool {
	return s.Core.Status == "running" && s.Core.Endpoint != nil && s.Core.Endpoint.URI != ""
}

// terminal: a status from which a new sandbox never comes to run.
func (s dcRESTSandbox) terminal() bool {
	switch s.Core.Status {
	case "failed", "stopping", "stopped", "deleting", "degraded":
		return true
	}
	return false
}

func (s dcRESTSandbox) failure() string {
	if s.Failure == nil {
		return ""
	}
	return ": " + truncateForError(s.Failure.Code+" "+s.Failure.Message)
}

func (d dcREST) createSandbox(ctx context.Context, spec dcCreateSpec) (dcReported, error) {
	in := map[string]any{
		"displayName": spec.name,
		"imageRef":    spec.image,
		// Pinned so the booted platform cannot change under the operator.
		"platform":  map[string]any{"os": "linux", "architecture": "amd64"},
		"resources": map[string]any{"cpus": spec.cpus, "memoryMib": spec.memoryMiB},
		// A raw image's own entrypoint never runs: the start command keeps the
		// sandbox alive for the run's execs.
		"startupExecution": map[string]any{"rawImage": map[string]any{"start": map[string]any{"argv": spec.startCmd}}},
		"features": map[string]any{"timeouts": map[string]any{
			"timeout": protoDuration(spec.ttl), "onTimeout": "delete", "autoResume": false,
		}},
		// No networkPolicies: while the account's default policy (deny-all, set by
		// the operator) governs, the API refuses a create that carries any (probe:
		// 409 failedPrecondition, "network_policies cannot be enforced while a local
		// account-default policy governs this sandbox"). verifyEgressDenied reads the
		// effective policy back before any guest code runs.
	}
	// The key replays to the same sandbox for 24 hours (probe: same uid, 201), so a
	// retried create cannot make a second one.
	header := http.Header{"Idempotency-Key": {spec.name}}
	ans, err := d.manage(ctx, "create sandbox", http.MethodPost, "/v1/sandboxes", header, in)
	if err != nil {
		return nil, &dcCreateError{stage: dcCreateSend, err: fmt.Errorf("dockercloud create sandbox: %w", err)}
	}
	var sb dcRESTSandbox
	// mine is the ID an error carries for the cleanup's delete: only one the service
	// shows under this create's name, since an ID under another name could be another
	// run's sandbox (round-3 review); otherwise the cleanup deletes by name.
	mine := func(sb dcRESTSandbox) string {
		if sb.DisplayName == spec.name {
			return sb.UID
		}
		return ""
	}
	if err := json.Unmarshal(ans.raw, &sb); err != nil || sb.UID == "" {
		// Answered, but not with a sandbox this code can name: whatever it made is
		// found by its display name, and until then the outcome is unknown.
		return nil, &dcCreateError{stage: dcCreateWait, err: errors.New("dockercloud create sandbox: the answer names no sandbox")}
	}
	for !sb.running() {
		if sb.terminal() {
			return nil, &dcCreateError{stage: dcCreateDone, id: mine(sb),
				err: fmt.Errorf("dockercloud create sandbox: sandbox reached status %s instead of running%s", truncateForError(sb.Core.Status), sb.failure())}
		}
		if err := sleepCtx(ctx, 250*time.Millisecond); err != nil {
			return nil, &dcCreateError{stage: dcCreateWait, id: mine(sb), err: fmt.Errorf("dockercloud create sandbox: %w", err)}
		}
		next, _, found, err := d.read(ctx, sb.UID)
		if err == nil && !found {
			err = errors.New("the sandbox disappeared while starting")
		}
		if err != nil {
			return nil, &dcCreateError{stage: dcCreateWait, id: mine(sb), err: fmt.Errorf("dockercloud create sandbox: %w", err)}
		}
		sb = next
	}
	if sb.DisplayName != spec.name {
		// Orphan reaping finds this instance's sandboxes by display name alone, so one
		// recorded under another name could never be reaped.
		return nil, &dcCreateError{stage: dcCreateDone, foreign: true,
			err: fmt.Errorf("dockercloud create sandbox: service recorded display name %q, requested %q", truncateForError(sb.DisplayName), spec.name)}
	}
	return sb, nil
}

// read gets one sandbox and its ETag. found is false only for the API's own notFound
// answer.
func (d dcREST) read(ctx context.Context, uid string) (sb dcRESTSandbox, etag string, found bool, err error) {
	ans, err := d.manage(ctx, "get sandbox", http.MethodGet, dcRESTSandboxPath(uid), nil, nil)
	if dcCodeIs(err, "not_found") {
		return dcRESTSandbox{}, "", false, nil
	}
	if err != nil {
		return dcRESTSandbox{}, "", false, err
	}
	if err := json.Unmarshal(ans.raw, &sb); err != nil {
		return dcRESTSandbox{}, "", false, fmt.Errorf("dockercloud get sandbox: unparseable response: %w", err)
	}
	// Sent as a header and as core.etag (probe; the header came lowercase, which
	// http.Header reads either way).
	etag = ans.header.Get("ETag")
	if etag == "" {
		etag = sb.Core.Etag
	}
	return sb, etag, true, nil
}

// deleteSandbox deletes one sandbox and waits until a read finds it gone. The delete's
// own answer proves nothing (probe: 204 for a sandbox that does not exist, whatever the
// ETag), so existed means a read found the sandbox and a later read did not. Without
// an ID, every sandbox with the name is deleted.
func (d dcREST) deleteSandbox(ctx context.Context, vm dcVM, _ string) (existed bool, err error) {
	if vm.id != "" {
		return d.deleteUID(ctx, vm.id)
	}
	uids, err := d.findByName(ctx, vm.name)
	if err != nil {
		return false, fmt.Errorf("dockercloud delete sandbox: %w", err)
	}
	for _, uid := range uids {
		gone, err := d.deleteUID(ctx, uid)
		if err != nil {
			return existed, err
		}
		existed = existed || gone
	}
	return existed, nil
}

func (d dcREST) deleteUID(ctx context.Context, uid string) (existed bool, err error) {
	sent := false
	for reread := 0; !sent; reread++ {
		if reread == dcRESTDeleteRereads {
			return existed, fmt.Errorf("dockercloud delete sandbox: its ETag changed %d times in a row", reread)
		}
		sb, etag, found, err := d.read(ctx, uid)
		if err != nil {
			return existed, fmt.Errorf("dockercloud delete sandbox: %w", err)
		}
		if !found {
			return existed, nil
		}
		existed = true
		if sb.Core.Status == "deleting" {
			break // already on its way out: wait for it
		}
		if etag == "" {
			return existed, errors.New("dockercloud delete sandbox: the sandbox reports no ETag, which the delete requires")
		}
		// If-Match is required (428 without it; `*` is refused).
		_, err = d.manage(ctx, "delete sandbox", http.MethodDelete, dcRESTSandboxPath(uid)+"?force=true", http.Header{"If-Match": {etag}}, nil)
		switch {
		case err == nil:
			sent = true
		case dcCodeIs(err, "failed_precondition"), dcCodeIs(err, "not_found"):
			// Changed or gone since the read: read again.
		default:
			return existed, fmt.Errorf("dockercloud delete sandbox: %w", err)
		}
	}
	for {
		_, _, found, err := d.read(ctx, uid)
		if err != nil {
			return existed, fmt.Errorf("dockercloud delete sandbox: %w", err)
		}
		if !found {
			d.forgetCredential(uid)
			return existed, nil
		}
		if err := sleepCtx(ctx, 250*time.Millisecond); err != nil {
			return existed, fmt.Errorf("dockercloud delete sandbox: still present: %w", err)
		}
	}
}

// findByName lists every page for the sandboxes with this display name. The API's
// filter matches whole values only; matching here keeps one rule for both uses.
func (d dcREST) findByName(ctx context.Context, name string) ([]string, error) {
	var uids []string
	token := ""
	for page := 0; page < dcMaxListPages; page++ {
		sandboxes, next, err := d.listSandboxes(ctx, token)
		if err != nil {
			return nil, err
		}
		for _, sb := range sandboxes {
			if sb.name == name && sb.id != "" {
				uids = append(uids, sb.id)
			}
		}
		if next == "" {
			return uids, nil
		}
		token = next
	}
	return nil, fmt.Errorf("list sandboxes: more than %d pages", dcMaxListPages)
}

func (d dcREST) listSandboxes(ctx context.Context, pageToken string) ([]dcListed, string, error) {
	q := url.Values{"pageSize": {"100"}}
	if pageToken != "" {
		q.Set("pageToken", pageToken)
	}
	ans, err := d.manage(ctx, "list sandboxes", http.MethodGet, "/v1/sandboxes?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, "", err
	}
	var out struct {
		Sandboxes     []dcRESTSandbox `json:"sandboxes"`
		NextPageToken string          `json:"nextPageToken"`
	}
	if err := json.Unmarshal(ans.raw, &out); err != nil {
		return nil, "", fmt.Errorf("dockercloud list sandboxes: unparseable response: %w", err)
	}
	page := make([]dcListed, 0, len(out.Sandboxes))
	for _, sb := range out.Sandboxes {
		page = append(page, dcListed{name: sb.DisplayName, id: sb.UID, createdAt: sb.Core.CreatedAt})
	}
	return page, out.NextPageToken, nil
}

// checkCapabilities: the REST API has no capability service and states no size range,
// so this proves what it can, that the URL serves the API and the token may list
// sandboxes. The endpoint's own capabilities are checked on each new sandbox (view),
// and a size the service does not offer is refused at create.
func (d dcREST) checkCapabilities(ctx context.Context) error {
	if _, err := d.manage(ctx, "list sandboxes", http.MethodGet, "/v1/sandboxes?pageSize=1", nil, nil); err != nil {
		return fmt.Errorf("list sandboxes: %w", err)
	}
	return nil
}

func (d dcREST) effectivePolicy(ctx context.Context, vm dcVM) (dcPolicy, error) {
	ans, err := d.manage(ctx, "get network policies", http.MethodGet, dcRESTSandboxPath(vm.id)+"/network-policies", nil, nil)
	if err != nil {
		return dcPolicy{}, err
	}
	var pol struct {
		Effective *struct {
			Mode          string `json:"mode"`
			AllowNetworks []struct {
				Network string `json:"network"`
			} `json:"allowNetworks"`
		} `json:"effective"`
	}
	if err := json.Unmarshal(ans.raw, &pol); err != nil {
		return dcPolicy{}, fmt.Errorf("unparseable response: %w", err)
	}
	if pol.Effective == nil {
		return dcPolicy{}, errors.New("the answer has no effective policy")
	}
	out := dcPolicy{mode: pol.Effective.Mode, denyAll: pol.Effective.Mode == "denyAll"}
	out.allow = make([]string, 0, len(pol.Effective.AllowNetworks))
	for _, a := range pol.Effective.AllowNetworks {
		out.allow = append(out.allow, a.Network)
	}
	return out, nil
}

// ---- the sandbox endpoint ----

// dcRESTCred is a sandbox's cached endpoint credential.
type dcRESTCred struct {
	token   string
	expires time.Time
}

// dcRESTCredMargin is how long a cached credential must outlive the call's deadline to
// be used for it.
const dcRESTCredMargin = 10 * time.Second

// dcRESTPermissions are what a run does on the endpoint: run commands, write files,
// read files.
var dcRESTPermissions = []string{"sandboxesExec", "sandboxesFilesWrite", "sandboxesFilesRead"}

// credential returns a credential for one sandbox that outlives the call's deadline by
// dcRESTCredMargin, minting one when the cached one would not (or fresh asks for a new
// one). One credential serves the whole run: the live service answered 429 to a mint
// per call (2026-10-04), and a run of at most dcRESTMaxRun fits in one credential's
// life. It never leaves the host.
func (d dcREST) credential(ctx context.Context, vm dcVM, fresh bool) (string, error) {
	need := time.Now().Add(dcRESTCredentialTTL)
	if deadline, ok := ctx.Deadline(); ok {
		need = deadline.Add(dcRESTCredMargin)
	}
	d.restCredMu.Lock()
	c, ok := d.restCreds[vm.id]
	d.restCredMu.Unlock()
	if ok && !fresh && c.expires.After(need) {
		return c.token, nil
	}
	in := map[string]any{"permissions": dcRESTPermissions, "ttl": protoDuration(dcRESTCredentialTTL)}
	var ans dcRESTAnswer
	var err error
	for attempt := 1; ; attempt++ {
		minted := time.Now()
		ans, err = d.manage(ctx, "mint endpoint credential", http.MethodPost, dcRESTSandboxPath(vm.id)+"/endpoint-credentials", nil, in)
		// Minting again is harmless, so a mint the service rate-limited is tried
		// again after a pause.
		if dcCodeIs(err, "resource_exhausted") && attempt < dcRESTGetAttempts {
			if err := sleepCtx(ctx, dcRESTRetryAfter(ans.header, attempt)); err != nil {
				return "", err
			}
			continue
		}
		if err != nil {
			return "", err
		}
		var out struct {
			Token      string    `json:"token"`
			ExpireTime time.Time `json:"expireTime"`
		}
		if err := json.Unmarshal(ans.raw, &out); err != nil || out.Token == "" {
			return "", errors.New("dockercloud mint endpoint credential: the answer holds no token")
		}
		// The earlier of the two, so a clock behind the service's cannot stretch it.
		c = dcRESTCred{token: out.Token, expires: minted.Add(dcRESTCredentialTTL)}
		if !out.ExpireTime.IsZero() && out.ExpireTime.Before(c.expires) {
			c.expires = out.ExpireTime
		}
		break
	}
	d.restCredMu.Lock()
	if d.restCreds == nil {
		d.restCreds = map[string]dcRESTCred{}
	}
	for id, old := range d.restCreds {
		if time.Now().After(old.expires) {
			delete(d.restCreds, id)
		}
	}
	d.restCreds[vm.id] = c
	d.restCredMu.Unlock()
	return c.token, nil
}

// forgetCredential drops a deleted sandbox's credential.
func (d dcREST) forgetCredential(uid string) {
	d.restCredMu.Lock()
	delete(d.restCreds, uid)
	d.restCredMu.Unlock()
}

// dcRESTCredentialExpired reports an endpoint 401 for an expired credential, which can
// arrive after a command ran (probe: an exec cut at 299.6 s), unlike any other 401,
// which refuses the request before anything runs.
func dcRESTCredentialExpired(raw []byte) bool {
	var body struct {
		Details []struct {
			Reason string `json:"reason"`
		} `json:"details"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return false
	}
	for _, det := range body.Details {
		if det.Reason == "ENDPOINT_CREDENTIAL_EXPIRED" {
			return true
		}
	}
	return false
}

// dcRESTTryAgain reports an endpoint answer worth one more try with a fresh credential:
// a 401 that refused the request before anything ran. One upload was refused that way
// with a credential minted a moment earlier (live, 2026-10-04).
func dcRESTTryAgain(status int, raw []byte) bool {
	return status == http.StatusUnauthorized && !dcRESTCredentialExpired(raw)
}

// endpoint is one call to the sandbox endpoint. A failed mint is a dcUnsentError:
// nothing reached the endpoint.
func (d dcREST) endpoint(ctx context.Context, vm dcVM, method, path string, header http.Header, body []byte, limit int64) (dcRESTAnswer, error) {
	for attempt := 1; ; attempt++ {
		token, err := d.credential(ctx, vm, attempt > 1)
		if err != nil {
			return dcRESTAnswer{}, &dcUnsentError{err}
		}
		ans, err := d.send(ctx, method, vm.endpoint+path, token, header, body, limit)
		if err == nil && attempt == 1 && dcRESTTryAgain(ans.status, ans.raw) {
			if err := sleepCtx(ctx, time.Second); err != nil {
				return dcRESTAnswer{}, err
			}
			continue
		}
		return ans, err
	}
}

// exec runs cmd with one unary exec. flooded reports a body longer than limit, or the
// API's own cut (incomplete, at 4 MiB of output in the probe): either means the
// in-guest caps did not hold, which only guest code working around them can cause.
func (d dcREST) exec(ctx context.Context, vm dcVM, cmd []string, cwd string, limit int64) (dcExecResponse, bool, error) {
	in := map[string]any{"cmd": cmd}
	if cwd != "" {
		in["workingDir"] = cwd
	}
	body, _ := json.Marshal(in)
	ans, err := d.endpoint(ctx, vm, http.MethodPost, "/v1/processes/exec",
		http.Header{"Content-Type": {"application/json"}}, body, limit)
	if err != nil {
		return dcExecResponse{}, false, err
	}
	if ans.status != http.StatusOK {
		return dcExecResponse{}, false, dcRESTErrorFrom("exec", ans.status, ans.raw)
	}
	if ans.over {
		return dcExecResponse{}, true, nil
	}
	var out struct {
		dcExecResponse
		Incomplete bool `json:"incomplete"`
	}
	if err := json.Unmarshal(ans.raw, &out); err != nil {
		return dcExecResponse{}, false, fmt.Errorf("dockercloud exec: unparseable response: %w", err)
	}
	if out.Incomplete {
		return dcExecResponse{}, true, nil
	}
	return out.dcExecResponse, false, nil
}

// upload writes every file in one multipart request: per file a metadata part, then
// its bytes in a content part. The part names are the spec's (probe: the SDK's
// "header" is refused), and the service creates parent directories (probe).
func (d dcREST) upload(ctx context.Context, vm dcVM, files []File) error {
	if len(files) == 0 {
		return nil
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for _, f := range files {
		meta, _ := json.Marshal(map[string]any{"path": f.Path, "mode": 0o644})
		part, err := w.CreatePart(textproto.MIMEHeader{
			"Content-Disposition": {`form-data; name="metadata"`}, "Content-Type": {"application/json"}})
		if err != nil {
			return err
		}
		_, _ = part.Write(meta)
		part, err = w.CreatePart(textproto.MIMEHeader{
			"Content-Disposition": {`form-data; name="content"`}, "Content-Type": {"application/octet-stream"}})
		if err != nil {
			return err
		}
		_, _ = part.Write([]byte(f.Content))
	}
	if err := w.Close(); err != nil {
		return err
	}
	ans, err := d.endpoint(ctx, vm, http.MethodPost, "/v1/files/upload",
		http.Header{"Content-Type": {w.FormDataContentType()}}, body.Bytes(), 64<<10)
	if err != nil {
		return err
	}
	if ans.over {
		return errors.New("dockercloud upload: response exceeds 64 KiB")
	}
	if ans.status != http.StatusOK {
		return dcRESTErrorFrom("upload", ans.status, ans.raw)
	}
	var out struct {
		FilesWritten int `json:"filesWritten"`
	}
	if err := json.Unmarshal(ans.raw, &out); err != nil {
		return fmt.Errorf("dockercloud upload: unparseable response: %w", err)
	}
	if out.FilesWritten != len(files) {
		return fmt.Errorf("dockercloud upload: server reported %d of %d files written", out.FilesWritten, len(files))
	}
	return nil
}

// download reads the given absolute paths in one multipart/mixed answer: per file a
// metadata part and its content part, an error part for a path the service cannot
// read (that path is absent), and a stream-error part for a failure of the whole
// answer. Only the closing delimiter makes the answer whole.
func (d dcREST) download(ctx context.Context, vm dcVM, paths []string) ([]Artifact, bool, error) {
	resp, err := d.openDownload(ctx, vm, paths)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" || params["boundary"] == "" {
		return nil, false, fmt.Errorf("dockercloud download: answer is %q, not multipart/mixed", truncateForError(resp.Header.Get("Content-Type")))
	}
	requested := make(map[string]bool, len(paths))
	for _, p := range paths {
		requested[p] = true
	}
	var (
		arts    []Artifact
		current *Artifact
		total   int64
	)
	finish := func() {
		if current != nil {
			arts = append(arts, *current)
			current = nil
		}
	}
	// Bounds the whole answer: the decoded artifact budget plus room for the parts'
	// headers and JSON; the budget below is what normally stops it.
	mr := multipart.NewReader(io.LimitReader(resp.Body, maxArtifactBytesTotal+2<<20), params["boundary"])
	for {
		part, err := mr.NextRawPart()
		if err == io.EOF {
			finish()
			return arts, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("dockercloud download: %w", err)
		}
		_, disp, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		switch name := disp["name"]; name {
		case "metadata":
			var meta struct {
				Path string `json:"path"`
			}
			if err := dcRESTPartJSON(part, &meta); err != nil {
				return nil, false, err
			}
			finish()
			if !requested[meta.Path] {
				return nil, false, fmt.Errorf("dockercloud download: server sent unrequested path %q", truncateForError(meta.Path))
			}
			current = &Artifact{Path: meta.Path}
		case "content":
			if current == nil {
				return nil, false, errors.New("dockercloud download: content before any metadata")
			}
			room := maxArtifactBytesTotal - total
			b, err := io.ReadAll(io.LimitReader(part, room+1))
			if err != nil {
				return nil, false, fmt.Errorf("dockercloud download: %w", err)
			}
			if int64(len(b)) > room {
				current = nil // this artifact does not fit; drop it whole
				return arts, true, nil
			}
			total += int64(len(b))
			current.Content = append(current.Content, b...)
		case "error":
			finish() // a per-file error: that path is absent
			if _, err := io.Copy(io.Discard, io.LimitReader(part, 64<<10)); err != nil {
				return nil, false, fmt.Errorf("dockercloud download: %w", err)
			}
		case "stream-error":
			var e struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			if err := dcRESTPartJSON(part, &e); err != nil {
				return nil, false, err
			}
			raw, _ := json.Marshal(e)
			return nil, false, dcRESTErrorFrom("download", http.StatusOK, raw)
		default:
			return nil, false, fmt.Errorf("dockercloud download: unknown part %q", truncateForError(name))
		}
	}
}

// openDownload starts the download, trying once more with a fresh credential after a
// 401 that refused it (a read: safe to repeat).
func (d dcREST) openDownload(ctx context.Context, vm dcVM, paths []string) (*http.Response, error) {
	for attempt := 1; ; attempt++ {
		token, err := d.credential(ctx, vm, attempt > 1)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, vm.endpoint+"/v1/files/download?"+url.Values{"paths": paths}.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := d.httpClient().Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		if attempt == 1 && dcRESTTryAgain(resp.StatusCode, raw) {
			if err := sleepCtx(ctx, time.Second); err != nil {
				return nil, err
			}
			continue
		}
		return nil, dcRESTErrorFrom("download", resp.StatusCode, raw)
	}
}

// dcRESTPartJSON decodes one JSON part of at most 64 KiB.
func dcRESTPartJSON(part io.Reader, v any) error {
	raw, err := io.ReadAll(io.LimitReader(part, 64<<10+1))
	if err != nil {
		return fmt.Errorf("dockercloud download: %w", err)
	}
	if len(raw) > 64<<10 {
		return errors.New("dockercloud download: a JSON part exceeds 64 KiB")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("dockercloud download: unparseable part: %w", err)
	}
	return nil
}
