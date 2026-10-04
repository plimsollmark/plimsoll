package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// dcConnect is the Connect transport: Docker's pre-launch protobuf contract, released
// as the Go module github.com/docker/sandboxes-api (v0.36.0, Apache-2.0). Docker has
// since documented only its REST API, so nothing promises this contract stays served;
// the live suite is the evidence that it still is.
//
// The contract is Connect RPC. This transport speaks it by hand, as JSON over
// net/http, rather than importing Docker's generated client: that client would add
// protovalidate and googleapis generated code to the module graph of a hostile-code
// TCB, for a surface of nine procedures. Unary calls are JSON POSTs; the file upload
// and download streams use Connect's enveloped framing in one request body.
//
// Two endpoints, one credential:
//   - Management (APIURL): docker.sbx.v1 sandbox, operation, capability and
//     network-policy services.
//   - Sandbox endpoint (SandboxCore.endpoint.uri, reported per sandbox):
//     docker.sbx.process.v1 and docker.sbx.files.v1.
//
// The contract has no separate endpoint credential in v1: SandboxEndpoint's
// credential_audience "is empty in v1; an empty value does not mean open access",
// PERMISSION_SANDBOXES_CREDENTIAL is "reserved for endpoint credentials", and the
// generated facade (gen/go/sbx/facade.go, NewSandboxClient) says "the endpoint takes
// the same credential as the management client". The cloud CloudCredentialService
// is unrelated: it exchanges a one-use Docker OIDC id_token for a Docker credential
// stored server-side and returns nothing. So the same bearer token authorizes both
// endpoints: the short-lived one exchanged from the personal access token (bearer),
// never the personal access token itself, which the service refuses.
//
// It embeds the provider for its configuration and the shared token exchange.
type dcConnect struct{ *DockerCloud }

var _ dcTransport = dcConnect{}

const (
	dcProcCreateSandbox   = "/docker.sbx.v1.SandboxService/CreateSandbox"
	dcProcGetSandbox      = "/docker.sbx.v1.SandboxService/GetSandbox"
	dcProcListSandboxes   = "/docker.sbx.v1.SandboxService/ListSandboxes"
	dcProcDeleteSandbox   = "/docker.sbx.v1.SandboxService/DeleteSandbox"
	dcProcGetCapabilities = "/docker.sbx.v1.CapabilityService/GetCapabilities"
	dcProcWaitOperation   = "/docker.sbx.v1.OperationService/WaitOperation"
	dcProcGetOperation    = "/docker.sbx.v1.OperationService/GetOperation"
	dcProcEffectivePolicy = "/docker.sbx.v1.NetworkPolicyService/GetEffectiveNetworkPolicy"
	dcProcExec            = "/docker.sbx.process.v1.ProcessService/Exec"
	dcProcUpload          = "/docker.sbx.files.v1.FileService/Upload"
	dcProcDownload        = "/docker.sbx.files.v1.FileService/Download"
)

// dcUploadChunk is the data-frame size for file uploads.
const dcUploadChunk = 512 << 10

// ---- calls ----

// dcErrorFrom parses a unary Connect error body, falling back to the protocol's
// HTTP-status mapping when the body is not a Connect error (a proxy's page, say).
func dcErrorFrom(procedure string, status int, raw []byte) error {
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Code != "" {
		return &dcRPCError{Procedure: procedure, HTTPStatus: status, Code: body.Code, Message: body.Message}
	}
	code := "unknown"
	switch status {
	case http.StatusBadRequest:
		code = "internal"
	case http.StatusUnauthorized:
		code = "unauthenticated"
	case http.StatusForbidden:
		code = "permission_denied"
	case http.StatusNotFound:
		code = "unimplemented"
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		code = "unavailable"
	}
	return &dcRPCError{Procedure: procedure, HTTPStatus: status, Code: code, Message: strings.TrimSpace(string(raw))}
}

// authorize stamps the bearer token and the Connect headers. The remaining
// deadline travels as Connect-Timeout-Ms so the server can stop work the client
// has already abandoned.
func (d dcConnect) authorize(ctx context.Context, req *http.Request, contentType string) error {
	tok, err := d.bearer(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connect-Protocol-Version", "1")
	if deadline, ok := ctx.Deadline(); ok {
		ms := (time.Until(deadline) + time.Millisecond - 1) / time.Millisecond
		if ms < 1 {
			ms = 1
		}
		req.Header.Set("Connect-Timeout-Ms", strconv.FormatInt(int64(ms), 10))
	}
	return nil
}

// post sends one request and reads at most limit bytes of the response. over
// reports that the body was longer than limit.
func (d dcConnect) post(ctx context.Context, target, contentType string, body []byte, limit int64) (status int, raw []byte, over bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, false, err
	}
	if err := d.authorize(ctx, req, contentType); err != nil {
		return 0, nil, false, &dcUnsentError{err}
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, false, &dcUnsentError{err}
	}
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return 0, nil, false, err
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, nil, false, err
	}
	if int64(len(raw)) > limit {
		return resp.StatusCode, nil, true, nil
	}
	return resp.StatusCode, raw, false, nil
}

// call is one unary management RPC with a JSON body.
func (d dcConnect) call(ctx context.Context, procedure string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	status, raw, over, err := d.post(ctx, d.apiBase()+procedure, "application/json", body, dcMaxUnaryResponse)
	if err != nil {
		return err
	}
	if over {
		return fmt.Errorf("dockercloud %s: response exceeds %d bytes", procedure, dcMaxUnaryResponse)
	}
	if status != http.StatusOK {
		return dcErrorFrom(procedure, status, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("dockercloud %s: unparseable response: %w", procedure, err)
	}
	return nil
}

// stream opens a Connect streaming call with a pre-framed request body.
func (d dcConnect) stream(ctx context.Context, target string, framed []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(framed))
	if err != nil {
		return nil, err
	}
	if err := d.authorize(ctx, req, "application/connect+json"); err != nil {
		return nil, err
	}
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, dcErrorFrom(target, resp.StatusCode, raw)
	}
	return resp, nil
}

// ---- sandboxes ----

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

func (s dcSandbox) view() dcSandboxView {
	v := dcSandboxView{id: s.Core.ID, name: s.Core.Name}
	if ep := s.Core.Endpoint; ep != nil {
		v.endpoint = ep.URI
		// Assumption (live probe): the cloud reports protocol CONNECT (or leaves it
		// unset). A unix-socket endpoint is the local backend's and is refused.
		if ep.Protocol != "" && !ep.Protocol.is("SANDBOX_ENDPOINT_PROTOCOL_CONNECT", 1) {
			v.endpointRefused = fmt.Errorf("dockercloud create sandbox: endpoint protocol %s is not Connect over HTTP", ep.Protocol)
		}
	}
	if r := s.Core.Resources; r != nil {
		v.cpus, v.memoryMiB = r.Cpus, r.MemoryMib
	}
	v.reportsBootedDigest = true
	if s.Cloud != nil {
		v.imageDigest = s.Cloud.ImageDigest
	}
	return v
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

func (d dcConnect) createSandbox(ctx context.Context, spec dcCreateSpec) (dcReported, error) {
	fail := func(stage dcCreateStage, err error) (dcReported, error) {
		return nil, &dcCreateError{stage: stage, err: err}
	}
	in := map[string]any{
		"name":      spec.name,
		"requestId": spec.name,
		// No inline networkPolicies. Verified live on 2026-09-24: a create carrying
		// {"mode": NETWORK_POLICY_MODE_DENY_ALL} fails with Connect code 13
		// "internal error", although capabilities report can_attach_policies. The
		// account's cloud policy default supplies deny-all instead (the operator runs
		// `sbx --cloud policy init deny-all` once); with it in force the effective
		// policy reads DENY_ALL and, from inside the guest, HTTP is unreachable, TLS
		// is refused, a TCP connection is reset on its first byte and UDP gets no
		// answer. verifyEgressDenied refuses any sandbox where that is not so.
		"cloud": map[string]any{
			"imageRef":   spec.image,
			"startCmd":   spec.startCmd,
			"timeout":    protoDuration(spec.ttl),
			"onTimeout":  "ON_TIMEOUT_DELETE",
			"autoResume": false,
			// Pinned so the booted platform, and with it the manifest digest checked in
			// verifySandbox, cannot change under the operator.
			"platform": map[string]any{"os": "linux", "architecture": "amd64"},
		},
		// The service refuses a raw-image create without cpus (verified live
		// 2026-09-24: "'cpus' is required when using 'imageRef'"), so an unset
		// SANDBOX_CPUS or SANDBOX_MEMORY_MB requests the smallest size, Micro.
		"resources": map[string]any{
			"cpus":      spec.cpus,
			"memoryMib": strconv.Itoa(spec.memoryMiB), // uint64: a string in protojson
		},
	}

	var op dcOperation
	if err := d.call(ctx, dcProcCreateSandbox, in, &op); err != nil {
		return fail(dcCreateSend, fmt.Errorf("dockercloud create sandbox: %w", err))
	}
	op, err := d.waitOperation(ctx, op)
	if err != nil {
		// the create's operation may still be running
		return fail(dcCreateWait, fmt.Errorf("dockercloud create sandbox: %w", err))
	}
	if op.Error != nil {
		return fail(dcCreateDone, fmt.Errorf("dockercloud create sandbox: operation failed (code %d): %s", op.Error.Code, truncateForError(op.Error.Message)))
	}
	var sb dcSandbox
	if len(op.Response) == 0 || json.Unmarshal(op.Response, &sb) != nil || !sb.running() {
		// The operation's response is a google.protobuf.Any; if it does not already
		// carry a running sandbox, read the sandbox itself.
		sb, err = d.waitRunning(ctx, dcVM{name: spec.name})
		if err != nil {
			return fail(dcCreateDone, err)
		}
	}
	return sb, nil
}

// waitOperation blocks until op is done, using WaitOperation's server-side wait
// and falling back to polling GetOperation where it is not served.
func (d dcConnect) waitOperation(ctx context.Context, op dcOperation) (dcOperation, error) {
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
func (d dcConnect) waitRunning(ctx context.Context, vm dcVM) (dcSandbox, error) {
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

// deleteSandbox deletes one sandbox and waits for the deletion. A NOT_FOUND, from the
// call or its operation, is success with existed false: nothing was there to delete.
func (d dcConnect) deleteSandbox(ctx context.Context, vm dcVM, requestID string) (existed bool, err error) {
	// DeleteSandbox answers an Operation; an accepted request is not a completed
	// deletion. Wait for it, and treat a failed operation as a failed delete so
	// destroy retries and the reaper does not count the sandbox as gone.
	var op dcOperation
	err = d.call(ctx, dcProcDeleteSandbox, map[string]any{"sandbox": vm.ref(), "force": true, "requestId": requestID}, &op)
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

func (d dcConnect) listSandboxes(ctx context.Context, pageToken string) ([]dcListed, string, error) {
	in := map[string]any{"pageSize": 100}
	if pageToken != "" {
		in["pageToken"] = pageToken
	}
	var out struct {
		Sandboxes     []dcSandbox `json:"sandboxes"`
		NextPageToken string      `json:"nextPageToken"`
	}
	if err := d.call(ctx, dcProcListSandboxes, in, &out); err != nil {
		return nil, "", err
	}
	page := make([]dcListed, 0, len(out.Sandboxes))
	for _, sb := range out.Sandboxes {
		page = append(page, dcListed{name: sb.Core.Name, id: sb.Core.ID, createdAt: sb.Core.CreatedAt})
	}
	return page, out.NextPageToken, nil
}

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
func (d dcConnect) checkCapabilities(ctx context.Context) error {
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

func (d dcConnect) effectivePolicy(ctx context.Context, vm dcVM) (dcPolicy, error) {
	var pol struct {
		Mode          protoEnum `json:"mode"`
		AllowNetworks []struct {
			Network string `json:"network"`
		} `json:"allowNetworks"`
	}
	in := map[string]any{"target": map[string]any{"sandbox": map[string]string{"id": vm.id}}}
	if err := d.call(ctx, dcProcEffectivePolicy, in, &pol); err != nil {
		return dcPolicy{}, err
	}
	out := dcPolicy{mode: string(pol.Mode), denyAll: pol.Mode.is("NETWORK_POLICY_MODE_DENY_ALL", 2)}
	out.allow = make([]string, 0, len(pol.AllowNetworks))
	for _, a := range pol.AllowNetworks {
		out.allow = append(out.allow, a.Network)
	}
	return out, nil
}

// ---- guest execution and files ----

// exec calls ProcessService.Exec on the sandbox endpoint. flooded reports that the
// response body exceeded limit; the body is then discarded unread.
func (d dcConnect) exec(ctx context.Context, vm dcVM, cmd []string, cwd string, limit int64) (dcExecResponse, bool, error) {
	in := map[string]any{"cmd": cmd}
	if cwd != "" {
		in["workingDir"] = cwd
	}
	body, _ := json.Marshal(in)
	status, raw, over, err := d.post(ctx, vm.endpoint+dcProcExec, "application/json", body, limit)
	if err != nil {
		return dcExecResponse{}, false, err
	}
	if status != http.StatusOK {
		return dcExecResponse{}, false, dcErrorFrom(dcProcExec, status, raw)
	}
	if over {
		return dcExecResponse{}, true, nil
	}
	var out dcExecResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return dcExecResponse{}, false, fmt.Errorf("dockercloud exec: unparseable response: %w", err)
	}
	return out, false, nil
}

// upload writes files with one FileService.Upload client stream: per file a header
// frame, then its bytes in data frames.
// Assumption (live probe): a file is complete when the next header or the end of
// the stream arrives, and an empty file is a header with no data frame.
func (d dcConnect) upload(ctx context.Context, vm dcVM, files []File) error {
	if len(files) == 0 {
		return nil
	}
	var body bytes.Buffer
	for _, f := range files {
		frame, _ := json.Marshal(map[string]any{"header": map[string]any{"path": f.Path, "mode": 0o644}})
		body.Write(connectEnvelope(frame))
		content := []byte(f.Content)
		for off := 0; off < len(content); off += dcUploadChunk {
			end := min(off+dcUploadChunk, len(content))
			frame, _ := json.Marshal(map[string]any{"data": content[off:end]})
			body.Write(connectEnvelope(frame))
		}
	}
	resp, err := d.stream(ctx, vm.endpoint+dcProcUpload, body.Bytes())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var written uint32
	var got bool
	err = readConnectFrames(resp.Body, dcProcUpload, 1<<20, 1<<20, func(msg []byte) error {
		var out struct {
			FilesWritten uint32 `json:"filesWritten"`
		}
		if err := json.Unmarshal(msg, &out); err != nil {
			return fmt.Errorf("dockercloud upload: unparseable response: %w", err)
		}
		written, got = out.FilesWritten, true
		return nil
	})
	if err != nil {
		return err
	}
	if !got || int(written) != len(files) {
		return fmt.Errorf("dockercloud upload: server reported %d of %d files written", written, len(files))
	}
	return nil
}

// download reads the given absolute paths with one FileService.Download server
// stream. A path the server answers with a per-file error is treated as absent.
// Assumption (live probe): a missing file produces a per-file error frame rather
// than failing the stream, and header paths echo the requested paths.
func (d dcConnect) download(ctx context.Context, vm dcVM, paths []string) ([]Artifact, bool, error) {
	req, _ := json.Marshal(map[string]any{"paths": paths})
	resp, err := d.stream(ctx, vm.endpoint+dcProcDownload, connectEnvelope(req))
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
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
	// The transport budget is the decoded artifact budget in base64 plus room for
	// headers and per-file errors; the decoded budget below is what normally stops it.
	transport := int64(base64.StdEncoding.EncodedLen(maxArtifactBytesTotal)) + 2<<20
	err = readConnectFrames(resp.Body, dcProcDownload, 16<<20, transport, func(msg []byte) error {
		var frame struct {
			Header *struct {
				Path string `json:"path"`
			} `json:"header"`
			Data  []byte          `json:"data"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(msg, &frame); err != nil {
			return fmt.Errorf("dockercloud download: unparseable frame: %w", err)
		}
		switch {
		case frame.Header != nil:
			finish()
			if !requested[frame.Header.Path] {
				return fmt.Errorf("dockercloud download: server sent unrequested path %q", frame.Header.Path)
			}
			current = &Artifact{Path: frame.Header.Path}
		case frame.Error != nil:
			finish() // a per-file error: that path is absent
		case frame.Data != nil:
			if current == nil {
				return errors.New("dockercloud download: data frame before any header")
			}
			if total+int64(len(frame.Data)) > maxArtifactBytesTotal {
				current = nil // this artifact does not fit; drop it whole
				return errArtifactBudget
			}
			total += int64(len(frame.Data))
			current.Content = append(current.Content, frame.Data...)
		}
		return nil
	})
	if errors.Is(err, errArtifactBudget) {
		return arts, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	finish()
	return arts, false, nil
}

// readConnectFrames decodes a Connect streaming response. Every frame is bounded
// (maxFrame) and so is the stream (maxTotal). The end-of-stream frame is required:
// a body that ends without one was cut, and its content cannot be trusted as whole.
func readConnectFrames(r io.Reader, procedure string, maxFrame uint32, maxTotal int64, fn func(msg []byte) error) error {
	header := make([]byte, 5)
	var total int64
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if err == io.EOF {
				return fmt.Errorf("dockercloud %s: stream ended without an end-of-stream frame", procedure)
			}
			return err
		}
		flags := header[0]
		length := binary.BigEndian.Uint32(header[1:5])
		if length > maxFrame {
			return fmt.Errorf("dockercloud %s: stream frame of %d bytes exceeds %d", procedure, length, maxFrame)
		}
		total += int64(length)
		if total > maxTotal {
			return fmt.Errorf("dockercloud %s: stream exceeds %d bytes", procedure, maxTotal)
		}
		if flags&0x01 != 0 {
			return fmt.Errorf("dockercloud %s: compressed stream frame, which was not negotiated", procedure)
		}
		msg := make([]byte, length)
		if _, err := io.ReadFull(r, msg); err != nil {
			return err
		}
		if flags&0x02 != 0 {
			var end struct {
				Error *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if len(msg) > 0 {
				if err := json.Unmarshal(msg, &end); err != nil {
					return fmt.Errorf("dockercloud %s: unparseable end-of-stream frame: %w", procedure, err)
				}
			}
			if end.Error != nil {
				return &dcRPCError{Procedure: procedure, HTTPStatus: http.StatusOK, Code: end.Error.Code, Message: end.Error.Message}
			}
			return nil
		}
		if err := fn(msg); err != nil {
			return err
		}
	}
}
