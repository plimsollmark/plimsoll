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
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// dcFake is an in-process stand-in for both Docker Cloud Sandboxes endpoints: the
// management API at its root and one sandbox endpoint under /ep. It speaks the
// Connect JSON shapes the provider sends, records every call, and exposes knobs
// for the failure paths.
type dcFake struct {
	exchanges      int
	refuseExchange bool
	accessLife     time.Duration
	issued         string
	t              *testing.T
	srv            *httptest.Server

	mu       sync.Mutex
	calls    []string
	creates  []map[string]any
	deletes  []map[string]any
	execs    [][]string
	execCwds []string
	uploads  [][]dcFakeFile

	// knobs
	createStatus   int  // non-zero: CreateSandbox fails with this HTTP status
	opPending      bool // CreateSandbox returns a not-done operation
	waitUnimpl     bool // WaitOperation answers unimplemented, forcing GetOperation polling
	opError        bool // the create operation finishes with an error
	reportedCPUs   int
	reportedMemMiB int
	policyMode     string // default NETWORK_POLICY_MODE_DENY_ALL
	policyAllow    []string
	caps           map[string]any
	files          map[string][]byte  // what Download serves
	listPages      [][]map[string]any // ListSandboxes pages
	exec           func(argv []string) (exit int, stdout, stderr string)
	execHandler    func(w http.ResponseWriter, r *http.Request) // overrides exec entirely
	execBlock      bool                                         // Exec blocks until the request is cancelled

	// the undocumented per-sandbox network-policy REST call
	policyPuts      []map[string]any
	policyPutStatus int  // non-zero: the PUT fails with this status
	policyEchoWrong bool // the PUT answers a different policy than requested
	policyIgnored   bool // the PUT answers correctly but the rule never takes effect

	noResources      bool   // the sandbox reports no CPU or memory size
	deleteOpFailures int    // this many delete operations finish with an error before one succeeds
	echoSecret       string // CreateSandbox fails with a message echoing this value
	opErrorEcho      string // the create operation fails with a message echoing this value
}

type dcFakeFile struct {
	path    string
	mode    float64
	content []byte
}

const dcTestToken = "tok-123"

// dcTestUser is the account the fake's token exchange expects. The live service
// refuses the personal access token itself (TOKEN_INVALID, 2026-09-24); only the
// exchanged bearer is accepted, and the fake enforces the same.
const dcTestUser = "plimsoll-test"

// dcTestAccess builds the fake's exchanged bearer: an unsigned JWT whose exp is
// the given time, which is all the provider reads from it.
func dcTestAccess(exp time.Time) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix()))) + ".sig"
}

func newDCFake(t *testing.T) *dcFake {
	t.Helper()
	f := &dcFake{t: t, policyMode: "NETWORK_POLICY_MODE_DENY_ALL"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *dcFake) provider() *DockerCloud {
	return &DockerCloud{
		Token:          dcTestToken,
		Username:       dcTestUser,
		AuthURL:        f.srv.URL + "/v2/auth/token",
		PolicyURL:      f.srv.URL + "/v1",
		APIURL:         f.srv.URL,
		Image:          "registry.example/plimsoll/sandbox@sha256:" + strings.Repeat("a", 64),
		DefaultTimeout: 10 * time.Second,
		MaxTimeout:     20 * time.Second,
	}
}

func (f *dcFake) called(proc string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == proc {
			n++
		}
	}
	return n
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func connectError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": msg})
}

// readFrames splits a Connect streaming body into its messages.
func readFrames(t *testing.T, body []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(body) > 0 {
		if len(body) < 5 {
			t.Errorf("truncated envelope header")
			return out
		}
		n := binary.BigEndian.Uint32(body[1:5])
		if int(n) > len(body)-5 {
			t.Errorf("truncated envelope body")
			return out
		}
		out = append(out, body[5:5+n])
		body = body[5+n:]
	}
	return out
}

func writeStream(w http.ResponseWriter, msgs ...any) {
	w.Header().Set("Content-Type", "application/connect+json")
	for _, m := range msgs {
		b, _ := json.Marshal(m)
		_, _ = w.Write(connectEnvelope(b))
	}
	end := connectEnvelope([]byte("{}"))
	end[0] = 0x02
	_, _ = w.Write(end)
}

func (f *dcFake) sandbox(name string) map[string]any {
	core := map[string]any{
		"id":     "sb-1",
		"name":   name,
		"status": "SANDBOX_STATUS_RUNNING",
		"endpoint": map[string]any{
			"uri":       f.srv.URL + "/ep",
			"protocol":  "SANDBOX_ENDPOINT_PROTOCOL_CONNECT",
			"sandboxId": "sb-1",
		},
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}
	res := map[string]any{}
	if !f.noResources {
		// The live service reported exactly the requested size (2026-09-24); the fake
		// echoes the last create's request unless a test overrides it.
		f.mu.Lock()
		if n := len(f.creates); n > 0 {
			if req, ok := f.creates[n-1]["resources"].(map[string]any); ok {
				res["cpus"], res["memoryMib"] = req["cpus"], req["memoryMib"]
			}
		}
		f.mu.Unlock()
		if f.reportedCPUs > 0 {
			res["cpus"] = f.reportedCPUs
		}
		if f.reportedMemMiB > 0 {
			res["memoryMib"] = strconv.Itoa(f.reportedMemMiB)
		}
	}
	if len(res) > 0 {
		core["resources"] = res
	}
	return map[string]any{"core": core, "cloud": map[string]any{"imageDigest": "sha256:" + strings.Repeat("a", 64)}}
}

// deleteOp answers a delete operation: failed while deleteOpFailures lasts.
func (f *dcFake) deleteOp() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteOpFailures > 0 {
		f.deleteOpFailures--
		return map[string]any{"id": "op-del", "done": true, "error": map[string]any{"code": 13, "message": "delete failed"}}
	}
	return map[string]any{"id": "op-del", "done": true, "response": map[string]any{}}
}

func (f *dcFake) doneOp(name string) map[string]any {
	if f.opErrorEcho != "" {
		return map[string]any{"id": "op-1", "done": true, "error": map[string]any{"code": 3, "message": "rejected token " + f.opErrorEcho}}
	}
	if f.opError {
		return map[string]any{"id": "op-1", "done": true, "error": map[string]any{"code": 8, "message": "quota exhausted"}}
	}
	resp := f.sandbox(name)
	resp["@type"] = "type.googleapis.com/docker.sbx.v1.Sandbox"
	return map[string]any{"id": "op-1", "done": true, "response": resp}
}

func (f *dcFake) lastName() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) == 0 {
		return ""
	}
	name, _ := f.creates[len(f.creates)-1]["name"].(string)
	return name
}

func (f *dcFake) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v2/auth/token" {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.exchanges++
		refuse := f.refuseExchange
		life := f.accessLife
		f.mu.Unlock()
		if refuse || in["identifier"] != dcTestUser || in["secret"] != dcTestToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"incorrect authentication credentials"}`))
			return
		}
		if life == 0 {
			life = 15 * time.Minute
		}
		tok := dcTestAccess(time.Now().Add(life))
		f.mu.Lock()
		f.issued = tok
		f.mu.Unlock()
		writeJSON(w, map[string]string{"access_token": tok})
		return
	}
	f.mu.Lock()
	issued := f.issued
	f.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/v1/sandboxes/") && strings.HasSuffix(r.URL.Path, "/network-policy") {
		if issued == "" || r.Header.Get("Authorization") != "Bearer "+issued || r.Method != http.MethodPut {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.policyPuts = append(f.policyPuts, in)
		status, wrong, ignored := f.policyPutStatus, f.policyEchoWrong, f.policyIgnored
		f.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"refused"}`))
			return
		}
		var allow []string
		for _, a := range in["allowNetworks"].([]any) {
			allow = append(allow, a.(string))
		}
		if !ignored {
			f.mu.Lock()
			f.policyAllow = append(f.policyAllow, allow...)
			f.mu.Unlock()
		}
		echo := map[string]any{"mode": in["mode"], "allowNetworks": allow}
		if wrong {
			echo["allowNetworks"] = []string{"evil.example.com:443"}
		}
		writeJSON(w, echo)
		return
	}
	if issued == "" || r.Header.Get("Authorization") != "Bearer "+issued {
		connectError(w, http.StatusUnauthorized, "unauthenticated", "bad token")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, r.URL.Path)
	f.mu.Unlock()
	var in map[string]any
	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.Unmarshal(body, &in); err != nil {
			f.t.Errorf("%s: request is not JSON: %v", r.URL.Path, err)
		}
	}

	switch r.URL.Path {
	case dcProcGetCapabilities:
		caps := f.caps
		if caps == nil {
			caps = map[string]any{"canAttachPolicies": true}
		}
		writeJSON(w, caps)
	case dcProcCreateSandbox:
		f.mu.Lock()
		f.creates = append(f.creates, in)
		f.mu.Unlock()
		if f.createStatus != 0 {
			connectError(w, f.createStatus, "resource_exhausted", "no capacity")
			return
		}
		if f.echoSecret != "" {
			connectError(w, http.StatusBadRequest, "invalid_argument", "bad request from Authorization: Bearer "+f.echoSecret+" and "+f.echoSecret)
			return
		}
		name, _ := in["name"].(string)
		if f.opPending {
			writeJSON(w, map[string]any{"id": "op-1", "done": false})
			return
		}
		writeJSON(w, f.doneOp(name))
	case dcProcWaitOperation:
		if f.waitUnimpl {
			connectError(w, http.StatusNotFound, "unimplemented", "no wait")
			return
		}
		if id, _ := in["id"].(string); strings.HasPrefix(id, "op-del") {
			writeJSON(w, f.deleteOp())
			return
		}
		writeJSON(w, f.doneOp(f.lastName()))
	case dcProcGetOperation:
		if id, _ := in["id"].(string); strings.HasPrefix(id, "op-del") {
			writeJSON(w, f.deleteOp())
			return
		}
		writeJSON(w, f.doneOp(f.lastName()))
	case dcProcGetSandbox:
		writeJSON(w, f.sandbox(f.lastName()))
	case dcProcEffectivePolicy:
		allow := []any{}
		for _, a := range f.policyAllow {
			allow = append(allow, map[string]any{"network": a, "layer": "POLICY_LAYER_OWNER"})
		}
		writeJSON(w, map[string]any{"mode": f.policyMode, "allowNetworks": allow})
	case dcProcDeleteSandbox:
		f.mu.Lock()
		f.deletes = append(f.deletes, in)
		f.mu.Unlock()
		writeJSON(w, map[string]any{"id": "op-del", "done": false})
	case dcProcListSandboxes:
		page := 0
		if tok, _ := in["pageToken"].(string); tok != "" {
			page, _ = strconv.Atoi(tok)
		}
		out := map[string]any{"sandboxes": []any{}}
		if page < len(f.listPages) {
			out["sandboxes"] = f.listPages[page]
			if page+1 < len(f.listPages) {
				out["nextPageToken"] = strconv.Itoa(page + 1)
			}
		}
		writeJSON(w, out)
	case "/ep" + dcProcExec:
		var cmd []string
		for _, c := range in["cmd"].([]any) {
			cmd = append(cmd, c.(string))
		}
		cwd, _ := in["workingDir"].(string)
		f.mu.Lock()
		f.execs = append(f.execs, cmd)
		f.execCwds = append(f.execCwds, cwd)
		f.mu.Unlock()
		if f.execBlock && cmd[0] != "mkdir" {
			<-r.Context().Done()
			return
		}
		if f.execHandler != nil && cmd[0] != "mkdir" {
			f.execHandler(w, r)
			return
		}
		exit, stdout, stderr := 0, "ok\n", ""
		if cmd[0] == "mkdir" {
			stdout = ""
		} else if f.exec != nil {
			exit, stdout, stderr = f.exec(dcInnerArgv(f.t, cmd))
		}
		writeJSON(w, map[string]any{"exitCode": exit, "stdout": []byte(stdout), "stderr": []byte(stderr)})
	case "/ep" + dcProcUpload:
		if ct := r.Header.Get("Content-Type"); ct != "application/connect+json" {
			f.t.Errorf("upload content type = %q", ct)
		}
		var files []dcFakeFile
		for _, msg := range readFrames(f.t, body) {
			var frame struct {
				Header *struct {
					Path string  `json:"path"`
					Mode float64 `json:"mode"`
				} `json:"header"`
				Data []byte `json:"data"`
			}
			if err := json.Unmarshal(msg, &frame); err != nil {
				f.t.Errorf("upload frame is not JSON: %v", err)
				continue
			}
			switch {
			case frame.Header != nil:
				files = append(files, dcFakeFile{path: frame.Header.Path, mode: frame.Header.Mode})
			case frame.Data != nil:
				if len(files) == 0 {
					f.t.Errorf("data frame before header")
					continue
				}
				files[len(files)-1].content = append(files[len(files)-1].content, frame.Data...)
			}
		}
		f.mu.Lock()
		f.uploads = append(f.uploads, files)
		f.mu.Unlock()
		writeStream(w, map[string]any{"filesWritten": len(files)})
	case "/ep" + dcProcDownload:
		frames := readFrames(f.t, body)
		var req struct {
			Paths []string `json:"paths"`
		}
		if len(frames) != 1 || json.Unmarshal(frames[0], &req) != nil {
			f.t.Errorf("download request is not one JSON frame")
		}
		var msgs []any
		for _, p := range req.Paths {
			content, ok := f.files[p]
			if !ok {
				msgs = append(msgs, map[string]any{"error": map[string]any{"path": p, "message": "no such file"}})
				continue
			}
			msgs = append(msgs, map[string]any{"header": map[string]any{"path": p, "mode": 420}})
			for off := 0; off < len(content); off += 1 << 20 {
				msgs = append(msgs, map[string]any{"data": content[off:min(off+1<<20, len(content))]})
			}
		}
		writeStream(w, msgs...)
	default:
		connectError(w, http.StatusNotFound, "unimplemented", r.URL.Path)
	}
}

// dcInnerArgv returns the command the wrapper runs, checking the wrapper framing.
func dcInnerArgv(t *testing.T, cmd []string) []string {
	t.Helper()
	if len(cmd) < 7 || cmd[0] != "sh" || cmd[1] != "-c" || cmd[2] != dcExecWrapper || cmd[3] != "plimsoll-exec" {
		t.Errorf("guest command is not wrapped: %q", cmd)
		return cmd
	}
	if secs, err := strconv.Atoi(cmd[4]); err != nil || secs < 1 {
		t.Errorf("in-guest time limit %q is not a positive whole number of seconds", cmd[4])
	}
	if _, err := strconv.Atoi(cmd[5]); err != nil {
		t.Errorf("in-guest output cap %q is not a number", cmd[5])
	}
	return cmd[6:]
}

// deletedRefs flattens the recorded DeleteSandbox targets for assertions.
func (f *dcFake) deletedRefs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, d := range f.deletes {
		ref, _ := d["sandbox"].(map[string]any)
		for k, v := range ref {
			out = append(out, k+":"+v.(string))
		}
		if force, _ := d["force"].(bool); !force {
			out = append(out, "not-forced")
		}
	}
	return out
}

func (d *DockerCloud) inflightCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.inflight)
}

func TestDockerCloudCreateDeniesAllEgressAndWrapsTheSnippet(t *testing.T) {
	f := newDCFake(t)
	f.exec = func(argv []string) (int, string, string) {
		if strings.Join(argv, " ") != "node /tmp/plimsoll-snippet.cjs" {
			t.Errorf("snippet argv = %q", argv)
		}
		return 0, "dc 42\n", ""
	}
	d := f.provider()
	res, err := d.RunJavaScript(context.Background(), Request{Code: `console.log("dc", 6*7)`})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.ExitCode != 0 || res.Stdout != "dc 42\n" || res.Sandbox != "dockercloud" || res.Isolation != IsolationVM {
		t.Fatalf("result = %+v", res)
	}

	create := f.creates[0]
	name, _ := create["name"].(string)
	if !strings.HasPrefix(name, dcNamePrefix+d.instance()+"-") || create["requestId"] != name {
		t.Fatalf("sandbox not stamped with this instance: name=%q requestId=%v", name, create["requestId"])
	}
	// No inline policy: the live service fails a create that carries one
	// (2026-09-24). Deny-all comes from the account policy and is read back.
	if _, ok := create["networkPolicies"]; ok {
		t.Fatalf("create carries an inline networkPolicies field: %v", create["networkPolicies"])
	}
	if f.called(dcProcEffectivePolicy) == 0 {
		t.Fatal("the effective egress policy was not read back before the run")
	}
	cloud := create["cloud"].(map[string]any)
	if cloud["imageRef"] != d.Image || cloud["onTimeout"] != "ON_TIMEOUT_DELETE" || cloud["autoResume"] != false {
		t.Fatalf("cloud options = %v", cloud)
	}
	if ttl, _ := cloud["timeout"].(string); !strings.HasSuffix(ttl, "s") || ttl == "0s" {
		t.Fatalf("cloud TTL = %v, want a protojson duration", cloud["timeout"])
	}
	// No envelope configured: the Micro size is requested, since the service
	// refuses a raw-image create without cpus (TestDockerCloudDefaultsToMicroWhenUnset).
	if res, _ := create["resources"].(map[string]any); res["cpus"] != float64(dcDefaultCPUs) {
		t.Fatalf("resources without a configured envelope = %v, want the Micro default", create["resources"])
	}

	// The effective policy is read back before any guest code runs.
	if f.called(dcProcEffectivePolicy) != 1 {
		t.Fatalf("effective network policy read %d times, want 1", f.called(dcProcEffectivePolicy))
	}
	if len(f.uploads) != 1 || len(f.uploads[0]) != 1 || f.uploads[0][0].path != "/tmp/plimsoll-snippet.cjs" ||
		string(f.uploads[0][0].content) != `console.log("dc", 6*7)` {
		t.Fatalf("uploads = %+v", f.uploads)
	}
	if got := f.deletedRefs(); len(got) != 1 || got[0] != "id:sb-1" {
		t.Fatalf("deletes = %v, want one forced delete by id", got)
	}
	if d.inflightCount() != 0 {
		t.Fatal("sandbox still tracked after the run")
	}
}

func TestDockerCloudRequestsAndVerifiesResources(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.MaxVCPU, d.MaxMemoryMB = 2, 1024
	f.reportedCPUs, f.reportedMemMiB = 2, 1024
	if _, err := d.RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
		t.Fatalf("within-cap run failed: %v", err)
	}
	res := f.creates[0]["resources"].(map[string]any)
	if res["cpus"] != float64(2) || res["memoryMib"] != "1024" {
		t.Fatalf("requested resources = %v, want cpus 2 and memoryMib \"1024\"", res)
	}

	for name, tweak := range map[string]func(){
		"cpu over cap":     func() { f.noResources, f.reportedCPUs, f.reportedMemMiB = false, 4, 1024 },
		"memory over cap":  func() { f.noResources, f.reportedCPUs, f.reportedMemMiB = false, 2, 4096 },
		"resources absent": func() { f.noResources, f.reportedCPUs, f.reportedMemMiB = true, 0, 0 },
	} {
		t.Run(name, func(t *testing.T) {
			tweak()
			before := len(f.deletedRefs())
			if _, err := d.RunJavaScript(context.Background(), Request{Code: "1"}); err == nil {
				t.Fatal("run proceeded on a sandbox that does not prove the cap")
			}
			if len(f.deletedRefs()) != before+1 {
				t.Fatal("rejected sandbox was not deleted")
			}
		})
	}
}

func TestDockerCloudRefusesUnlessEgressIsDenied(t *testing.T) {
	for name, tweak := range map[string]func(*dcFake){
		"allow-all mode": func(f *dcFake) { f.policyMode = "NETWORK_POLICY_MODE_ALLOW_ALL" },
		"numeric allow":  func(f *dcFake) { f.policyMode = "1" },
		"allow rule":     func(f *dcFake) { f.policyAllow = []string{"0.0.0.0/0"} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newDCFake(t)
			tweak(f)
			d := f.provider()
			_, err := d.RunJavaScript(context.Background(), Request{Code: "1"})
			if err == nil || !strings.Contains(err.Error(), "egress") {
				t.Fatalf("err = %v, want an egress-policy refusal", err)
			}
			if len(f.execs) != 0 || len(f.uploads) != 0 {
				t.Fatal("guest work happened before the egress policy was proven")
			}
			if len(f.deletedRefs()) != 1 {
				t.Fatal("sandbox not deleted after the refusal")
			}
		})
	}
	// The number form of DENY_ALL is accepted, since protojson allows it.
	f := newDCFake(t)
	f.policyMode = "2"
	if _, err := f.provider().RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
		t.Fatalf("numeric deny-all refused: %v", err)
	}
}

func TestDockerCloudUploadFramingAndProjectFlow(t *testing.T) {
	f := newDCFake(t)
	big := strings.Repeat("x", dcUploadChunk+123) // spans two data frames
	var stepArgv [][]string
	f.exec = func(argv []string) (int, string, string) {
		stepArgv = append(stepArgv, argv)
		return 0, "", ""
	}
	f.files = map[string][]byte{"/tmp/plimsoll-project/out/result.txt": []byte("artifact")}
	d := f.provider()
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{
			{Path: "main.mjs", Content: "console.log(1)\n"},
			{Path: "lib/big.txt", Content: big},
			{Path: "empty.txt", Content: ""},
		},
		Steps:     []string{"node main.mjs", "echo done"},
		Artifacts: []string{"out/result.txt", "missing.txt"},
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 2 {
		t.Fatalf("result = %+v", res)
	}

	// One mkdir for the project tree, before the upload.
	if f.execs[0][0] != "mkdir" || strings.Join(f.execs[0], " ") != "mkdir -p -- /tmp/plimsoll-project /tmp/plimsoll-project/lib" {
		t.Fatalf("first exec = %q, want one mkdir -p of the project dirs", f.execs[0])
	}
	// One upload carrying every file and every step script.
	if len(f.uploads) != 1 {
		t.Fatalf("%d uploads, want 1", len(f.uploads))
	}
	got := map[string]dcFakeFile{}
	for _, file := range f.uploads[0] {
		got[file.path] = file
	}
	want := map[string]string{
		"/tmp/plimsoll-project/main.mjs":    "console.log(1)\n",
		"/tmp/plimsoll-project/lib/big.txt": big,
		"/tmp/plimsoll-project/empty.txt":   "",
		"/tmp/plimsoll-step-0.sh":           "node main.mjs",
		"/tmp/plimsoll-step-1.sh":           "echo done",
	}
	if len(got) != len(want) {
		t.Fatalf("uploaded %d files, want %d", len(got), len(want))
	}
	for p, content := range want {
		file, ok := got[p]
		if !ok || string(file.content) != content || file.mode != 0o644 {
			t.Fatalf("upload %s = %+v (present %v)", p, file.mode, ok)
		}
	}
	// Steps run through the wrapper in the project dir, in order.
	if len(stepArgv) != 2 || strings.Join(stepArgv[0], " ") != "sh /tmp/plimsoll-step-0.sh" || strings.Join(stepArgv[1], " ") != "sh /tmp/plimsoll-step-1.sh" {
		t.Fatalf("step argv = %q", stepArgv)
	}
	if f.execCwds[1] != "/tmp/plimsoll-project" {
		t.Fatalf("step cwd = %q", f.execCwds[1])
	}
	// The existing artifact comes back relative; the missing one is absent.
	if len(res.Artifacts) != 1 || res.Artifacts[0].Path != "out/result.txt" || string(res.Artifacts[0].Content) != "artifact" || res.ArtifactsTruncated {
		t.Fatalf("artifacts = %+v truncated=%v", res.Artifacts, res.ArtifactsTruncated)
	}
	if len(f.deletedRefs()) != 1 {
		t.Fatal("sandbox not deleted")
	}
}

func TestDockerCloudProjectStopsOnFirstFailure(t *testing.T) {
	f := newDCFake(t)
	f.exec = func(argv []string) (int, string, string) { return 2, "", "boom" }
	res, err := f.provider().RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "a.txt", Content: "a"}},
		Steps: []string{"false", "never"},
	})
	if err != nil || res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 2 || res.Steps[0].Stderr != "boom" {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

func TestDockerCloudArtifactBudgetTruncates(t *testing.T) {
	f := newDCFake(t)
	f.files = map[string][]byte{
		"/tmp/plimsoll-project/a.bin": bytes.Repeat([]byte("a"), 5<<20),
		"/tmp/plimsoll-project/b.bin": bytes.Repeat([]byte("b"), 5<<20),
	}
	res, err := f.provider().RunProject(context.Background(), ProjectRequest{
		Files:     []File{{Path: "x", Content: "x"}},
		Steps:     []string{"true"},
		Artifacts: []string{"a.bin", "b.bin"},
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if !res.ArtifactsTruncated || len(res.Artifacts) != 1 || res.Artifacts[0].Path != "a.bin" || len(res.Artifacts[0].Content) != 5<<20 {
		t.Fatalf("artifacts = %d truncated=%v", len(res.Artifacts), res.ArtifactsTruncated)
	}
}

func TestDockerCloudTruncationFlagsNoMarkers(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.MaxOutputBytes = 10
	// The in-guest head caps at max+1, so 11 bytes means "more existed".
	f.exec = func([]string) (int, string, string) { return 141, "0123456789X", "short" }
	res, err := d.RunJavaScript(context.Background(), Request{Code: "1"})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.Stdout != "0123456789" || !res.StdoutTruncated || res.Stderr != "short" || res.StderrTruncated || res.ExitCode != 141 || res.TimedOut {
		t.Fatalf("result = %+v", res)
	}
	// The cap the wrapper receives is the host cap plus one.
	if f.execs[0][5] != "11" {
		t.Fatalf("in-guest cap = %s, want 11", f.execs[0][5])
	}
}

func TestDockerCloudFloodIsAFailedUserRun(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.MaxOutputBytes = 16
	f.execHandler = func(w http.ResponseWriter, _ *http.Request) {
		// Far more than the wrapper's caps allow, as guest code writing around them
		// would produce.
		writeJSON(w, map[string]any{"exitCode": 0, "stdout": bytes.Repeat([]byte("y"), 1<<20)})
	}
	res, err := d.RunJavaScript(context.Background(), Request{Code: "1"})
	if err != nil {
		t.Fatalf("a flood must not be an infrastructure error: %v", err)
	}
	if res.ExitCode != exitOutputFlooded || !res.StdoutTruncated || !res.StderrTruncated || res.Stdout != "" {
		t.Fatalf("result = %+v", res)
	}
	if len(f.deletedRefs()) != 1 {
		t.Fatal("sandbox not deleted after a flood")
	}
}

// TestDockerCloudInGuestTimeout: exit 137 counts as a timeout only when the call
// actually lasted the in-guest limit, so a program exiting 137 on its own is not
// misread.
func TestDockerCloudInGuestTimeout(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	var sleep time.Duration
	f.exec = func([]string) (int, string, string) {
		time.Sleep(sleep)
		return 137, "partial", ""
	}

	// Budget 3s leaves a 1s in-guest limit after the 2s margin.
	sleep = 1100 * time.Millisecond
	res, err := d.RunJavaScript(context.Background(), Request{Code: "1", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if f.execs[0][4] != "1" {
		t.Fatalf("in-guest limit = %s, want 1", f.execs[0][4])
	}
	if !res.TimedOut || res.ExitCode != 124 || res.Stdout != "partial" {
		t.Fatalf("killed-at-limit result = %+v", res)
	}

	sleep = 0
	res, err = d.RunJavaScript(context.Background(), Request{Code: "1", Timeout: 3 * time.Second})
	if err != nil || res.TimedOut || res.ExitCode != 137 {
		t.Fatalf("an immediate exit 137 was read as a timeout: %+v %v", res, err)
	}

	// A project step killed by the in-guest limit makes the run timed_out.
	sleep = 1100 * time.Millisecond
	pres, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "a", Content: "a"}}, Steps: []string{"sleep 60", "never"}, Timeout: 3 * time.Second,
	})
	if err != nil || pres.Outcome != ProjectOutcomeTimedOut || len(pres.Steps) != 1 || !pres.Steps[0].TimedOut || pres.Steps[0].ExitCode != 124 {
		t.Fatalf("project = %+v err = %v", pres, err)
	}
}

// TestDockerCloudDeletesOnEveryExitPath: the sandbox is deleted whether the run
// succeeds, fails in the infrastructure, hits the host deadline, or is cancelled,
// and whether or not the create itself succeeded.
func TestDockerCloudDeletesOnEveryExitPath(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(*dcFake)
		ctx     func() (context.Context, context.CancelFunc)
		timeout time.Duration
		check   func(t *testing.T, res Result, err error)
		wantRef string // "id" or "name"
	}{
		{
			name:    "success",
			check:   func(t *testing.T, res Result, err error) { mustNil(t, err) },
			wantRef: "id",
		},
		{
			name: "exec infrastructure error",
			setup: func(f *dcFake) {
				f.execHandler = func(w http.ResponseWriter, _ *http.Request) {
					connectError(w, http.StatusInternalServerError, "internal", "exec broke")
				}
			},
			check: func(t *testing.T, _ Result, err error) {
				if err == nil || !strings.Contains(err.Error(), "exec broke") {
					t.Fatalf("err = %v", err)
				}
			},
			wantRef: "id",
		},
		{
			name:    "host deadline",
			setup:   func(f *dcFake) { f.execBlock = true },
			timeout: 1500 * time.Millisecond,
			check: func(t *testing.T, res Result, err error) {
				if err != nil || !res.TimedOut || res.ExitCode != 124 {
					t.Fatalf("res = %+v err = %v, want a timed-out result", res, err)
				}
			},
			wantRef: "id",
		},
		{
			name:  "context cancel",
			setup: func(f *dcFake) { f.execBlock = true },
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(300*time.Millisecond, cancel)
				return ctx, cancel
			},
			check: func(t *testing.T, _ Result, err error) {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err = %v, want context.Canceled", err)
				}
			},
			wantRef: "id",
		},
		{
			name:  "create rejected",
			setup: func(f *dcFake) { f.createStatus = http.StatusTooManyRequests },
			check: func(t *testing.T, _ Result, err error) {
				if err == nil || !strings.Contains(err.Error(), "resource_exhausted") {
					t.Fatalf("err = %v", err)
				}
			},
			wantRef: "name",
		},
		{
			name:  "create operation failed",
			setup: func(f *dcFake) { f.opError = true },
			check: func(t *testing.T, _ Result, err error) {
				if err == nil || !strings.Contains(err.Error(), "quota exhausted") {
					t.Fatalf("err = %v", err)
				}
			},
			wantRef: "name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDCFake(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			d := f.provider()
			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if tc.ctx != nil {
				ctx, cancel = tc.ctx()
			}
			defer cancel()
			res, err := d.RunJavaScript(ctx, Request{Code: "1", Timeout: tc.timeout})
			tc.check(t, res, err)
			refs := f.deletedRefs()
			if len(refs) != 1 || !strings.HasPrefix(refs[0], tc.wantRef+":") {
				t.Fatalf("deletes = %v, want one forced delete by %s", refs, tc.wantRef)
			}
			if tc.wantRef == "name" && refs[0] != "name:"+f.lastName() {
				t.Fatalf("deleted %s, created %s", refs[0], f.lastName())
			}
			if d.inflightCount() != 0 {
				t.Fatal("sandbox still tracked after the run")
			}
		})
	}
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDockerCloudWaitsForTheCreateOperation(t *testing.T) {
	for _, unimpl := range []bool{false, true} {
		f := newDCFake(t)
		f.opPending, f.waitUnimpl = true, unimpl
		if _, err := f.provider().RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
			t.Fatalf("waitUnimplemented=%v: %v", unimpl, err)
		}
		if unimpl && f.called(dcProcGetOperation) == 0 {
			t.Fatal("did not fall back to GetOperation polling")
		}
		if !unimpl && f.called(dcProcWaitOperation) == 0 {
			t.Fatal("did not use WaitOperation")
		}
	}
}

func TestDockerCloudGrantsAreRefusedBeforeAnyCall(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	grant := &HostAPIGrant{BaseURL: "https://api.example.com"}
	if _, err := d.RunJavaScript(context.Background(), Request{Code: "1", Grant: grant}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("snippet grant err = %v, want ErrUnsupported", err)
	}
	if _, err := d.RunProject(context.Background(), ProjectRequest{Files: []File{{Path: "a", Content: "a"}}, Steps: []string{"true"}, Grant: grant}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("project grant err = %v, want ErrUnsupported", err)
	}
	if d.SupportsJavaScriptGrants() || d.SupportsProjectGrants() {
		t.Fatal("dockercloud advertises grant support")
	}
	if len(f.calls) != 0 {
		t.Fatalf("grant refusal made API calls: %v", f.calls)
	}
	if _, err := d.RunModule(context.Background(), ModuleRequest{Model: "vdp", Rows: [][]float64{{1}}, EndTime: 1, Step: 0.1}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("module err = %v", err)
	}
}

func TestDockerCloudOrphanReconciliation(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.instanceID = "inst1"
	live := dcNamePrefix + "inst1-live"
	d.track(live)
	sb := func(id, name string) map[string]any {
		return map[string]any{"core": map[string]any{"id": id, "name": name, "createdAt": "2026-09-24T00:00:00Z"}}
	}
	f.listPages = [][]map[string]any{
		{sb("sb-orphan", dcNamePrefix+"inst1-orphan"), sb("sb-live", live), sb("sb-other", dcNamePrefix+"inst2-x")},
		{sb("sb-foreign", "someone-elses-sandbox"), sb("", dcNamePrefix+"inst1-noid"), sb("sb-prefixtrick", dcNamePrefix+"inst1")},
	}
	n, err := d.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	refs := f.deletedRefs()
	want := []string{"id:sb-orphan", "name:" + dcNamePrefix + "inst1-noid"}
	if n != 2 || strings.Join(refs, ",") != strings.Join(want, ",") {
		t.Fatalf("deleted %d: %v, want %v", n, refs, want)
	}
	if f.called(dcProcListSandboxes) != 2 {
		t.Fatal("did not follow the page token")
	}
}

func TestBuildDockerCloudValidation(t *testing.T) {
	pinned := "registry.example/plimsoll/sandbox@sha256:" + strings.Repeat("b", 64)
	base := func() map[string]string {
		return map[string]string{
			"SANDBOX_PROVIDER":            "dockercloud",
			"DOCKER_SBX_TOKEN":            "t",
			"DOCKER_SBX_USERNAME":         "u",
			"SANDBOX_DOCKERCLOUD_API_URL": "https://sbx.example.com/sbx",
			"SANDBOX_DOCKERCLOUD_IMAGE":   pinned,
		}
	}
	p, err := Build(mapEnv(base()))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	d, ok := p.Sandbox.(*DockerCloud)
	if !ok || d.Name() != "dockercloud" || d.IsolationClass() != IsolationVM || !d.SupportsProjects() {
		t.Fatalf("Build returned %T", p.Sandbox)
	}

	env := base()
	env["SANDBOX_CPUS"], env["SANDBOX_MEMORY_MB"] = "2", "2048"
	if p, err := Build(mapEnv(env)); err != nil || p.Sandbox.(*DockerCloud).MaxVCPU != 2 || p.Sandbox.(*DockerCloud).MaxMemoryMB != 2048 {
		t.Fatalf("envelope not applied: %v", err)
	}

	bad := map[string]func(map[string]string){
		"no token":       func(e map[string]string) { delete(e, "DOCKER_SBX_TOKEN") },
		"no API URL":     func(e map[string]string) { delete(e, "SANDBOX_DOCKERCLOUD_API_URL") },
		"no image":       func(e map[string]string) { delete(e, "SANDBOX_DOCKERCLOUD_IMAGE") },
		"cleartext API":  func(e map[string]string) { e["SANDBOX_DOCKERCLOUD_API_URL"] = "http://sbx.example.com" },
		"API with creds": func(e map[string]string) { e["SANDBOX_DOCKERCLOUD_API_URL"] = "https://u:p@sbx.example.com" },
		"API with query": func(e map[string]string) { e["SANDBOX_DOCKERCLOUD_API_URL"] = "https://sbx.example.com/?x=1" },
		"unpinned required": func(e map[string]string) {
			e["SANDBOX_DOCKERCLOUD_IMAGE"], e["SANDBOX_REQUIRE_PINNED_IMAGES"] = "plimsoll/sandbox:latest", "1"
		},
		"bad pinned boolean": func(e map[string]string) { e["SANDBOX_REQUIRE_PINNED_IMAGES"] = "yes" },
		"disk cap":           func(e map[string]string) { e["SANDBOX_DISK_MB"] = "1024" },
		"pids cap":           func(e map[string]string) { e["SANDBOX_PIDS"] = "64" },
		"fractional cpus":    func(e map[string]string) { e["SANDBOX_CPUS"] = "1.5" },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			env := base()
			mutate(env)
			if _, err := Build(mapEnv(env)); err == nil {
				t.Fatal("Build accepted an invalid dockercloud configuration")
			}
		})
	}
	// Loopback cleartext is allowed (tests and local sandboxd-style endpoints).
	env = base()
	env["SANDBOX_DOCKERCLOUD_API_URL"] = "http://127.0.0.1:9999"
	if _, err := Build(mapEnv(env)); err != nil {
		t.Fatalf("loopback URL rejected: %v", err)
	}
}

func TestDockerCloudRefusesUnsafeSandboxEndpoint(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	sb := dcSandbox{}
	if err := json.Unmarshal([]byte(`{"core":{"id":"x","status":"SANDBOX_STATUS_RUNNING","endpoint":{"uri":"http://evil.example.com/ep","protocol":"SANDBOX_ENDPOINT_PROTOCOL_CONNECT"}}}`), &sb); err != nil {
		t.Fatal(err)
	}
	if err := d.verifySandbox(sb); err == nil {
		t.Fatal("token would be sent to a cleartext non-loopback endpoint")
	}
	var sb2 dcSandbox
	if err := json.Unmarshal([]byte(`{"core":{"id":"x","status":"SANDBOX_STATUS_RUNNING","endpoint":{"uri":"https://ok.example.com","protocol":"SANDBOX_ENDPOINT_PROTOCOL_UNIX_SOCKET"}}}`), &sb2); err != nil {
		t.Fatal(err)
	}
	if err := d.verifySandbox(sb2); err == nil {
		t.Fatal("unix-socket endpoint accepted")
	}
	var sb3 dcSandbox
	if err := json.Unmarshal([]byte(`{"core":{"id":"x","status":"SANDBOX_STATUS_RUNNING","resources":{"cpus":1,"memoryMib":"2048"},"endpoint":{"uri":"https://ok.example.com"}},"cloud":{"imageDigest":"sha256:`+strings.Repeat("c", 64)+`"}}`), &sb3); err != nil {
		t.Fatal(err)
	}
	if err := d.verifySandbox(sb3); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("err = %v, want a digest mismatch", err)
	}
	// A pinned image with no booted digest reported is refused: no evidence, no run.
	var sb4 dcSandbox
	if err := json.Unmarshal([]byte(`{"core":{"id":"x","status":"SANDBOX_STATUS_RUNNING","resources":{"cpus":1,"memoryMib":"2048"},"endpoint":{"uri":"https://ok.example.com"}}}`), &sb4); err != nil {
		t.Fatal(err)
	}
	if err := d.verifySandbox(sb4); err == nil || !strings.Contains(err.Error(), "no booted image digest") {
		t.Fatalf("err = %v, want a refusal for a missing digest", err)
	}
}

func TestDockerCloudDefaultsToMicroWhenUnset(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.MaxVCPU, d.MaxMemoryMB = 0, 0
	if _, err := d.RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	res, _ := f.creates[0]["resources"].(map[string]any)
	if res["cpus"] != float64(dcDefaultCPUs) || res["memoryMib"] != strconv.Itoa(dcDefaultMemoryMiB) {
		t.Fatalf("requested resources = %v, want the Micro size", res)
	}
}

// dcSmokeGuest simulates the guest side of the startup smoke: the probe script,
// a hung `sleep` the in-guest limit should kill, and a `yes` flood the in-guest
// cap should truncate. The knobs break one property at a time.
type dcSmokeGuest struct {
	t          *testing.T
	probe      func() (int, string, string)
	hangEscape bool // the in-guest limit fails open: sleep runs to completion
	floodEsc   bool // the in-guest cap fails: the flood exits 0 untruncated
}

func (g *dcSmokeGuest) exec(argv []string) (int, string, string) {
	switch strings.Join(argv, " ") {
	case "sh /tmp/plimsoll-smoke-step.sh":
		return g.probe()
	case "sleep 30":
		time.Sleep(1100 * time.Millisecond) // the in-guest limit is 1s
		if g.hangEscape {
			return 0, "", ""
		}
		return 137, "", ""
	case "yes":
		if g.floodEsc {
			return 0, "y\n", ""
		}
		return 141, strings.Repeat("y", 64<<10+1), ""
	default:
		g.t.Errorf("unexpected smoke argv %q", argv)
		return 1, "", ""
	}
}

func TestDockerCloudSmokeTest(t *testing.T) {
	report := func(cwd string, open []string) func() (int, string, string) {
		return func() (int, string, string) {
			b, _ := json.Marshal(map[string]any{"node": "v22.0.0", "cwd": cwd, "egressOpen": open})
			return 0, string(b), ""
		}
	}
	setup := func(t *testing.T, tweak func(*dcFake, *dcSmokeGuest)) *dcFake {
		f := newDCFake(t)
		g := &dcSmokeGuest{t: t, probe: report("/tmp/plimsoll-project", nil)}
		if tweak != nil {
			tweak(f, g)
		}
		f.exec = g.exec
		return f
	}

	f := setup(t, nil)
	if err := f.provider().SmokeTest(context.Background()); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	if f.called(dcProcGetCapabilities) != 1 || len(f.deletedRefs()) != 1 {
		t.Fatal("smoke did not check capabilities or did not delete its sandbox")
	}

	fails := map[string]func(*dcFake, *dcSmokeGuest){
		"missing permission": func(f *dcFake, _ *dcSmokeGuest) {
			f.caps = map[string]any{"canAttachPolicies": true, "permissions": []string{"PERMISSION_SANDBOXES_READ"}}
		},
		"egress open": func(_ *dcFake, g *dcSmokeGuest) {
			g.probe = report("/tmp/plimsoll-project", []string{"https://1.1.1.1"})
		},
		"cwd ignored": func(_ *dcFake, g *dcSmokeGuest) { g.probe = report("/", nil) },
		"missing toolchain": func(_ *dcFake, g *dcSmokeGuest) {
			g.probe = func() (int, string, string) { return 127, "", "sh: node: not found" }
		},
		"policy not in force":     func(f *dcFake, _ *dcSmokeGuest) { f.policyMode = "NETWORK_POLICY_MODE_ALLOW_ALL" },
		"time limit fails open":   func(_ *dcFake, g *dcSmokeGuest) { g.hangEscape = true },
		"output cap not in force": func(_ *dcFake, g *dcSmokeGuest) { g.floodEsc = true },
	}
	for name, tweak := range fails {
		t.Run(name, func(t *testing.T) {
			f := setup(t, tweak)
			if err := f.provider().SmokeTest(context.Background()); err == nil {
				t.Fatal("SmokeTest passed")
			}
			if len(f.creates) > 0 && len(f.deletedRefs()) != 1 {
				t.Fatal("smoke sandbox not deleted")
			}
		})
	}
	// A full permission list passes.
	f = setup(t, func(f *dcFake, _ *dcSmokeGuest) {
		var perms []string
		for _, p := range dockerCloudRequiredPermissions {
			perms = append(perms, p.name)
		}
		f.caps = map[string]any{"canAttachPolicies": true, "permissions": perms}
	})
	if err := f.provider().SmokeTest(context.Background()); err != nil {
		t.Fatalf("SmokeTest with full permissions: %v", err)
	}
}

func TestDockerCloudUnauthenticatedIsAnError(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.Token = "wrong"
	_, err := d.RunJavaScript(context.Background(), Request{Code: "1"})
	if !dcCodeIs(err, "unauthenticated") {
		t.Fatalf("err = %v, want unauthenticated", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatal("the token leaked into the error text")
	}
}

func TestReadConnectFramesRequiresEndOfStream(t *testing.T) {
	msg := connectEnvelope([]byte(`{}`))
	if err := readConnectFrames(bytes.NewReader(msg), "p", 1<<10, 1<<10, func([]byte) error { return nil }); err == nil {
		t.Fatal("a stream cut before its end frame was accepted")
	}
	end := connectEnvelope([]byte(`{"error":{"code":"internal","message":"x"}}`))
	end[0] = 0x02
	if err := readConnectFrames(bytes.NewReader(end), "p", 1<<10, 1<<10, func([]byte) error { return nil }); !dcCodeIs(err, "internal") {
		t.Fatalf("end-stream error not surfaced: %v", err)
	}
	big := make([]byte, 5)
	binary.BigEndian.PutUint32(big[1:], 1<<20)
	if err := readConnectFrames(bytes.NewReader(big), "p", 1<<10, 1<<30, func([]byte) error { return nil }); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestDockerCloudExchangesTokenAndCaches(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	for i := 0; i < 3; i++ {
		if _, err := d.bearer(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.exchanges != 1 {
		t.Fatalf("token exchanged %d times for three calls, want 1", f.exchanges)
	}
}

func TestDockerCloudRefreshesNearExpiry(t *testing.T) {
	f := newDCFake(t)
	f.accessLife = dcAuthRefreshMargin / 2 // already inside the refresh margin
	d := f.provider()
	for i := 0; i < 2; i++ {
		if _, err := d.bearer(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.exchanges != 2 {
		t.Fatalf("a token inside the refresh margin was reused: %d exchanges, want 2", f.exchanges)
	}
}

func TestDockerCloudRefusedExchangeHidesSecret(t *testing.T) {
	f := newDCFake(t)
	f.refuseExchange = true
	_, err := f.provider().bearer(context.Background())
	if err == nil {
		t.Fatal("a refused exchange returned a token")
	}
	if strings.Contains(err.Error(), dcTestToken) {
		t.Fatalf("error leaks the access token: %v", err)
	}
}

func TestDockerCloudRequiresUsername(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.Username = ""
	if err := d.validateConfig(); err == nil || !strings.Contains(err.Error(), "DOCKER_SBX_USERNAME") {
		t.Fatalf("missing username accepted: %v", err)
	}
}

func TestDockerCloudJWTExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if got := dcJWTExpiry(dcTestAccess(now.Add(900*time.Second)), now); !got.Equal(now.Add(900 * time.Second)) {
		t.Fatalf("exp read as %v", got)
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c", dcTestAccess(time.Unix(0, 0))} {
		if got := dcJWTExpiry(bad, now); !got.Equal(now.Add(5 * time.Minute)) {
			t.Fatalf("%q: fallback expiry %v", bad, got)
		}
	}
}

// ---- host-API grants ----

// dcGrant is a grant against an httptest upstream that answers GET /items/*.
func dcGrant(t *testing.T) (*HostAPIGrant, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer downstream-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `"}`))
	}))
	t.Cleanup(up.Close)
	return &HostAPIGrant{BaseURL: up.URL, Allow: []HostRoute{{Method: "GET", Path: "/items/*"}}, Minter: StaticToken("downstream-secret")}, up
}

func TestDockerCloudGrantRefusedWithoutGuardURL(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	grant, _ := dcGrant(t)
	if d.SupportsJavaScriptGrants() || d.SupportsProjectGrants() {
		t.Fatal("grants advertised without a guard URL")
	}
	_, err := d.RunJavaScript(context.Background(), Request{Code: "1", Grant: grant})
	if !errors.Is(err, ErrUnsupported) || len(f.creates) != 0 {
		t.Fatalf("err = %v, creates = %d; want ErrUnsupported before any sandbox", err, len(f.creates))
	}
}

func TestDockerCloudGrantSnippetOpensOnlyTheGuard(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.GuardURL = "https://guard.example.com/v1/dockercloud/guard"
	grant, _ := dcGrant(t)
	if !d.SupportsJavaScriptGrants() || !d.SupportsProjectGrants() || d.EgressGuardPath() != "/v1/dockercloud/guard" {
		t.Fatal("grant capability or guard path not reported")
	}
	var token string
	f.exec = func(argv []string) (int, string, string) {
		// While the run is live its credential is known to the guard.
		body := string(f.uploads[len(f.uploads)-1][0].content)
		i := strings.Index(body, `"X-Plimsoll-Guard":"`)
		if i < 0 {
			t.Fatalf("snippet has no guard header: %.300s", body)
		}
		token = body[i+len(`"X-Plimsoll-Guard":"`):]
		token = token[:strings.Index(token, `"`)]
		if !d.EgressGuardKnownToken(token) {
			t.Fatal("the run's credential is not registered while the run is live")
		}
		// The guest's host.get, as it arrives at the guard.
		req := httptest.NewRequest(http.MethodPost, d.EgressGuardPath(), strings.NewReader(`{"method":"GET","path":"/items/1"}`))
		req.Header.Set(EgressGuardHeader, token)
		rec := httptest.NewRecorder()
		EgressGuardHTTPHandler(d, d.EgressGuardPath(), 4).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("guard call during the run: %d %s", rec.Code, rec.Body.String())
		}
		return 0, "ok\n", ""
	}
	res, err := d.RunJavaScript(context.Background(), Request{Code: `console.log("ok")`, Grant: grant})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("res = %+v err = %v", res, err)
	}
	if len(f.policyPuts) != 1 {
		t.Fatalf("policy PUTs = %d, want 1", len(f.policyPuts))
	}
	put := f.policyPuts[0]
	if put["mode"] != "deny-all" || fmt.Sprint(put["allowNetworks"]) != "[guard.example.com:443]" {
		t.Fatalf("policy PUT = %v, want deny-all with only the guard host on 443", put)
	}
	if res.CallTrace == nil || len(res.CallTrace.Calls) != 1 || res.CallTrace.Calls[0].Route != "/items/*" || res.CallTrace.Calls[0].Status != http.StatusOK {
		t.Fatalf("call trace = %+v, want the one brokered call by route template", res.CallTrace)
	}
	body := string(f.uploads[0][0].content)
	if strings.Contains(body, "downstream-secret") || !strings.Contains(body, "https://guard.example.com/v1/dockercloud/guard") {
		t.Fatal("the snippet carries the downstream credential or lacks the guard URL")
	}
	if d.EgressGuardKnownToken(token) {
		t.Fatal("the run's credential outlived the run")
	}
	if len(f.deletedRefs()) != 1 {
		t.Fatal("sandbox not deleted")
	}
}

func TestDockerCloudNoGrantRunNeverOpensTheNetwork(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.GuardURL = "https://guard.example.com/g"
	f.exec = func([]string) (int, string, string) { return 0, "", "" }
	if _, err := d.RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	if len(f.policyPuts) != 0 {
		t.Fatalf("a no-grant run sent %d policy PUT(s)", len(f.policyPuts))
	}
}

func TestDockerCloudGrantFailsClosed(t *testing.T) {
	cases := map[string]func(*dcFake){
		"policy PUT refused":               func(f *dcFake) { f.policyPutStatus = http.StatusForbidden },
		"policy PUT echoes another":        func(f *dcFake) { f.policyEchoWrong = true },
		"rule accepted, never in force":    func(f *dcFake) { f.policyIgnored = true },
		"an extra rule from another layer": func(f *dcFake) { f.policyAllow = []string{"registry.npmjs.org:443"} },
		"mode not deny-all":                func(f *dcFake) { f.policyMode = "NETWORK_POLICY_MODE_ALLOW_ALL" },
	}
	for name, tweak := range cases {
		t.Run(name, func(t *testing.T) {
			f := newDCFake(t)
			tweak(f)
			d := f.provider()
			d.GuardURL = "https://guard.example.com/g"
			grant, _ := dcGrant(t)
			ran := false
			f.exec = func([]string) (int, string, string) { ran = true; return 0, "", "" }
			if _, err := d.RunJavaScript(context.Background(), Request{Code: "1", Grant: grant}); err == nil {
				t.Fatal("the run proceeded")
			}
			if ran {
				t.Fatal("caller code ran before the network was proven")
			}
			if len(f.creates) > 0 && len(f.deletedRefs()) != 1 {
				t.Fatal("sandbox not deleted")
			}
		})
	}
}

func TestDockerCloudGrantProjectPreloadsTheClient(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.GuardURL = "https://guard.example.com/g"
	grant, _ := dcGrant(t)
	var steps [][]string
	f.exec = func(argv []string) (int, string, string) {
		if len(argv) > 0 && (argv[0] == "env" || argv[0] == "sh") {
			steps = append(steps, argv)
		}
		return 0, "", ""
	}
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "main.mjs", Content: "await host.get('/items/1')"}}, Steps: []string{"node main.mjs"}, Grant: grant})
	if err != nil || res.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("res = %+v err = %v", res, err)
	}
	if len(steps) != 1 || strings.Join(steps[0][:2], " ") != "env NODE_OPTIONS=--import "+dcHostModulePath {
		t.Fatalf("step argv = %v, want the guard client preloaded", steps)
	}
	found := false
	for _, file := range f.uploads[0] {
		if file.path == dcHostModulePath {
			found = true
			if !strings.Contains(string(file.content), `"X-Plimsoll-Guard":"crg_`) || strings.Contains(string(file.content), "downstream-secret") {
				t.Fatal("the host module lacks the run credential or carries the downstream credential")
			}
		}
	}
	if !found {
		t.Fatal("host module not staged")
	}
}

// The guard itself, through the shared HTTP handler: a live run's credential and an
// allowed route reach the upstream with the downstream credential added outside the
// VM; a wrong route, a forged credential and an expired one are refused.
func TestDockerCloudGuardEnforcesTheGrant(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.GuardURL = "https://guard.example.com/v1/dockercloud/guard"
	grant, _ := dcGrant(t)
	guard, closeGuard, err := d.openGuard(context.Background(), grant, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h := EgressGuardHTTPHandler(d, d.EgressGuardPath(), 4)
	call := func(token, method, path string) (int, string) {
		body := `{"method":"` + method + `","path":"` + path + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/dockercloud/guard", strings.NewReader(body))
		if token != "" {
			req.Header.Set(EgressGuardHeader, token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := call(guard.token, "GET", "/items/7"); code != http.StatusOK || !strings.Contains(body, "/items/7") {
		t.Fatalf("allowed call: %d %s", code, body)
	}
	if code, _ := call(guard.token, "GET", "/admin"); code < 400 {
		t.Fatalf("a route outside the grant was allowed: %d", code)
	}
	if code, _ := call(guard.token, "DELETE", "/items/7"); code < 400 {
		t.Fatalf("a method outside the grant was allowed: %d", code)
	}
	if code, _ := call("crg_forged", "GET", "/items/7"); code != http.StatusUnauthorized {
		t.Fatalf("forged credential: %d", code)
	}
	if code, _ := call("", "GET", "/items/7"); code != http.StatusUnauthorized {
		t.Fatalf("missing credential: %d", code)
	}
	closeGuard()
	if code, _ := call(guard.token, "GET", "/items/7"); code != http.StatusUnauthorized {
		t.Fatalf("expired credential: %d", code)
	}
}

func TestBuildDockerCloudRejectsABadGuardURL(t *testing.T) {
	env := map[string]string{
		"SANDBOX_PROVIDER": "dockercloud", "DOCKER_SBX_TOKEN": "t", "DOCKER_SBX_USERNAME": "u",
		"SANDBOX_DOCKERCLOUD_API_URL": "https://api.example.com/sbx",
		"SANDBOX_DOCKERCLOUD_IMAGE":   "registry.example/img@sha256:" + strings.Repeat("a", 64),
	}
	for _, bad := range []string{"http://guard.example.com/g", "https://guard.example.com:8443/g", "https://localhost/g", "https://guard.example.com/a/../b"} {
		env["SANDBOX_DOCKERCLOUD_GUARD_URL"] = bad
		if _, err := Build(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "SANDBOX_DOCKERCLOUD_GUARD_URL") {
			t.Fatalf("%s: err = %v, want a guard URL refusal", bad, err)
		}
	}
	env["SANDBOX_DOCKERCLOUD_GUARD_URL"] = "https://guard.example.com"
	p, err := Build(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := p.Sandbox.(EgressGuardCapable); !ok || g.EgressGuardPath() != dcGuardDefaultPath {
		t.Fatal("a configured guard URL does not expose the default guard path")
	}
}

// An accepted DeleteSandbox is not a completed deletion: a failed delete operation
// makes teardown retry until one succeeds.
func TestDockerCloudDeleteWaitsForItsOperation(t *testing.T) {
	f := newDCFake(t)
	f.deleteOpFailures = 1
	d := f.provider()
	f.exec = func([]string) (int, string, string) { return 0, "", "" }
	if _, err := d.RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	if n := len(f.deletedRefs()); n != 2 {
		t.Fatalf("delete requests = %d, want 2 (the first operation failed, the retry succeeded)", n)
	}
}

func TestDockerCloudRefusesUnreportedOrLargerSize(t *testing.T) {
	for name, tweak := range map[string]func(*dcFake){
		"no size reported":       func(f *dcFake) { f.noResources = true },
		"more CPU than asked":    func(f *dcFake) { f.reportedCPUs = 2 },
		"more memory than asked": func(f *dcFake) { f.reportedMemMiB = 4096 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newDCFake(t)
			tweak(f)
			d := f.provider()
			d.MaxVCPU, d.MaxMemoryMB = 0, 0 // the Micro default is the requested size
			ran := false
			f.exec = func([]string) (int, string, string) { ran = true; return 0, "", "" }
			if _, err := d.RunJavaScript(context.Background(), Request{Code: "1"}); err == nil || ran {
				t.Fatalf("err = %v, ran = %v; want a refusal before any code", err, ran)
			}
		})
	}
}

// Vendor text that echoes the exchanged bearer, the personal access token or a JWT
// never reaches an error.
func TestDockerCloudErrorsNeverCarryCredentials(t *testing.T) {
	for name, tweak := range map[string]func(*dcFake, string){
		"connect error":    func(f *dcFake, s string) { f.echoSecret = s },
		"failed operation": func(f *dcFake, s string) { f.opErrorEcho = s },
	} {
		t.Run(name, func(t *testing.T) {
			f := newDCFake(t)
			d := f.provider()
			// Mint the bearer first so the fake can echo the real one.
			if _, err := d.bearer(context.Background()); err != nil {
				t.Fatal(err)
			}
			tweak(f, f.issued)
			_, err := d.RunJavaScript(context.Background(), Request{Code: "1"})
			if err == nil {
				t.Fatal("run succeeded")
			}
			if strings.Contains(err.Error(), f.issued) || strings.Contains(err.Error(), dcTestToken) || !strings.Contains(err.Error(), "<redacted>") {
				t.Fatalf("error carries a credential or was not scrubbed: %v", err)
			}
		})
	}
	if got := truncateForError("x dckr_pat_AbC-123 y crg_" + strings.Repeat("a", 64)); strings.Contains(got, "dckr_pat_") || strings.Contains(got, "crg_") {
		t.Fatalf("personal token or guard credential survived: %q", got)
	}
}
