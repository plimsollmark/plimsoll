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
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The REST half of dcFake: the same server, state and knobs, speaking the REST API on
// the wire. Each call is recorded under the Connect procedure it stands for, and each
// create and delete in the Connect request's shape, so a behavior test's assertions
// read the same for both transports (eachDCAPI). Where the two APIs truly differ, the
// test says so with its own expectation for REST.

// eachDCAPI runs a behavior test once per transport, each against the fake speaking
// that API. The two run side by side, so covering both APIs does not double the
// package's time: each has its own fake server and provider, and none of these tests
// touches process-wide state (no t.Setenv), which a parallel test must not.
func eachDCAPI(t *testing.T, test func(t *testing.T, api string)) {
	t.Helper()
	for _, api := range []string{dcAPIConnect, dcAPIREST} {
		t.Run(api, func(t *testing.T) {
			t.Parallel()
			test(t, api)
		})
	}
}

func newDCFakeAPI(t *testing.T, api string) *dcFake {
	t.Helper()
	f := newDCFake(t)
	f.api = api
	return f
}

// dcRESTFake is the REST-only state: the one sandbox the fake models, and knobs that
// exist only in this API.
type dcRESTFake struct {
	live    bool                       // a create reached the fake and no delete has removed the sandbox
	etag    int                        // the sandbox's ETag version; a change makes an older If-Match stale
	tokens  map[string]map[string]bool // credential -> its permissions
	minted  int
	used    []string // the credential each endpoint call carried, in order
	gets    atomic.Int32
	deletes int // DELETE requests that removed the sandbox

	staleOnce      bool          // the ETag changes between the delete's read and its DELETE, once
	deleteLag      int           // reads after the delete that still find the sandbox "deleting"
	endpointCaps   []string      // overrides the endpoint's capabilities
	endpointProto  string        // overrides the endpoint's protocol ("http")
	recordedImage  string        // overrides the image reference the sandbox reports
	downloadCut    bool          // the download stops before its closing delimiter
	rateLimitReads int           // this many sandbox reads are answered 429 first
	incomplete     bool          // exec answers incomplete: true
	displayName    string        // overrides the display name the sandbox reports
	mintLimited    int           // this many mints are answered 429 first
	refuseOnce     bool          // the first endpoint call is refused 401, "invalid endpoint credential"
	expiredExec    bool          // every exec is answered 401 ENDPOINT_CREDENTIAL_EXPIRED, as one cut off mid-run
	credLife       time.Duration // the life a minted credential is given; default 5 minutes

	gone map[string]bool // listed sandboxes (listPages) a delete has removed
}

const dcRESTUID = "sb-1"

func restError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": msg})
}

var dcSnake = regexp.MustCompile(`_([a-z])`)

// camel turns a Connect code into the REST API's spelling.
func camel(code string) string {
	return dcSnake.ReplaceAllStringFunc(code, func(m string) string { return strings.ToUpper(m[1:]) })
}

// restMode is the REST spelling of the Connect policy mode a test configured.
func restMode(mode string) string {
	switch mode {
	case "NETWORK_POLICY_MODE_DENY_ALL", "2":
		return "denyAll"
	case "NETWORK_POLICY_MODE_ALLOW_ALL", "1":
		return "allowAll"
	}
	return mode
}

func (f *dcFake) restState() *dcRESTFake {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rest == nil {
		f.rest = &dcRESTFake{tokens: map[string]map[string]bool{}, gone: map[string]bool{}}
	}
	return f.rest
}

func (f *dcFake) record(proc string) {
	f.mu.Lock()
	f.calls = append(f.calls, proc)
	f.mu.Unlock()
}

// restSandbox is the modelled sandbox in the REST API's shape.
func (f *dcFake) restSandbox(status string) map[string]any {
	rs := f.restState()
	// Built from the Connect fake's sandbox, so the size knobs mean the same.
	cs := f.sandbox(f.lastName())["core"].(map[string]any)
	f.mu.Lock()
	defer f.mu.Unlock()
	caps := []string{"createProcess", "download", "exec", "list", "mkdir", "readFile", "upload", "writeFile"}
	if rs.endpointCaps != nil {
		caps = rs.endpointCaps
	}
	proto := "http"
	if rs.endpointProto != "" {
		proto = rs.endpointProto
	}
	image := ""
	if n := len(f.creates); n > 0 {
		image, _ = f.creates[n-1]["cloud"].(map[string]any)["imageRef"].(string)
	}
	if rs.recordedImage != "" {
		image = rs.recordedImage
	}
	etag := fmt.Sprintf(`"e%d"`, rs.etag)
	core := map[string]any{
		"status":    status,
		"createdAt": cs["createdAt"],
		"etag":      etag,
		"imageRef":  image,
		"endpoint": map[string]any{
			"uri": f.srv.URL + "/ep", "protocol": proto, "capabilities": caps,
			"sandbox": "sandboxes/" + dcRESTUID, "sandboxUid": dcRESTUID, "apiVersion": "v1",
			"authentication": map[string]any{"scheme": "scopedBearer", "defaultTtl": "300s", "maxTtl": "300s"},
		},
	}
	if res, ok := cs["resources"]; ok {
		core["resources"] = res
	}
	display := f.lastNameLocked()
	if rs.displayName != "" {
		display = rs.displayName
	}
	out := map[string]any{"uid": dcRESTUID, "name": "sandboxes/" + dcRESTUID, "displayName": display, "core": core}
	if status == "failed" {
		msg := "quota exhausted"
		if f.opErrorEcho != "" {
			msg = "rejected token " + f.opErrorEcho
		}
		out["failure"] = map[string]any{"code": "resourceExhausted", "message": msg}
	}
	return out
}

func (f *dcFake) lastNameLocked() string {
	if len(f.creates) == 0 {
		return ""
	}
	name, _ := f.creates[len(f.creates)-1]["name"].(string)
	return name
}

// restStatus is the status a read of the modelled sandbox finds; found false is the
// API's notFound.
func (f *dcFake) restStatus() (status string, found bool) {
	rs := f.restState()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !rs.live || f.deleteNotFound {
		if rs.deleteLag > 0 && !f.deleteNotFound && rs.deletes > 0 {
			rs.deleteLag--
			return "deleting", true
		}
		return "", false
	}
	switch {
	case f.opError || f.opErrorEcho != "":
		return "failed", true
	case f.opPending && f.opNeverDone:
		return "creating", true
	}
	return "running", true
}

func (f *dcFake) handleREST(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/ep/") {
		f.handleRESTEndpoint(w, r)
		return
	}
	f.mu.Lock()
	issued := f.issued
	f.mu.Unlock()
	if issued == "" || r.Header.Get("Authorization") != "Bearer "+issued {
		restError(w, http.StatusUnauthorized, "unauthenticated", "bad token")
		return
	}
	body, _ := io.ReadAll(r.Body)
	var in map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &in); err != nil {
			f.t.Errorf("%s %s: request is not JSON: %v", r.Method, r.URL.Path, err)
		}
	}
	rs := f.restState()
	path := r.URL.Path
	sandboxPath := "/v1/sandboxes/" + dcRESTUID
	switch {
	case path == "/v1/sandboxes" && r.Method == http.MethodPost:
		f.record(dcProcCreateSandbox)
		f.restCreate(w, r, in)
	case path == "/v1/sandboxes" && r.Method == http.MethodGet:
		if r.URL.Query().Get("pageSize") == "1" {
			f.record(dcProcGetCapabilities) // the REST transport's capability check
			writeJSON(w, map[string]any{"sandboxes": []any{}})
			return
		}
		f.record(dcProcListSandboxes)
		f.restList(w, r)
	case path == sandboxPath && r.Method == http.MethodGet:
		f.record(dcProcGetSandbox)
		rs.gets.Add(1)
		f.mu.Lock()
		limited := rs.rateLimitReads > 0
		if limited {
			rs.rateLimitReads--
		}
		f.mu.Unlock()
		if limited {
			w.Header().Set("Retry-After", "0")
			restError(w, http.StatusTooManyRequests, "resourceExhausted", "slow down")
			return
		}
		status, found := f.restStatus()
		if !found {
			restError(w, http.StatusNotFound, "notFound", "Sandbox not found")
			return
		}
		sb := f.restSandbox(status)
		w.Header().Set("ETag", sb["core"].(map[string]any)["etag"].(string))
		writeJSON(w, sb)
	case path == sandboxPath && r.Method == http.MethodDelete:
		f.record(dcProcDeleteSandbox)
		if f.onDelete != nil {
			f.onDelete()
		}
		f.mu.Lock()
		f.deletes = append(f.deletes, map[string]any{"sandbox": map[string]any{"id": dcRESTUID}, "force": r.URL.Query().Get("force") == "true"})
		match := r.Header.Get("If-Match")
		if rs.staleOnce {
			rs.staleOnce = false
			rs.etag++
		}
		current := fmt.Sprintf(`"e%d"`, rs.etag)
		failures := f.deleteOpFailures
		if failures > 0 {
			f.deleteOpFailures--
		}
		f.mu.Unlock()
		switch {
		case match == "":
			restError(w, http.StatusPreconditionRequired, "failedPrecondition", "etag_required")
		case match == "*":
			restError(w, http.StatusPreconditionRequired, "failedPrecondition", "etag_required: * is refused")
		case match != current:
			restError(w, http.StatusPreconditionFailed, "failedPrecondition", "stale etag")
		case failures > 0:
			restError(w, http.StatusInternalServerError, "internal", "delete failed")
		default:
			f.mu.Lock()
			rs.live = false
			rs.deletes++
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	case path == sandboxPath+"/network-policies" && r.Method == http.MethodGet:
		f.record(dcProcEffectivePolicy)
		allow := []any{}
		for _, a := range f.policyAllow {
			allow = append(allow, map[string]any{"network": a, "layer": "owner"})
		}
		writeJSON(w, map[string]any{
			"effective": map[string]any{"mode": restMode(f.policyMode), "allowNetworks": allow},
			"exact":     map[string]any{"revision": "r1", "selectorVersion": "destination.v1", "nodes": []any{}},
		})
	case path == sandboxPath+"/endpoint-credentials" && r.Method == http.MethodPost:
		f.record("rest:endpoint-credentials")
		perms, _ := in["permissions"].([]any)
		set := map[string]bool{}
		for _, p := range perms {
			set[p.(string)] = true
		}
		f.mu.Lock()
		limited := rs.mintLimited > 0
		if limited {
			rs.mintLimited--
		}
		life := rs.credLife
		if life == 0 {
			life = 5 * time.Minute
		}
		token := ""
		if !limited {
			rs.minted++
			token = fmt.Sprintf("ep-%d", rs.minted)
			rs.tokens[token] = set
		}
		f.mu.Unlock()
		if limited {
			restError(w, http.StatusTooManyRequests, "resourceExhausted", "Too Many Requests")
			return
		}
		writeJSON(w, map[string]any{"token": token, "expireTime": time.Now().Add(life).UTC().Format(time.RFC3339Nano),
			"permissions": perms, "sandbox": "sandboxes/" + dcRESTUID, "audience": "docker.sandboxes.endpoint.test"})
	case strings.HasPrefix(path, "/v1/sandboxes/") && !strings.Contains(strings.TrimPrefix(path, "/v1/sandboxes/"), "/"):
		f.restListed(w, r, strings.TrimPrefix(path, "/v1/sandboxes/"))
	default:
		// A route the fake does not serve answers like a proxy would: no API error body.
		http.NotFound(w, r)
	}
}

// restListed serves a read or delete of a sandbox a test listed (listPages), which
// exists until a delete removes it.
func (f *dcFake) restListed(w http.ResponseWriter, r *http.Request, uid string) {
	rs := f.restState()
	name := ""
	for _, page := range f.listPages {
		for _, sb := range page {
			if core := sb["core"].(map[string]any); core["id"] == uid {
				name, _ = core["name"].(string)
			}
		}
	}
	f.mu.Lock()
	exists := name != "" && !rs.gone[uid]
	f.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		f.record(dcProcGetSandbox)
		if !exists {
			restError(w, http.StatusNotFound, "notFound", "Sandbox not found")
			return
		}
		w.Header().Set("ETag", `"l1"`)
		writeJSON(w, map[string]any{"uid": uid, "displayName": name, "core": map[string]any{"status": "running", "etag": `"l1"`}})
	case http.MethodDelete:
		f.record(dcProcDeleteSandbox)
		f.mu.Lock()
		f.deletes = append(f.deletes, map[string]any{"sandbox": map[string]any{"id": uid}, "force": r.URL.Query().Get("force") == "true"})
		f.mu.Unlock()
		if r.Header.Get("If-Match") != `"l1"` {
			restError(w, http.StatusPreconditionFailed, "failedPrecondition", "stale etag")
			return
		}
		f.mu.Lock()
		rs.gone[uid] = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (f *dcFake) restCreate(w http.ResponseWriter, r *http.Request, in map[string]any) {
	// Recorded in the Connect request's shape, plus the REST body as sent.
	norm := map[string]any{"name": in["displayName"], "requestId": r.Header.Get("Idempotency-Key"), "rest": in}
	if p, ok := in["networkPolicies"]; ok {
		norm["networkPolicies"] = p
	}
	timeouts, _ := in["features"].(map[string]any)["timeouts"].(map[string]any)
	onTimeout := timeouts["onTimeout"]
	if onTimeout == "delete" {
		onTimeout = "ON_TIMEOUT_DELETE"
	}
	start, _ := in["startupExecution"].(map[string]any)["rawImage"].(map[string]any)["start"].(map[string]any)
	norm["cloud"] = map[string]any{"imageRef": in["imageRef"], "startCmd": start["argv"], "timeout": timeouts["timeout"],
		"onTimeout": onTimeout, "autoResume": timeouts["autoResume"], "platform": in["platform"]}
	if res, ok := in["resources"].(map[string]any); ok {
		cp := map[string]any{"cpus": res["cpus"]}
		if m, ok := res["memoryMib"].(float64); ok {
			cp["memoryMib"] = strconv.Itoa(int(m))
		}
		norm["resources"] = cp
	}
	f.mu.Lock()
	f.creates = append(f.creates, norm)
	f.mu.Unlock()
	rs := f.restState()
	if f.createDrop {
		f.mu.Lock()
		rs.live = true // the request arrived; only its answer is lost
		f.mu.Unlock()
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
		return
	}
	if f.createStatus != 0 {
		code := f.createCode
		if code == "" {
			code = "resource_exhausted"
		}
		restError(w, f.createStatus, camel(code), "no capacity")
		return
	}
	if f.echoSecret != "" {
		restError(w, http.StatusBadRequest, "invalidArgument", "bad request from Authorization: Bearer "+f.echoSecret+" and "+f.echoSecret)
		return
	}
	f.mu.Lock()
	rs.live = true
	rs.etag++
	f.mu.Unlock()
	status, code := "running", http.StatusCreated
	if f.opPending || f.opError || f.opErrorEcho != "" {
		status, code = "creating", http.StatusAccepted
	}
	sb := f.restSandbox(status)
	w.Header().Set("ETag", sb["core"].(map[string]any)["etag"].(string))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(sb)
}

func (f *dcFake) restList(w http.ResponseWriter, r *http.Request) {
	page := 0
	if tok := r.URL.Query().Get("pageToken"); tok != "" {
		page, _ = strconv.Atoi(tok)
	}
	rs := f.restState()
	var sandboxes []any
	if page < len(f.listPages) {
		for _, sb := range f.listPages[page] {
			core := sb["core"].(map[string]any)
			id, _ := core["id"].(string)
			f.mu.Lock()
			gone := rs.gone[id]
			f.mu.Unlock()
			if id != "" && !gone { // the REST API always names a sandbox's uid
				sandboxes = append(sandboxes, map[string]any{"uid": id, "displayName": core["name"], "core": map[string]any{"createdAt": core["createdAt"]}})
			}
		}
	}
	if page == 0 {
		if _, found := f.restStatus(); found {
			sandboxes = append(sandboxes, f.restSandbox("running"))
		}
	}
	out := map[string]any{"sandboxes": sandboxes}
	if page+1 < len(f.listPages) {
		out["nextPageToken"] = strconv.Itoa(page + 1)
	}
	writeJSON(w, out)
}

// handleRESTEndpoint serves the sandbox endpoint, which takes only a credential minted
// for the call, never the management token.
func (f *dcFake) handleRESTEndpoint(w http.ResponseWriter, r *http.Request) {
	rs := f.restState()
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	perms, ok := rs.tokens[token]
	issued := f.issued
	refuse := rs.refuseOnce
	rs.refuseOnce = false
	rs.used = append(rs.used, token)
	f.mu.Unlock()
	if token == issued {
		f.t.Errorf("%s: the management token was sent to the sandbox endpoint", r.URL.Path)
	}
	if !ok || refuse {
		restError(w, http.StatusUnauthorized, "unauthenticated", "invalid endpoint credential")
		return
	}
	need := map[string]string{"/ep/v1/processes/exec": "sandboxesExec", "/ep/v1/files/upload": "sandboxesFilesWrite", "/ep/v1/files/download": "sandboxesFilesRead"}[r.URL.Path]
	if !perms[need] {
		restError(w, http.StatusForbidden, "permissionDenied", "credential lacks "+need)
		return
	}
	switch r.URL.Path {
	case "/ep/v1/processes/exec":
		f.record("/ep" + dcProcExec)
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		var cmd []string
		for _, c := range in["cmd"].([]any) {
			cmd = append(cmd, c.(string))
		}
		cwd, _ := in["workingDir"].(string)
		f.mu.Lock()
		f.execs = append(f.execs, cmd)
		f.execCwds = append(f.execCwds, cwd)
		incomplete, expired := rs.incomplete, rs.expiredExec
		f.mu.Unlock()
		if expired {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"unauthenticated","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ENDPOINT_CREDENTIAL_EXPIRED"}],"message":"endpoint_credential_expired"}`))
			return
		}
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
		out := map[string]any{"stdout": []byte(stdout), "stderr": []byte(stderr)}
		if exit != 0 { // protojson leaves a zero exit code out (probe)
			out["exitCode"] = exit
		}
		if incomplete && cmd[0] != "mkdir" {
			out["incomplete"] = true
		}
		writeJSON(w, out)
	case "/ep/v1/files/upload":
		f.record("/ep" + dcProcUpload)
		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "multipart/form-data" {
			f.t.Errorf("upload content type = %q", r.Header.Get("Content-Type"))
			return
		}
		var files []dcFakeFile
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextRawPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.t.Errorf("upload body: %v", err)
				return
			}
			b, _ := io.ReadAll(part)
			switch part.FormName() {
			case "metadata":
				var meta struct {
					Path string  `json:"path"`
					Mode float64 `json:"mode"`
				}
				if err := json.Unmarshal(b, &meta); err != nil {
					restError(w, http.StatusBadRequest, "invalidArgument", "expected unencoded metadata part")
					return
				}
				files = append(files, dcFakeFile{path: meta.Path, mode: meta.Mode})
			case "content":
				if len(files) == 0 {
					f.t.Errorf("content part before metadata")
					continue
				}
				files[len(files)-1].content = append(files[len(files)-1].content, b...)
			default:
				restError(w, http.StatusBadRequest, "invalidArgument", "expected unencoded metadata part")
				return
			}
		}
		f.mu.Lock()
		f.uploads = append(f.uploads, files)
		f.mu.Unlock()
		if f.uploadEndEcho != "" {
			restError(w, http.StatusInternalServerError, "internal", "upload refused for Bearer "+f.uploadEndEcho+" and "+f.uploadEndEcho)
			return
		}
		writeJSON(w, map[string]any{"filesWritten": len(files)})
	case "/ep/v1/files/download":
		f.record("/ep" + dcProcDownload)
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		part := func(name, ctype string, content []byte) {
			p, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Disposition": {"attachment; name=" + name}, "Content-Type": {ctype}})
			_, _ = p.Write(content)
		}
		for _, p := range r.URL.Query()["paths"] {
			content, ok := f.files[p]
			if !ok {
				e, _ := json.Marshal(map[string]any{"path": p, "failure": map[string]any{"code": "notFound", "message": "path not found: " + p}})
				part("error", "application/json", e)
				continue
			}
			meta, _ := json.Marshal(map[string]any{"path": p, "mode": 420})
			part("metadata", "application/json", meta)
			part("content", "application/octet-stream", content)
		}
		if !rs.downloadCut {
			_ = mw.Close()
		}
		w.Header().Set("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
		_, _ = w.Write(body.Bytes())
	default:
		http.NotFound(w, r)
	}
}

// ---- REST-only behavior ----

func TestDockerCloudRESTCreateAndCredentials(t *testing.T) {
	f := newDCFakeAPI(t, dcAPIREST)
	d := f.provider()
	f.files = map[string][]byte{"/tmp/plimsoll-project/out.txt": []byte("x")}
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "a.txt", Content: "a"}}, Steps: []string{"true"}, Artifacts: []string{"out.txt"},
	})
	if err != nil || res.Outcome != ProjectOutcomeCompleted || len(res.Artifacts) != 1 {
		t.Fatalf("res = %+v err = %v", res, err)
	}
	body := f.creates[0]["rest"].(map[string]any)
	name := f.creates[0]["name"].(string)
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(name) || f.creates[0]["requestId"] != name {
		t.Fatalf("displayName %q or Idempotency-Key %v does not fit the API", name, f.creates[0]["requestId"])
	}
	argv := f.creates[0]["cloud"].(map[string]any)["startCmd"]
	if fmt.Sprint(argv) != fmt.Sprint([]any{"tail", "-f", "/dev/null"}) {
		t.Fatalf("start argv = %v", argv)
	}
	if _, ok := body["networkPolicies"]; ok {
		t.Fatal("create carries networkPolicies, which the API refuses under the account default")
	}
	if p := body["platform"].(map[string]any); p["os"] != "linux" || p["architecture"] != "amd64" {
		t.Fatalf("platform = %v", p)
	}
	// One credential serves the run's four endpoint calls (mkdir, the upload, the
	// step, the download): the live service rate-limits a mint per call.
	rs := f.restState()
	if rs.minted != 1 || len(rs.used) != 4 || strings.Count(strings.Join(rs.used, ","), "ep-1") != 4 {
		t.Fatalf("minted %d credentials; endpoint calls carried %v; want one credential for all four", rs.minted, rs.used)
	}
}

func TestDockerCloudRESTCredentialRules(t *testing.T) {
	run := func(t *testing.T, tweak func(*dcRESTFake)) (*dcFake, Result, error) {
		f := newDCFakeAPI(t, dcAPIREST)
		tweak(f.restState())
		res, err := f.provider().RunJavaScript(context.Background(), Request{Code: "1"})
		return f, res, err
	}
	t.Run("a rate-limited mint is tried again", func(t *testing.T) {
		if _, _, err := run(t, func(rs *dcRESTFake) { rs.mintLimited = 2 }); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a refused credential is replaced once", func(t *testing.T) {
		f, _, err := run(t, func(rs *dcRESTFake) { rs.refuseOnce = true })
		if err != nil {
			t.Fatal(err)
		}
		if f.restState().minted != 2 {
			t.Fatalf("minted %d, want a second credential after the refusal", f.restState().minted)
		}
	})
	t.Run("an exec cut off by its credential's expiry is never run again", func(t *testing.T) {
		f, _, err := run(t, func(rs *dcRESTFake) { rs.expiredExec = true })
		if err == nil || !dcCodeIs(err, "unauthenticated") {
			t.Fatalf("err = %v, want the expiry as an error", err)
		}
		if len(f.execs) != 1 {
			t.Fatalf("%d execs, want 1: an exec that may have run is not repeated", len(f.execs))
		}
	})
	t.Run("a credential that would expire during a call is not used for it", func(t *testing.T) {
		f, _, err := run(t, func(rs *dcRESTFake) { rs.credLife = 5 * time.Second }) // the run's deadline is 10 s away
		if err != nil {
			t.Fatal(err)
		}
		if f.restState().minted != len(f.restState().used) {
			t.Fatalf("minted %d for %d calls; a short-lived credential was reused", f.restState().minted, len(f.restState().used))
		}
	})
}

func TestDockerCloudRESTWaitsForTheSandboxToRun(t *testing.T) {
	f := newDCFakeAPI(t, dcAPIREST)
	f.opPending = true // 202, still creating; the next read finds it running
	if _, err := f.provider().RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	if f.called(dcProcGetSandbox) == 0 {
		t.Fatal("did not read the sandbox until it ran")
	}
}

func TestDockerCloudRESTDeleteProvesTheSandboxGone(t *testing.T) {
	f := newDCFakeAPI(t, dcAPIREST)
	rs := f.restState()
	rs.staleOnce = true // the first DELETE meets a changed ETag: 412, then a fresh read
	rs.deleteLag = 2    // and the sandbox outlives the accepted delete by two reads
	d := f.provider()
	ctx, gaveUp := WatchTeardown(context.Background())
	if _, err := d.RunJavaScript(ctx, Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	if gaveUp() {
		t.Fatal("charged as a delete that gave up")
	}
	if n := len(f.deletedRefs()); n != 2 || rs.deletes != 1 {
		t.Fatalf("DELETE requests = %d (%d removed it), want 2: a stale ETag, then one that removed it", n, rs.deletes)
	}
	if _, found := f.restStatus(); found {
		t.Fatal("the provider stopped waiting while the sandbox was still deleting")
	}
}

func TestDockerCloudRESTRefusesAnUnusableEndpoint(t *testing.T) {
	for name, tweak := range map[string]func(*dcRESTFake){
		"no exec":     func(rs *dcRESTFake) { rs.endpointCaps = []string{"upload", "download"} },
		"unix socket": func(rs *dcRESTFake) { rs.endpointProto = "unixSocket" },
		"another image": func(rs *dcRESTFake) {
			rs.recordedImage = "registry.example/plimsoll/sandbox@sha256:" + strings.Repeat("b", 64)
		},
		"image not pinned": func(rs *dcRESTFake) { rs.recordedImage = "registry.example/plimsoll/sandbox:latest" },
		"name not kept":    func(rs *dcRESTFake) { rs.displayName = "someone-else" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newDCFakeAPI(t, dcAPIREST)
			tweak(f.restState())
			ran := false
			f.exec = func([]string) (int, string, string) { ran = true; return 0, "", "" }
			if _, err := f.provider().RunJavaScript(context.Background(), Request{Code: "1"}); err == nil || ran {
				t.Fatalf("err = %v, ran = %v; want a refusal before any code", err, ran)
			}
			if len(f.deletedRefs()) != 1 {
				t.Fatal("refused sandbox not deleted")
			}
		})
	}
}

func TestDockerCloudRESTIncompleteExecIsAFlood(t *testing.T) {
	f := newDCFakeAPI(t, dcAPIREST)
	f.restState().incomplete = true
	res, err := f.provider().RunJavaScript(context.Background(), Request{Code: "1"})
	if err != nil || res.ExitCode != exitOutputFlooded || !res.StdoutTruncated {
		t.Fatalf("res = %+v err = %v, want a flooded user run", res, err)
	}
}

func TestDockerCloudRESTDownloadNeedsItsClosingDelimiter(t *testing.T) {
	f := newDCFakeAPI(t, dcAPIREST)
	f.restState().downloadCut = true
	f.files = map[string][]byte{"/tmp/plimsoll-project/out.txt": []byte("x")}
	_, err := f.provider().RunProject(context.Background(), ProjectRequest{
		Files: []File{{Path: "a", Content: "a"}}, Steps: []string{"true"}, Artifacts: []string{"out.txt"},
	})
	if err == nil {
		t.Fatal("a download cut before its closing delimiter was taken as whole")
	}
}

func TestDockerCloudRESTRetriesARateLimitedRead(t *testing.T) {
	f := newDCFakeAPI(t, dcAPIREST)
	f.restState().rateLimitReads = 2
	if _, err := f.provider().RunJavaScript(context.Background(), Request{Code: "1"}); err != nil {
		t.Fatalf("a read answered 429 failed the run: %v", err)
	}
}

func TestDockerCloudRESTGrantsAreRefusedBeforeAnyCall(t *testing.T) {
	f := newDCFakeAPI(t, dcAPIREST)
	d := f.provider()
	grant, _ := dcGrant(t)
	// A guard URL is a configuration REST cannot honor, so it fails startup rather
	// than quietly serving no grants.
	d.GuardURL = "https://guard.example.com/v1/dockercloud/guard"
	if err := d.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "SANDBOX_DOCKERCLOUD_GUARD_URL") {
		t.Fatalf("Preflight with a guard URL on REST: %v", err)
	}
	if d.SupportsJavaScriptGrants() || d.SupportsProjectGrants() {
		t.Fatal("REST advertises grants")
	}
	_, err := d.RunJavaScript(context.Background(), Request{Code: "1", Grant: grant})
	if _, marked := NotDispatchedReason(err); err == nil || !marked {
		t.Fatalf("err = %v, want a refusal marked not dispatched", err)
	}
	d.GuardURL = ""
	_, err = d.RunJavaScript(context.Background(), Request{Code: "1", Grant: grant})
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "REST") {
		t.Fatalf("err = %v, want ErrUnsupported naming the REST API", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("the refusals made API calls: %v", f.calls)
	}
}

func TestDockerCloudRESTErrorCodes(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{409, `{"code":"failedPrecondition","message":"m"}`, "failed_precondition"},
		{404, `{"code":"notFound","message":"Sandbox not found"}`, "not_found"},
		{404, `<html>not here</html>`, "unimplemented"}, // a route not served, never a missing sandbox
		{429, ``, "resource_exhausted"},
		{503, ``, "unavailable"},
		{401, `{"code":"unauthenticated","details":[{"reason":"ENDPOINT_CREDENTIAL_EXPIRED"}]}`, "unauthenticated"},
	} {
		if err := dcRESTErrorFrom("op", tc.status, []byte(tc.body)); !dcCodeIs(err, tc.want) {
			t.Errorf("HTTP %d %s: %v, want %s", tc.status, tc.body, err, tc.want)
		}
	}
}

func TestDockerCloudRefusesAnUnknownAPI(t *testing.T) {
	f := newDCFake(t)
	d := f.provider()
	d.API = "grpc"
	if err := d.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "SANDBOX_DOCKERCLOUD_API") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildDockerCloudREST(t *testing.T) {
	pinned := "registry.example/plimsoll/sandbox@sha256:" + strings.Repeat("b", 64)
	env := map[string]string{
		"SANDBOX_PROVIDER":          "dockercloud",
		"SANDBOX_DOCKERCLOUD_API":   "rest",
		"DOCKER_SBX_TOKEN":          "t",
		"DOCKER_SBX_USERNAME":       "u",
		"SANDBOX_DOCKERCLOUD_IMAGE": pinned,
	}
	p, err := Build(mapEnv(env))
	if err != nil {
		t.Fatalf("REST without an API URL (the documented one is the default): %v", err)
	}
	d := p.Sandbox.(*DockerCloud)
	if d.APIName() != "rest" || d.apiBase() != dcRESTDefaultURL {
		t.Fatalf("api = %s at %s", d.APIName(), d.apiBase())
	}
	// No booted digest on REST, so the pin is not stated as an identity.
	if id := d.Environments().JavaScript.Identity; id != "" {
		t.Fatalf("REST states identity %q", id)
	}
	d.API = dcAPIConnect
	if id := d.Environments().JavaScript.Identity; !strings.HasSuffix(id, strings.Repeat("b", 64)) {
		t.Fatalf("connect identity = %q, want the pinned digest", id)
	}

	// Connect is the default, and Docker documents no URL for it.
	delete(env, "SANDBOX_DOCKERCLOUD_API")
	if _, err := Build(mapEnv(env)); err == nil || !strings.Contains(err.Error(), "SANDBOX_DOCKERCLOUD_API_URL") {
		t.Fatalf("unset API without an API URL: err = %v", err)
	}
	env["SANDBOX_DOCKERCLOUD_API_URL"] = "https://sandboxes.example/sbx"
	if p, err := Build(mapEnv(env)); err != nil || p.Sandbox.(*DockerCloud).APIName() != dcAPIConnect {
		t.Fatalf("unset API: %v, want connect", err)
	}
	delete(env, "SANDBOX_DOCKERCLOUD_API_URL")
	env["SANDBOX_DOCKERCLOUD_API"] = "connect"
	if _, err := Build(mapEnv(env)); err == nil || !strings.Contains(err.Error(), "SANDBOX_DOCKERCLOUD_API_URL") {
		t.Fatalf("connect without an API URL: err = %v", err)
	}
	env["SANDBOX_DOCKERCLOUD_API"] = "graphql"
	if _, err := Build(mapEnv(env)); err == nil || !strings.Contains(err.Error(), "SANDBOX_DOCKERCLOUD_API") {
		t.Fatalf("unknown API: err = %v", err)
	}
}

func TestDockerCloudRESTCapsTheRunCeiling(t *testing.T) {
	f := newDCFakeAPI(t, dcAPIREST)
	d := f.provider()
	d.MaxTimeout = dcRESTMaxRun
	if err := d.Preflight(context.Background()); err != nil {
		t.Fatalf("a %s ceiling refused: %v", dcRESTMaxRun, err)
	}
	d.MaxTimeout = dcRESTMaxRun + time.Second
	if err := d.Preflight(context.Background()); err == nil {
		t.Fatal("a ceiling past what an endpoint credential covers was accepted")
	}
	d.API = dcAPIConnect
	if err := d.Preflight(context.Background()); err != nil {
		t.Fatalf("connect has no such cap: %v", err)
	}
}
