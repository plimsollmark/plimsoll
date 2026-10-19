package agentsandbox

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/agentsandbox/processv1"
	"github.com/plimsollmark/plimsoll/gen/go/agentsandbox/processv1/processv1connect"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

const (
	fakeToken  = "a-sandboxd-token-of-at-least-32-characters"
	fakeImage  = "plimsoll/sandbox-agentsandbox@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	fakePodIP  = "10.244.0.10"
	fakeHash   = "29c99b14"
	fakeTmpl   = "plimsoll-run"
	fakeAPIKey = "api-token"
	fakeNode   = "node-1"
	// fakeBoot is the boot ID every fake guest reports, fakeNodeBoot its node's.
	fakeBoot     = "8d3ee747-814b-4758-9f9f-9a4511c052d9"
	fakeNodeBoot = "0f7463ef-d5fc-4a93-9ac0-3056015fe7d3"
)

// fakeAPI is the slice of the Kubernetes API the provider uses, in memory: a warm pool,
// its template, a runtime class, and claims that become ready at once with a sandbox and a
// pod made from the template. Hooks change what the claimed pod or the policies look like.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu             sync.Mutex
	n              int
	claims         map[string]*claim
	created        []claim // every claim as posted
	deleted        []string
	deleteRequests []string
	deleteMode     string // "reject" fails DELETE; "pending" accepts but never removes
	handler        string
	policies       []networkPolicy
	// nodeBoot is the boot ID fakeNode reports; nodeReads counts the node's reads.
	nodeBoot  string
	nodeReads int
	// podHook edits each claimed pod before it is served; tmplHook the template.
	podHook  func(*pod)
	tmplHook func(*podSpec)
	// JSON hooks inject fields the typed read-back must not silently discard.
	podJSONHook      func(map[string]any)
	tmplJSONHook     func(map[string]any)
	policiesJSONHook func(map[string]any)
	// createdAt, when set, is the creation time the server stamps (clock skew).
	createdAt func() time.Time
	// neverReady keeps every claim unready.
	neverReady bool
}

func goodSpec(digest string) podSpec {
	rc, f, tr := "gvisor", false, true
	return podSpec{
		RuntimeClassName: &rc, AutomountServiceAccountToken: &f, DNSPolicy: "None",
		DNSConfig: &dnsConfig{Nameservers: []string{fixedNameserver}},
		Containers: []container{{
			Name: "sandboxd", Image: fakeImage,
			Command: []string{"/usr/local/bin/sandboxd", "--root-dir=/work", "--grpc-port=9090", "--auth-token-sha256=" + digest},
			SecurityContext: &securityContext{AllowPrivilegeEscalation: &f, ReadOnlyRootFilesystem: &tr, Capabilities: &struct {
				Add  []string `json:"add,omitempty"`
				Drop []string `json:"drop,omitempty"`
			}{Add: []string{"SETUID", "SETGID"}, Drop: []string{"ALL"}}},
			VolumeMounts:           []volumeMount{{Name: "work", MountPath: "/work"}},
			TerminationMessagePath: "/root/termination-log",
			Resources: struct {
				Limits   map[string]string `json:"limits,omitempty"`
				Requests map[string]string `json:"requests,omitempty"`
			}{Limits: map[string]string{"memory": "256Mi", "cpu": "1"}},
		}},
		Volumes: []volume{{"name": json.RawMessage(`"work"`), "emptyDir": json.RawMessage(`{"medium":"Memory","sizeLimit":"128Mi"}`)}},
	}
}

// templatePolicy is what the template controller makes from a template whose policy
// admits plimsoll on 9090 and names no egress rule.
func templatePolicy() networkPolicy {
	var np networkPolicy
	np.Meta.Name = fakeTmpl + "-network-policy"
	np.Meta.UID = "network-policy-uid"
	np.Spec.PodSelector.MatchLabels = map[string]string{"agents.x-k8s.io/sandbox-template-ref-hash": fakeHash}
	np.Spec.PolicyTypes = []string{"Ingress", "Egress"}
	np.Spec.Ingress = []ingressRule{{From: []json.RawMessage{json.RawMessage(`{"ipBlock":{"cidr":"172.24.0.0/16"}}`)}}}
	np.Spec.Ingress[0].Ports = append(np.Spec.Ingress[0].Ports, struct {
		Protocol string          `json:"protocol,omitempty"`
		Port     json.RawMessage `json:"port,omitempty"`
		EndPort  *int            `json:"endPort,omitempty"`
	}{Protocol: "TCP", Port: json.RawMessage(`9090`)})
	return np
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, claims: map[string]*claim{}, handler: "runsc", policies: []networkPolicy{templatePolicy()}, nodeBoot: fakeNodeBoot}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeAPI) writeSpec(w http.ResponseWriter, v any, hook func(map[string]any), template bool) {
	f.writeObject(w, v, func(obj map[string]any) {
		if hook == nil {
			return
		}
		spec := obj["spec"].(map[string]any)
		if template {
			spec = spec["podTemplate"].(map[string]any)["spec"].(map[string]any)
		}
		hook(spec)
	})
}

func (f *fakeAPI) writeObject(w http.ResponseWriter, v any, hook func(map[string]any)) {
	if hook == nil {
		f.write(w, v)
		return
	}
	raw, err := json.Marshal(v)
	if err != nil {
		f.t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		f.t.Fatal(err)
	}
	hook(obj)
	f.write(w, obj)
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"kind":"Status","reason":"NotFound","message":"not found"}`))
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+fakeAPIKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ns := "/namespaces/default/"
	path := r.URL.Path
	switch {
	case path == extensionsAPI+ns+"sandboxwarmpools/pool":
		var wp warmPool
		wp.Spec.SandboxTemplateRef.Name = fakeTmpl
		f.write(w, wp)
	case path == extensionsAPI+ns+"sandboxtemplates/"+fakeTmpl:
		var t template
		t.Spec.PodTemplate.Spec = goodSpec(digestOf(fakeToken))
		if f.tmplHook != nil {
			f.tmplHook(&t.Spec.PodTemplate.Spec)
		}
		f.writeSpec(w, t, f.tmplJSONHook, true)
	case path == runtimeClassPath("gvisor"):
		f.write(w, runtimeClass{Handler: f.handler})
	case path == nodePath(fakeNode):
		f.nodeReads++
		var n node
		n.Meta.Name = fakeNode
		n.Status.NodeInfo.BootID = f.nodeBoot
		f.write(w, n)
	case strings.HasPrefix(path, "/api/v1/nodes/"):
		notFound(w)
	case path == networkPoliciesPath("default"):
		f.writeObject(w, networkPolicyList{Items: f.policies}, f.policiesJSONHook)
	case path == claimsPath("default") && r.Method == http.MethodPost:
		var c claim
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.created = append(f.created, c)
		f.n++
		c.Meta.UID = fmt.Sprintf("claim-uid-%d", f.n)
		now := time.Now().Truncate(time.Second)
		if f.createdAt != nil {
			now = f.createdAt()
		}
		c.Meta.CreationTimestamp = &now
		f.claims[c.Meta.Name] = &c
		f.write(w, c)
	case path == claimsPath("default") && r.Method == http.MethodGet:
		var l claimList
		for _, c := range f.claims {
			l.Items = append(l.Items, *c)
		}
		f.write(w, l)
	case strings.HasPrefix(path, claimsPath("default")+"/"):
		name := strings.TrimPrefix(path, claimsPath("default")+"/")
		c, ok := f.claims[name]
		if !ok {
			notFound(w)
			return
		}
		if r.Method == http.MethodDelete {
			f.deleteRequests = append(f.deleteRequests, name)
			if f.deleteMode == "reject" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if f.deleteMode == "pending" {
				now := time.Now()
				c.Meta.DeletionTimestamp = &now
				f.write(w, c)
				return
			}
			delete(f.claims, name)
			f.deleted = append(f.deleted, name)
			f.write(w, map[string]string{"kind": "Status"})
			return
		}
		out := *c
		if !f.neverReady {
			out.Status.Conditions = []condition{{Type: "Ready", Status: "True"}}
			out.Status.Sandbox.Name = "sb-" + name
			out.Status.Sandbox.PodIPs = []string{fakePodIP}
		}
		f.write(w, out)
	case strings.HasPrefix(path, agentsAPI+ns+"sandboxes/sb-"):
		name := strings.TrimPrefix(path, agentsAPI+ns+"sandboxes/sb-")
		c, ok := f.claims[name]
		if !ok {
			notFound(w)
			return
		}
		var sb sandboxObject
		ctl := true
		sb.Meta = objectMeta{Name: "sb-" + name, UID: "sandbox-uid-" + name, Annotations: map[string]string{"agents.x-k8s.io/sandbox-template-ref": fakeTmpl},
			OwnerReferences: []ownerReference{{Kind: "SandboxClaim", Name: name, UID: c.Meta.UID, Controller: &ctl}}}
		f.write(w, sb)
	case strings.HasPrefix(path, "/api/v1"+ns+"pods/sb-"):
		name := strings.TrimPrefix(path, "/api/v1"+ns+"pods/sb-")
		if _, ok := f.claims[name]; !ok {
			notFound(w)
			return
		}
		ctl := true
		pd := pod{Meta: objectMeta{Name: "sb-" + name, Labels: map[string]string{"agents.x-k8s.io/sandbox-template-ref-hash": fakeHash},
			OwnerReferences: []ownerReference{{Kind: "Sandbox", Name: "sb-" + name, UID: "sandbox-uid-" + name, Controller: &ctl}}},
			Spec: goodSpec(digestOf(fakeToken))}
		pd.Spec.NodeName = fakeNode
		pd.Status.Phase, pd.Status.PodIP = "Running", fakePodIP
		pd.Status.ContainerStatuses = append(pd.Status.ContainerStatuses, struct {
			Name    string `json:"name"`
			ImageID string `json:"imageID"`
			Ready   bool   `json:"ready"`
		}{Name: "sandboxd", ImageID: "docker.io/plimsoll/sandbox-agentsandbox@sha256:" + strings.Repeat("1", 64), Ready: true})
		if f.podHook != nil {
			f.podHook(&pd)
		}
		f.writeSpec(w, pd, f.podJSONHook, false)
	default:
		f.t.Errorf("unexpected API call %s %s", r.Method, path)
		notFound(w)
	}
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fakeSandboxd is a process service that runs nothing: each Start is answered by run,
// given the command and its stdin once the client has closed it.
type fakeSandboxd struct {
	processv1connect.UnimplementedProcessServiceHandler
	t   *testing.T
	srv *httptest.Server

	mu     sync.Mutex
	starts [][]string
	auth   []string
	// timeouts holds each call's Grpc-Timeout header, Start and WriteStdin alike.
	timeouts []string
	stdin    map[int32]chan []byte
	bufs     map[int32][]byte
	next     int32
	// run answers a command; hang, when set, makes Start wait for its stream to end.
	run  func(argv []string, stdin []byte) (stdout, stderr string, exit int32)
	hang bool
	// tierAnswer is the answer to tierCheck, which is counted in tierChecks, not starts:
	// gVisor's boot line and a seccomp filter unless a test sets another.
	tierAnswer  string
	mountAnswer string
	mountReport func() string
	tierChecks  int
	// cancelled is closed when a hanging Start sees its stream end.
	cancelled chan struct{}
}

func newFakeSandboxd(t *testing.T) *fakeSandboxd {
	f := &fakeSandboxd{t: t, stdin: map[int32]chan []byte{}, bufs: map[int32][]byte{}, cancelled: make(chan struct{}),
		mountAnswer: strings.Join(kataMounts, "\n") + "\n",
		tierAnswer:  "kernel [   0.000000] Starting gVisor...\nboot " + fakeBoot + "\nSeccomp:\t2\n"}
	mux := http.NewServeMux()
	mux.Handle(processv1connect.NewProcessServiceHandler(f))
	f.srv = httptest.NewUnstartedServer(mux)
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	f.srv.Config.Protocols = protocols
	f.srv.Start()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSandboxd) client(string) processv1connect.ProcessServiceClient {
	return processv1connect.NewProcessServiceClient(h2cClient(), f.srv.URL, connect.WithGRPC(),
		connect.WithInterceptors(bearer(fakeToken)))
}

func (f *fakeSandboxd) Start(ctx context.Context, req *connect.Request[processv1.StartRequest], stream *connect.ServerStream[processv1.StartResponse]) error {
	f.mu.Lock()
	checking := slices.Equal(req.Msg.GetConfig().GetCommand(), tierCheck)
	if checking {
		f.tierChecks++
	} else {
		f.starts = append(f.starts, req.Msg.GetConfig().GetCommand())
	}
	f.auth = append(f.auth, req.Header().Get("Authorization"))
	f.timeouts = append(f.timeouts, req.Header().Get("Grpc-Timeout"))
	f.next++
	pid := f.next
	in := make(chan []byte, 1)
	f.stdin[pid] = in
	f.mu.Unlock()
	if err := stream.Send(&processv1.StartResponse{Event: &processv1.StartResponse_Init{Init: &processv1.InitEvent{ProcessId: pid}}}); err != nil {
		return err
	}
	if f.hang && !checking {
		<-ctx.Done()
		close(f.cancelled)
		return ctx.Err()
	}
	var stdin []byte
	select {
	case stdin = <-in:
	case <-ctx.Done():
		return ctx.Err()
	}
	var out, errOut string
	var exit int32
	if checking {
		f.mu.Lock()
		mounts := f.mountAnswer
		if f.mountReport != nil {
			mounts = f.mountReport()
		}
		out = f.tierAnswer + "mounts\n" + mounts
		f.mu.Unlock()
	} else {
		out, errOut, exit = f.run(req.Msg.GetConfig().GetCommand(), stdin)
	}
	for _, ev := range []*processv1.StartResponse{
		{Event: &processv1.StartResponse_Stdout{Stdout: []byte(out)}},
		{Event: &processv1.StartResponse_Stderr{Stderr: []byte(errOut)}},
		{Event: &processv1.StartResponse_Exit{Exit: &processv1.ExitEvent{ExitCode: exit}}},
	} {
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeSandboxd) WriteStdin(_ context.Context, req *connect.Request[processv1.WriteStdinRequest]) (*connect.Response[processv1.WriteStdinResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.timeouts = append(f.timeouts, req.Header().Get("Grpc-Timeout"))
	pid := req.Msg.GetProcessId()
	in, ok := f.stdin[pid]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no process %d", pid))
	}
	if data := req.Msg.GetInput(); data != nil {
		f.bufs[pid] = append(f.bufs[pid], data...)
	} else {
		in <- f.bufs[pid]
	}
	return connect.NewResponse(&processv1.WriteStdinResponse{}), nil
}

// runnerReport answers a runner command the way /runner.mjs does: it reads the plan and
// signs a report of one passing step per plan step, each printing its command.
func runnerReport(t *testing.T, stdin []byte) string {
	t.Helper()
	var plan struct {
		Steps     []string `json:"steps"`
		ReportKey string   `json:"reportKey"`
	}
	if err := json.Unmarshal(stdin, &plan); err != nil {
		t.Fatalf("plan: %v", err)
	}
	key, err := hex.DecodeString(plan.ReportKey)
	if err != nil || len(key) != runnerwire.KeySize {
		t.Fatalf("report key %q", plan.ReportKey)
	}
	type step struct {
		Command string `json:"command"`
		Stdout  []byte `json:"stdoutBase64"`
		Stderr  []byte `json:"stderrBase64"`
	}
	var steps []step
	for _, s := range plan.Steps {
		steps = append(steps, step{Command: s, Stdout: []byte("ran " + s)})
	}
	body, _ := json.Marshal(map[string]any{"steps": steps, "artifacts": []any{}})
	h := hmac.New(sha256.New, key)
	h.Write(body)
	return fmt.Sprintf("\n%s %d %x\n%s", runnerwire.Marker, len(body), h.Sum(nil), body)
}

// testProvider is a provider over a fake API and a fake sandboxd.
func testProvider(t *testing.T) (*Provider, *fakeAPI, *fakeSandboxd) {
	t.Helper()
	api, sd := newFakeAPI(t), newFakeSandboxd(t)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte(fakeAPIKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{APIServer: api.srv.URL, CAFile: ca, TokenFile: tok, Namespace: "default", WarmPool: "pool",
		RuntimeClass: "gvisor", Image: fakeImage, RequirePinnedImage: true, SandboxdToken: fakeToken})
	if err != nil {
		t.Fatal(err)
	}
	p.dialProcess = sd.client
	p.pf.TTL = 0
	sd.run = func(argv []string, stdin []byte) (string, string, int32) {
		if strings.Contains(strings.Join(argv, " "), runnerPath) {
			return runnerReport(t, stdin), "", 0
		}
		return "out:" + string(stdin), "", 0
	}
	return p, api, sd
}

// drained waits for the provider's deletes.
func drained(t *testing.T, p *Provider) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Drain(ctx); err != nil {
		t.Fatal(err)
	}
}

// refusal is the not-dispatched reason err carries, or "" when it carries none.
func refusal(err error) sandbox.Refusal {
	r, _ := sandbox.NotDispatchedReason(err)
	return r
}

// Both a template and an admission-mutated pod must cross the same closed schema.
func TestPodFieldsAndRootHandlersAreRefused(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{"unknown pod field", func(s map[string]any) { s["futurePodField"] = true }, `unknown field "futurePodField"`},
		{"unknown container field", func(s map[string]any) { jsonContainer(s)["futureContainerField"] = true }, `unknown field "futureContainerField"`},
		{"container environment", func(s map[string]any) {
			jsonContainer(s)["env"] = []any{map[string]any{"name": "NODE_OPTIONS", "value": "--require=/work/hook.js"}}
		}, `unknown field "env"`},
		{"unknown security field", func(s map[string]any) {
			jsonContainer(s)["securityContext"].(map[string]any)["futureSecurityField"] = true
		}, `unknown field "futureSecurityField"`},
		{"unknown mount field", func(s map[string]any) {
			jsonContainer(s)["volumeMounts"].([]any)[0].(map[string]any)["subPathExpr"] = "work"
		}, `unknown field "subPathExpr"`},
		{"host port", func(s map[string]any) {
			jsonContainer(s)["ports"] = []any{map[string]any{"containerPort": 9090, "hostPort": 9090}}
		}, "host port"},
	}
	for _, name := range []string{"readinessProbe", "livenessProbe", "startupProbe"} {
		cases = append(cases, struct {
			name string
			edit func(map[string]any)
			want string
		}{name + " exec", func(s map[string]any) {
			jsonContainer(s)[name] = map[string]any{"exec": map[string]any{"command": []string{"/work/hook"}}}
		}, "exec handler"})
	}
	for _, name := range []string{"postStart", "preStop"} {
		cases = append(cases, struct {
			name string
			edit func(map[string]any)
			want string
		}{name + " exec", func(s map[string]any) {
			jsonContainer(s)["lifecycle"] = map[string]any{name: map[string]any{"exec": map[string]any{"command": []string{"/work/hook"}}}}
		}, "exec handler"})
	}
	cases = append(cases, struct {
		name string
		edit func(map[string]any)
		want string
	}{"exec alongside TCP", func(s map[string]any) {
		jsonContainer(s)["readinessProbe"] = map[string]any{"exec": nil, "tcpSocket": map[string]any{"port": 9090}}
	}, "exec handler"})
	for _, tc := range cases {
		for _, template := range []bool{true, false} {
			where := "pod"
			if template {
				where = "template"
			}
			t.Run(where+"/"+tc.name, func(t *testing.T) {
				p, api, sd := testProvider(t)
				if template {
					api.tmplJSONHook = tc.edit
				} else {
					api.podJSONHook = tc.edit
				}
				_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
				if refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want environment refusal containing %q", err, tc.want)
				}
				drained(t, p)
				sd.mu.Lock()
				defer sd.mu.Unlock()
				if len(sd.starts) != 0 || sd.tierChecks != 0 {
					t.Fatal("sent a command to a refused pod")
				}
			})
		}
	}
}

func jsonContainer(s map[string]any) map[string]any {
	return s["containers"].([]any)[0].(map[string]any)
}

// Measured pod defaults and RuntimeClass admission fields, including AKS accounting and
// placement, must survive strict decoding. Network probes never execute a guest file.
func TestPodDefaultsAndNetworkProbesAreAccepted(t *testing.T) {
	for _, action := range []string{"tcpSocket", "httpGet", "grpc"} {
		t.Run(action, func(t *testing.T) {
			p, api, _ := testProvider(t)
			defaults := func(s map[string]any) {
				for k, v := range map[string]any{
					"nodeName": fakeNode, "schedulerName": "default-scheduler", "priority": 0, "preemptionPolicy": "PreemptLowerPriority",
					"serviceAccount": "default", "serviceAccountName": "default", "restartPolicy": "Always", "terminationGracePeriodSeconds": 30,
					"enableServiceLinks": false, "nodeSelector": map[string]string{"runtime": "kata"}, "overhead": map[string]string{"memory": "600Mi", "cpu": "250m"},
					"tolerations": []any{map[string]any{"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 300}},
				} {
					s[k] = v
				}
				c := jsonContainer(s)
				c["imagePullPolicy"] = "Never"
				c["terminationMessagePolicy"] = "File"
				c["ports"] = []any{map[string]any{"containerPort": 9090, "protocol": "TCP"}}
				c["resources"].(map[string]any)["requests"] = map[string]string{"memory": "256Mi", "cpu": "1"}
				sc := c["securityContext"].(map[string]any)
				sc["runAsUser"] = 0
				sc["runAsGroup"] = 0
				for _, name := range []string{"readinessProbe", "livenessProbe", "startupProbe"} {
					c[name] = map[string]any{action: map[string]any{"port": 9090}, "failureThreshold": 3, "periodSeconds": 2, "successThreshold": 1, "timeoutSeconds": 1}
				}
				c["lifecycle"] = map[string]any{"postStart": map[string]any{"httpGet": map[string]any{"port": 8080, "path": "/ready", "scheme": "HTTP"}}, "preStop": map[string]any{"tcpSocket": map[string]any{"port": 9090}}}
			}
			api.tmplJSONHook, api.podJSONHook = defaults, defaults
			if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
				t.Fatal(err)
			}
			drained(t, p)
		})
	}
}

// fakeSmoke answers both smoke-test commands. It reports exactly the template's writable
// roots so a test can change the kernel's mount table independently of the API's paths.
func fakeSmoke(t *testing.T, p *Provider, sd *fakeSandboxd, edit func(*boundaryReport)) {
	t.Helper()
	sd.mountReport = func() string {
		roots, err := p.writableRoots()
		if err != nil {
			t.Error(err)
			return ""
		}
		escape := strings.NewReplacer(`\`, `\134`, " ", `\040`, "\t", `\011`, "\n", `\012`)
		out := "none / overlay ro 0 0\n"
		for _, root := range roots {
			out += "tmpfs " + escape.Replace(root) + " tmpfs rw 0 0\n"
		}
		return out
	}
	sd.run = func(argv []string, stdin []byte) (string, string, int32) {
		if strings.Contains(strings.Join(argv, " "), runnerPath) {
			return runnerReport(t, stdin), "", 0
		}
		ids := strings.Repeat("61000\t", 3) + "61000"
		r := boundaryReport{Node: "v22.0.0", UID: ids, GID: ids, CapEff: "0000000000000000", CapPrm: "0000000000000000", NoNewPrivs: "1", Seccomp: "2",
			Env: []string{"HOME", "PATH"}, Resolv: "nameserver 127.0.0.1\n", Swept: 1000, Gateway: "10.0.0.1", Egress: map[string]string{"tcp 10.0.0.1:10250": "timeout"},
			Dmesg: "[   0.000000] Starting gVisor...", Mounts: []string{"none / overlay ro 0 0", "shm /dev/shm tmpfs rw 0 0"},
		}
		if p.IsolationClass() == sandbox.IsolationVM {
			r.Dmesg = kataBoot
			r.Seccomp = "0"
		}
		r.Fill = map[string]struct {
			Wrote int64  `json:"wrote"`
			Code  string `json:"code"`
		}{}
		escape := strings.NewReplacer(`\`, `\134`, " ", `\040`, "\t", `\011`, "\n", `\012`)
		for m, size := range p.mounts() {
			r.Mounts = append(r.Mounts, "tmpfs "+escape.Replace(m)+" tmpfs rw 0 0")
			r.Writable = append(r.Writable, m)
			r.Fill[m] = struct {
				Wrote int64  `json:"wrote"`
				Code  string `json:"code"`
			}{size, "ENOSPC"}
		}
		if edit != nil {
			edit(&r)
		}
		out, err := json.Marshal(r)
		if err != nil {
			t.Error(err)
			return "", "", 1
		}
		return string(out), "", 0
	}
}

// /var/run can link to /run in the image: the API's text check accepts the termination
// path, but the guest sees its node-backed file under /run, a declared tmpfs root.
func TestSmokeRefusesMountsBeneathWritableRoots(t *testing.T) {
	for _, tier := range []string{"runsc", "runc", "kata-clh-runtime-rs"} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%t", tier, nested), func(t *testing.T) {
				p, api, sd := testProvider(t)
				api.handler = tier
				if tier == "kata-clh-runtime-rs" {
					sd.tierAnswer = kataAnswer
				}
				spec := func(s *podSpec) {
					s.Volumes = append(s.Volumes, volume{"name": json.RawMessage(`"run"`), "emptyDir": json.RawMessage(`{"medium":"Memory","sizeLimit":"32Mi"}`)})
					s.Containers[0].VolumeMounts = append(s.Containers[0].VolumeMounts, volumeMount{Name: "run", MountPath: "/run"})
					s.Containers[0].TerminationMessagePath = "/var/run/termination-log"
					if tier == "runc" {
						s.Containers[0].SecurityContext.SeccompProfile = &seccompProfile{Type: "RuntimeDefault"}
					}
				}
				api.tmplHook = spec
				api.podHook = func(pd *pod) { spec(&pd.Spec) }
				fakeSmoke(t, p, sd, func(r *boundaryReport) {
					// A sibling whose name merely shares a prefix is safe.
					r.Mounts = append(r.Mounts, "none /runtime/log ext4 rw 0 0")
					if nested {
						r.Mounts = append(r.Mounts, "/dev/node-disk /run/termination-log ext4 rw 0 0")
						r.Files = append(r.Files, "/run/termination-log")
					}
				})
				err := p.SmokeTest(context.Background())
				if nested {
					if err == nil || !strings.Contains(err.Error(), "mount point /run/termination-log is beneath writable root /run") {
						t.Fatalf("got %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				drained(t, p)
			})
		}
	}
	for _, tc := range []struct {
		mount string
		roots []string
		fail  bool
	}{
		{`tmpfs /run\040data/file tmpfs ro 0 0`, []string{"/run data"}, true},
		{`tmpfs /run\011data/file tmpfs ro 0 0`, []string{"/run\tdata"}, true},
		{`tmpfs /run\134data/file tmpfs ro 0 0`, []string{`/run\data`}, true},
		{`tmpfs /run tmpfs rw 0 0`, []string{"/run"}, false},
		{`unreadable: EACCES`, []string{"/run"}, true},
	} {
		if err := checkNestedMounts([]string{tc.mount}, tc.roots); (err != nil) != tc.fail {
			t.Errorf("%q: %v", tc.mount, err)
		}
	}
	if err := checkNestedMounts(nil, []string{"/run"}); err == nil {
		t.Fatal("missing mount table accepted")
	}
}

// A failed DELETE and an accepted foreground deletion that never completes must retain
// both ownership and the admission reservation until a later read confirms absence.
func TestPendingClaimDeletionHoldsCapacityUntilConfirmedGone(t *testing.T) {
	for _, mode := range []string{"reject", "pending", "gone before reconciliation"} {
		t.Run(mode, func(t *testing.T) {
			p, api, _ := testProvider(t)
			p.deleteTimeout = 40 * time.Millisecond
			api.deleteMode = mode
			if mode == "gone before reconciliation" {
				api.deleteMode = "pending"
			}
			released := make(chan struct{})
			ctx, returned := sandbox.WithCapacity(context.Background(), func() { close(released) })
			if _, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"}); err != nil {
				t.Fatal(err)
			}
			returned()
			names := p.leases.Keys()
			if len(names) != 1 {
				t.Fatalf("tracked claims: %v", names)
			}
			name := names[0]
			waitPendingDelete(t, p, name)
			assertHeld := func() {
				t.Helper()
				if !p.leases.Tracked(name) {
					t.Fatal("failed delete lost its lease")
				}
				select {
				case <-released:
					t.Fatal("failed delete gave back capacity")
				default:
				}
			}
			assertHeld()
			dctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			err := p.Drain(dctx)
			cancel()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("drain hid claim %s: %v", name, err)
			}
			api.mu.Lock()
			timestamp := api.claims[name].Meta.DeletionTimestamp
			api.mu.Unlock()
			if (timestamp != nil) != (mode != "reject") {
				t.Fatalf("mode %s: deletion timestamp %v", mode, timestamp)
			}
			if n, err := p.ReconcileOrphans(context.Background()); err == nil || n != 0 {
				t.Fatalf("still pending: %d, %v", n, err)
			}
			assertHeld()
			api.mu.Lock()
			api.deleteMode = ""
			if mode == "gone before reconciliation" {
				delete(api.claims, name)
			}
			api.mu.Unlock()
			if n, err := p.ReconcileOrphans(context.Background()); err != nil || n != 1 {
				t.Fatalf("recovered: %d, %v", n, err)
			}
			drained(t, p)
			select {
			case <-released:
			default:
				t.Fatal("confirmed deletion retained capacity")
			}
			if n, err := p.ReconcileOrphans(context.Background()); err != nil || n != 0 {
				t.Fatalf("second reconciliation: %d, %v", n, err)
			}
		})
	}
}

func waitPendingDelete(t *testing.T, p *Provider, name string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.cleanup.mu.Lock()
		d := p.cleanup.pending[name]
		pending := d != nil && !d.running
		p.cleanup.mu.Unlock()
		if pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("claim %s did not become pending", name)
}

func TestReconcileDoesNotTakeOverAClaimInUse(t *testing.T) {
	p, api, _ := testProvider(t)
	if err := p.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := p.claimSandbox(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := p.ReconcileOrphans(context.Background()); err != nil || n != 0 {
		t.Fatalf("active claim: %d, %v", n, err)
	}
	api.mu.Lock()
	requests := len(api.deleteRequests)
	api.mu.Unlock()
	if requests != 0 {
		t.Fatal("reconciler deleted a live run's claim")
	}
	p.deleteLater(context.Background(), b)
	drained(t, p)
}

func TestOnlyTheProvenNetworkPolicySetRuns(t *testing.T) {
	cases := []struct {
		name   string
		change func(*fakeAPI)
	}{
		{"added", func(f *fakeAPI) {
			np := templatePolicy()
			np.Meta.Name = "new-policy"
			np.Meta.UID = "new-policy-uid"
			np.Spec.PodSelector.MatchLabels = map[string]string{"app": "unrelated"}
			f.policies = append(f.policies, np)
		}},
		{"removed", func(f *fakeAPI) { f.policies = nil }},
		{"replaced with identical spec", func(f *fakeAPI) { f.policies[0].Meta.UID = "replacement-uid" }},
		{"spec changed", func(f *fakeAPI) {
			f.policies[0].Spec.Ingress[0].From = []json.RawMessage{json.RawMessage(`{"ipBlock":{"cidr":"192.0.2.0/24"}}`)}
		}},
		{"unknown spec field changed", func(f *fakeAPI) {
			f.policiesJSONHook = func(o map[string]any) {
				o["items"].([]any)[0].(map[string]any)["spec"].(map[string]any)["futurePolicyField"] = true
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, api, sd := testProvider(t)
			fakeSmoke(t, p, sd, nil)
			if err := p.SmokeTest(context.Background()); err != nil {
				t.Fatal(err)
			}
			drained(t, p)
			sd.mu.Lock()
			before := len(sd.starts)
			checks := sd.tierChecks
			sd.mu.Unlock()
			api.mu.Lock()
			original, marshalErr := json.Marshal(api.policies)
			tc.change(api)
			api.mu.Unlock()
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			if refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "network policy set changed") {
				t.Fatalf("run after %s: %v", tc.name, err)
			}
			drained(t, p)
			sd.mu.Lock()
			after := len(sd.starts)
			afterChecks := sd.tierChecks
			sd.mu.Unlock()
			if after != before || afterChecks != checks {
				t.Fatal("sent code after a policy change")
			}
			// Repeating the smoke test on this provider cannot silently approve changed policies.
			if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), "network policy set changed") {
				t.Fatalf("smoke repinned policies: %v", err)
			}
			api.mu.Lock()
			restoreErr := json.Unmarshal(original, &api.policies)
			api.policiesJSONHook = nil
			api.mu.Unlock()
			if restoreErr != nil {
				t.Fatal(restoreErr)
			}
			_, err = p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			if refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), "network policy set changed") {
				t.Fatalf("restoring the old policies cleared the refusal: %v", err)
			}
			drained(t, p)
		})
	}
}

func TestPolicyMetadataAndListOrderDoNotChangeThePin(t *testing.T) {
	p, api, sd := testProvider(t)
	other := templatePolicy()
	other.Meta.Name = "unrelated"
	other.Meta.UID = "unrelated-uid"
	other.Spec.PodSelector.MatchLabels = map[string]string{"app": "other"}
	api.policies = append(api.policies, other)
	fakeSmoke(t, p, sd, nil)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	drained(t, p)
	api.mu.Lock()
	slices.Reverse(api.policies)
	api.policiesJSONHook = func(o map[string]any) {
		for _, item := range o["items"].([]any) {
			m := item.(map[string]any)["metadata"].(map[string]any)
			m["resourceVersion"] = "new-version"
			m["annotations"] = map[string]string{"operator-note": "updated"}
		}
	}
	api.mu.Unlock()
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	drained(t, p)
}

// The candidate set is fixed before the boundary test, checked in both claimed pods,
// and checked after the runner test. None of those gaps can silently pin another set.
func TestPoliciesCannotChangeWhileTheSmokeTestProvesThem(t *testing.T) {
	for _, duringRunner := range []bool{false, true} {
		t.Run(fmt.Sprintf("during runner=%t", duringRunner), func(t *testing.T) {
			p, api, sd := testProvider(t)
			fakeSmoke(t, p, sd, nil)
			answer := sd.run
			sd.run = func(argv []string, stdin []byte) (string, string, int32) {
				out, stderr, exit := answer(argv, stdin)
				runner := strings.Contains(strings.Join(argv, " "), runnerPath)
				if runner == duringRunner {
					api.mu.Lock()
					api.policies[0].Meta.UID = "recreated-during-smoke"
					api.mu.Unlock()
				}
				return out, stderr, exit
			}
			if err := p.SmokeTest(context.Background()); err == nil || !strings.Contains(err.Error(), "network policy set changed") {
				t.Fatalf("changed during smoke: %v", err)
			}
			drained(t, p)
			p.mu.Lock()
			proven := p.proven
			p.mu.Unlock()
			if proven != "" {
				t.Fatal("recorded a successful smoke proof across a policy change")
			}
		})
	}
}
