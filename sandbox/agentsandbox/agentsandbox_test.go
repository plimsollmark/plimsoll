package agentsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

func TestConfigRefuses(t *testing.T) {
	good := Config{APIServer: "https://k8s.example:6443", CAFile: "ca", TokenFile: "tok", Namespace: "default", WarmPool: "pool",
		RuntimeClass: "gvisor", Image: fakeImage, RequirePinnedImage: true, SandboxdToken: fakeToken}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Config){
		"cleartext API":       func(c *Config) { c.APIServer = "http://k8s.example" },
		"API with a path":     func(c *Config) { c.APIServer = "https://k8s.example/x" },
		"API with userinfo":   func(c *Config) { c.APIServer = "https://u:p@k8s.example" },
		"no CA":               func(c *Config) { c.CAFile = "" },
		"bad namespace":       func(c *Config) { c.Namespace = "Default" },
		"path in a pool name": func(c *Config) { c.WarmPool = "../pool" },
		"unpinned image":      func(c *Config) { c.Image = "plimsoll/sandbox-agentsandbox:dev" },
		"short token":         func(c *Config) { c.SandboxdToken = "short" },
		"token with a space":  func(c *Config) { c.SandboxdToken = strings.Repeat("a", 20) + " " + strings.Repeat("b", 20) },
		"bad port":            func(c *Config) { c.SandboxdPort = 70000 },
	} {
		c := good
		edit(&c)
		if c.validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A snippet and a project each claim a sandbox, run as the guest through sandboxd with
// plimsoll's token, and delete their claim after.
func TestRunsClaimRunAndDelete(t *testing.T) {
	p, api, sd := testProvider(t)
	ctx := context.Background()
	if err := p.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	if p.IsolationClass() != sandbox.IsolationKernel {
		t.Fatalf("tier %s", p.IsolationClass())
	}
	res, err := p.RunJavaScript(ctx, sandbox.Request{Code: "console.log(1)", MinimumIsolation: sandbox.IsolationKernel})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "out:console.log(1)" || res.ExitCode != 0 || res.Isolation != sandbox.IsolationKernel {
		t.Fatalf("snippet %+v", res)
	}
	// Every result names the pod that ran it, from the provider's own read of the pod.
	if !strings.HasPrefix(res.Instance, "k8s-pod-uid:pod-uid-") {
		t.Fatalf("snippet instance %q", res.Instance)
	}
	pr, err := p.RunProject(ctx, sandbox.ProjectRequest{Files: []sandbox.File{{Path: "main.js", Content: "1"}}, Steps: []string{"node main.js"}})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Outcome != sandbox.ProjectOutcomeCompleted || len(pr.Steps) != 1 || string(pr.Steps[0].Stdout) != "ran node main.js" {
		t.Fatalf("project %+v", pr)
	}
	if !strings.HasPrefix(pr.Instance, "k8s-pod-uid:pod-uid-") || pr.Instance == res.Instance {
		t.Fatalf("project instance %q (the snippet's was %q; each run claims its own pod)", pr.Instance, res.Instance)
	}
	drained(t, p)
	sd.mu.Lock()
	defer sd.mu.Unlock()
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.claims) != 0 || len(api.deleted) != 2 {
		t.Fatalf("claims left %d, deleted %v", len(api.claims), api.deleted)
	}
	for _, c := range api.created {
		if c.Spec.WarmPoolRef.Name != "pool" || c.Spec.Lifecycle == nil || c.Spec.Lifecycle.ShutdownPolicy != "Delete" ||
			c.Meta.Labels[runLabel] != "1" || c.Meta.Labels[instanceLabel] != p.instance || c.Meta.Labels[lifetimeLabel] == "" {
			t.Fatalf("claim %+v", c)
		}
	}
	for i, argv := range sd.starts {
		if sd.auth[i] != "Bearer "+fakeToken || argv[0] != setprivPath || !slices.Contains(argv, "--reuid=61000") ||
			!slices.Contains(argv, "--no-new-privs") || !slices.Contains(argv, "-i") {
			t.Fatalf("start %d: %q with %q", i, argv, sd.auth[i])
		}
	}
}

// Every way a claimed pod can fall short is refused before sandboxd is called, not
// dispatched, and the claim is still deleted.
func TestReadBackRefuses(t *testing.T) {
	escalate := true
	cases := map[string]struct {
		pod    func(*pod)
		policy func(*[]networkPolicy)
		want   string
	}{
		"another runtime class": {pod: func(p *pod) { rc := "runc"; p.Spec.RuntimeClassName = &rc }, want: "runtime class"},
		"an API token mounted":  {pod: func(p *pod) { p.Spec.AutomountServiceAccountToken = nil }, want: "automountServiceAccountToken"},
		"the node's network":    {pod: func(p *pod) { p.Spec.HostNetwork = true }, want: "node's network"},
		"the cluster's DNS":     {pod: func(p *pod) { p.Spec.DNSPolicy = "ClusterFirst" }, want: "DNS"},
		"a search domain":       {pod: func(p *pod) { p.Spec.DNSConfig.Searches = []string{"lan"} }, want: "DNS"},
		"a debug container":     {pod: func(p *pod) { p.Spec.EphemeralContainers = []json.RawMessage{json.RawMessage(`{}`)} }, want: "ephemeral"},
		"a second container":    {pod: func(p *pod) { p.Spec.Containers = append(p.Spec.Containers, p.Spec.Containers[0]) }, want: "containers"},
		"a host path": {pod: func(p *pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, volume{"name": json.RawMessage(`"h"`), "hostPath": json.RawMessage(`{}`)})
		}, want: "emptyDir"},
		"NET_ADMIN": {pod: func(p *pod) {
			c := p.Spec.Containers[0].SecurityContext.Capabilities
			c.Add = append(c.Add, "NET_ADMIN")
		}, want: "capability"},
		"privilege escalation": {pod: func(p *pod) { p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = &escalate }, want: "allowPrivilegeEscalation"},
		"another token":        {pod: func(p *pod) { p.Spec.Containers[0].Command[3] = "--auth-token-sha256=" + digestOf("other") }, want: "another token"},
		"no token":             {pod: func(p *pod) { p.Spec.Containers[0].Command = p.Spec.Containers[0].Command[:3] }, want: "0 --auth-token-sha256"},
		"another command":      {pod: func(p *pod) { p.Spec.Containers[0].Command[0] = "/bin/sh" }, want: "command"},
		"a token file":         {pod: func(p *pod) { p.Spec.Containers[0].Args = []string{"--auth-token-file=/t"} }, want: "file"},
		"another gRPC port":    {pod: func(p *pod) { p.Spec.Containers[0].Command[2] = "--grpc-port=9091" }, want: "gRPC port"},
		"the token after --": {pod: func(p *pod) {
			c := p.Spec.Containers[0].Command
			p.Spec.Containers[0].Command = append(c[:3:3], "--", c[3])
		}, want: "not a --name=value"},
		"the token as another flag's value": {pod: func(p *pod) {
			c := p.Spec.Containers[0].Command
			p.Spec.Containers[0].Command = append(c[:3:3], "--metadata-env-prefix", c[3])
		}, want: "not a --name=value"},
		"a positional argument":         {pod: func(p *pod) { p.Spec.Containers[0].Args = []string{"serve"} }, want: "not a --name=value"},
		"the default termination log":   {pod: func(p *pod) { p.Spec.Containers[0].TerminationMessagePath = defaultTerminationLog }, want: "terminationMessagePath"},
		"no termination log path":       {pod: func(p *pod) { p.Spec.Containers[0].TerminationMessagePath = "" }, want: "terminationMessagePath"},
		"a termination log in a volume": {pod: func(p *pod) { p.Spec.Containers[0].TerminationMessagePath = "/work/log" }, want: "inside /work"},
		"a termination log in /tmp":     {pod: func(p *pod) { p.Spec.Containers[0].TerminationMessagePath = "/tmp/log" }, want: "inside /tmp"},
		"an unclean termination log":    {pod: func(p *pod) { p.Spec.Containers[0].TerminationMessagePath = "/root/../tmp/log" }, want: "clean absolute"},
		"another memory limit":          {pod: func(p *pod) { p.Spec.Containers[0].Resources.Limits["memory"] = "1Gi" }, want: "memory"},
		"another image digest":          {pod: func(p *pod) { p.Status.ContainerStatuses[0].ImageID = "x@sha256:" + strings.Repeat("2", 64) }, want: "pinned"},
		"another sandbox's pod":         {pod: func(p *pod) { p.Meta.OwnerReferences[0].UID = "other" }, want: "not a running pod"},
		"a pod being deleted":           {pod: func(p *pod) { now := time.Now(); p.Meta.DeletionTimestamp = &now }, want: "not a running pod"},
		"another pod IP":                {pod: func(p *pod) { p.Status.PodIP = "10.244.0.99" }, want: "IP"},
		"a policy with egress": {policy: func(ps *[]networkPolicy) {
			var np networkPolicy
			np.Meta.Name = "open"
			np.Meta.UID = "open-uid"
			np.Spec.PodSelector.MatchExpressions = append(np.Spec.PodSelector.MatchExpressions, struct {
				Key      string   `json:"key"`
				Operator string   `json:"operator"`
				Values   []string `json:"values,omitempty"`
			}{Key: "agents.x-k8s.io/sandbox-template-ref-hash", Operator: "Exists"})
			np.Spec.Egress = []json.RawMessage{json.RawMessage(`{}`)}
			*ps = append(*ps, np)
		}, want: "allows egress"},
		"no policy denies egress": {policy: func(ps *[]networkPolicy) { (*ps)[0].Spec.PolicyTypes = []string{"Ingress"} }, want: "denies the pod's egress"},
		"ingress from anywhere":   {policy: func(ps *[]networkPolicy) { (*ps)[0].Spec.Ingress[0].From = nil }, want: "every source"},
		"ingress to the file API": {policy: func(ps *[]networkPolicy) { (*ps)[0].Spec.Ingress[0].Ports[0].Port = json.RawMessage(`8080`) }, want: "8080"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p, api, sd := testProvider(t)
			api.podHook = c.pod
			if c.policy != nil {
				c.policy(&api.policies)
			}
			_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			if err == nil || !strings.Contains(err.Error(), c.want) || refusal(err) != sandbox.RefusalEnvironment {
				t.Fatalf("got %v", err)
			}
			drained(t, p)
			if len(sd.starts) != 0 || len(api.claims) != 0 {
				t.Fatalf("sandboxd called %d times, %d claims left", len(sd.starts), len(api.claims))
			}
		})
	}
}

// A policy elsewhere in the namespace that does not select the pod is not judged.
func TestAnUnrelatedPolicyIsIgnored(t *testing.T) {
	p, api, _ := testProvider(t)
	var np networkPolicy
	np.Meta.Name = "other-template"
	np.Meta.UID = "other-template-uid"
	np.Spec.PodSelector.MatchLabels = map[string]string{"agents.x-k8s.io/sandbox-template-ref-hash": "different"}
	np.Spec.Egress = []json.RawMessage{json.RawMessage(`{}`)}
	api.policies = append(api.policies, np)
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	drained(t, p)
}

// The tier is the runtime class's handler: runc is the container tier, so a kernel floor
// is refused before any claim; a handler plimsoll has not tested is refused outright.
func TestTheHandlerDecidesTheTier(t *testing.T) {
	p, api, _ := testProvider(t)
	api.handler = "runc"
	runtimeDefault(api)
	if err := p.Preflight(context.Background()); err != nil || p.IsolationClass() != sandbox.IsolationContainer {
		t.Fatalf("runc: %v, %s", err, p.IsolationClass())
	}
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationKernel})
	if !errors.Is(err, sandbox.ErrInsufficientIsolation) || len(api.created) != 0 {
		t.Fatalf("kernel floor on runc: %v, %d claims", err, len(api.created))
	}
	if res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil || res.Isolation != sandbox.IsolationContainer {
		t.Fatalf("no floor on runc: %+v, %v", res, err)
	}
	api.handler = "kata-qemu"
	if err := p.Preflight(context.Background()); err == nil || p.IsolationClass() != sandbox.IsolationUnknown {
		t.Fatalf("kata: %v, %s", err, p.IsolationClass())
	}
	drained(t, p)
}

// Each claimed pod is held to its tier from inside before any code is sent: a node can map
// the runsc handler to another runtime, which the API does not show (live on kind, a run was
// signed at the kernel tier on the host's kernel until this check). The check runs first, as
// the guest; a pod whose kernel log is not gVisor's boot line, a runc pod with no seccomp
// filter, or a check that answers anything else is refused, not dispatched, with nothing of
// the run's sent.
func TestEachPodIsHeldToItsTier(t *testing.T) {
	cases := []struct {
		name, handler, answer, want string
	}{
		{"the host's kernel under a runsc handler", "runsc", "kernel [    0.000000] Linux version 6.6.87.2\nboot " + fakeBoot + "\nSeccomp:\t0\n", "not gVisor's"},
		{"a host log line naming gVisor", "runsc", "kernel [178086.727419] Starting gVisor...\nboot " + fakeBoot + "\nSeccomp:\t0\n", "not gVisor's"},
		{"no kernel log readable under a runsc handler", "runsc", "kernel \nboot " + fakeBoot + "\nSeccomp:\t0\n", "not gVisor's"},
		{"runc with no seccomp filter", "runc", "kernel \nboot " + fakeBoot + "\nSeccomp:\t0\n", "seccomp filter"},
		{"a check that answers one line", "runsc", "kernel [   0.000000] Starting gVisor...\n", "tier check exited"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, api, sd := testProvider(t)
			api.handler = c.handler
			runtimeDefault(api)
			sd.tierAnswer = c.answer
			_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
			if err == nil || refusal(err) != sandbox.RefusalEnvironment || !strings.Contains(err.Error(), c.want) || sd.tierChecks != 1 || len(sd.starts) != 0 {
				t.Fatalf("a snippet: %v; %d tier checks, %d starts", err, sd.tierChecks, len(sd.starts))
			}
			_, err = p.RunProject(context.Background(), sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.js", Content: "1"}}, Steps: []string{"node a.js"}})
			if err == nil || refusal(err) != sandbox.RefusalEnvironment || sd.tierChecks != 2 || len(sd.starts) != 0 {
				t.Fatalf("a project: %v; %d tier checks, %d starts", err, sd.tierChecks, len(sd.starts))
			}
			drained(t, p)
		})
	}
	p, _, sd := testProvider(t)
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil || sd.tierChecks != 1 || len(sd.starts) != 1 {
		t.Fatalf("gVisor's boot line: %v; %d tier checks, %d starts", err, sd.tierChecks, len(sd.starts))
	}
	drained(t, p)
}

// A template that fails the read-back fails Preflight, so a misconfigured cluster is
// found at startup.
func TestPreflightChecksTheTemplate(t *testing.T) {
	p, api, _ := testProvider(t)
	api.tmplHook = func(s *podSpec) { s.DNSPolicy = "ClusterFirst" }
	if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), "template") {
		t.Fatalf("got %v", err)
	}
}

// An API server whose clock is far from this process's would make the claim's own
// shutdown time fall inside its run: the run is refused and the claim deleted.
func TestClockSkewIsRefused(t *testing.T) {
	p, api, sd := testProvider(t)
	api.createdAt = func() time.Time { return time.Now().Add(5 * time.Minute) }
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("got %v", err)
	}
	drained(t, p)
	if len(sd.starts) != 0 || len(api.claims) != 0 {
		t.Fatal("ran or left a claim")
	}
}

// A claim that never becomes ready ends with the run's deadline, and is deleted.
func TestAClaimNeverReady(t *testing.T) {
	p, api, _ := testProvider(t)
	api.neverReady = true
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Timeout: 300 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) || refusal(err) != sandbox.RefusalEnvironment {
		t.Fatalf("got %v", err)
	}
	drained(t, p)
	if len(api.claims) != 0 {
		t.Fatal("the claim was left")
	}
}

// A command that does not exit is timed out at the deadline, and its stream is
// cancelled, which is what makes sandboxd kill its process tree. No call carries the
// deadline as Grpc-Timeout: sandboxd's grpc-go server would end the stream on its own
// clock, and a hung command whose stream the server cancelled a moment before this
// process's deadline read as a broken stream (live under gVisor, 2026-10-18).
func TestAHungCommandTimesOut(t *testing.T) {
	p, _, sd := testProvider(t)
	sd.hang = true
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "for(;;);", Timeout: 500 * time.Millisecond})
	if err != nil || !res.TimedOut || res.ExitCode != 124 {
		t.Fatalf("got %+v, %v", res, err)
	}
	select {
	case <-sd.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream was not cancelled")
	}
	drained(t, p)
	sd.mu.Lock()
	defer sd.mu.Unlock()
	if len(sd.timeouts) == 0 {
		t.Fatal("no call reached sandboxd")
	}
	for _, h := range sd.timeouts {
		if h != "" {
			t.Fatalf("a call sent Grpc-Timeout %q", h)
		}
	}
}

// Output past the cap is dropped and flagged, never annotated.
func TestOutputIsCapped(t *testing.T) {
	p, _, sd := testProvider(t)
	sd.run = func([]string, []byte) (string, string, int32) {
		return strings.Repeat("x", maxOutputBytes+10), "e", 3
	}
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if err != nil || len(res.Stdout) != maxOutputBytes || !res.StdoutTruncated || res.StderrTruncated || res.ExitCode != 3 {
		t.Fatalf("got %d bytes, %v, exit %d, %v", len(res.Stdout), res.StdoutTruncated, res.ExitCode, err)
	}
	drained(t, p)
}

// A forged runner report (no valid MAC) is a protocol error, never a result.
func TestAnUnauthenticatedReportIsAProtocolError(t *testing.T) {
	p, _, sd := testProvider(t)
	sd.run = func([]string, []byte) (string, string, int32) {
		return "\nPLIMSOLL-RESULT 2 " + strings.Repeat("0", 64) + "\n{}", "", 0
	}
	pr, err := p.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"true"}})
	if err != nil || pr.Outcome != sandbox.ProjectOutcomeProtocolError {
		t.Fatalf("got %+v, %v", pr, err)
	}
	drained(t, p)
}

func TestGrantsAndModulesAreRefused(t *testing.T) {
	p, api, _ := testProvider(t)
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1", Grant: &sandbox.HostAPIGrant{}})
	if !errors.Is(err, sandbox.ErrUnsupported) || refusal(err) != sandbox.RefusalUnsupported {
		t.Fatalf("grant: %v", err)
	}
	if _, err := p.RunModule(context.Background(), sandbox.ModuleRequest{Model: "VanDerPol", Rows: [][]float64{{1}}, EndTime: 1, Step: 0.1}); !errors.Is(err, sandbox.ErrUnsupported) {
		t.Fatalf("module: %v", err)
	}
	if len(api.created) != 0 {
		t.Fatal("a claim was made")
	}
}

// ReconcileOrphans deletes this instance's untracked claims at once, another instance's
// only past its declared lifetime plus the margin once the clocks are measured, and
// never one without a valid declaration.
func TestReconcileOrphans(t *testing.T) {
	p, api, _ := testProvider(t)
	old := time.Now().Add(-time.Hour)
	young := time.Now()
	add := func(name, instance, lifetime string, at time.Time) {
		api.claims[name] = &claim{Meta: objectMeta{Name: name, CreationTimestamp: &at,
			Labels: map[string]string{runLabel: "1", instanceLabel: instance, lifetimeLabel: lifetime}}}
	}
	add("own-untracked", p.instance, "30", young)
	add("other-old", "other", "30", old)
	add("other-young", "other", "30", young)
	add("other-undeclared", "other", "", old)
	p.leases.Track("own-tracked")
	add("own-tracked", p.instance, "30", old)
	if n, err := p.ReconcileOrphans(context.Background()); err != nil || n != 1 {
		t.Fatalf("before the clocks are measured: %d, %v", n, err)
	}
	p.noteSkew(0)
	if n, err := p.ReconcileOrphans(context.Background()); err != nil || n != 1 {
		t.Fatalf("after: %d, %v", n, err)
	}
	slices.Sort(api.deleted)
	if !slices.Equal(api.deleted, []string{"other-old", "own-untracked"}) {
		t.Fatalf("deleted %v", api.deleted)
	}
}

func TestSelectorMatches(t *testing.T) {
	labels := map[string]string{"a": "1", "b": "2"}
	type expr = struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values,omitempty"`
	}
	for _, c := range []struct {
		sel  labelSelector
		want bool
	}{
		{labelSelector{}, true},
		{labelSelector{MatchLabels: map[string]string{"a": "1"}}, true},
		{labelSelector{MatchLabels: map[string]string{"a": "2"}}, false},
		{labelSelector{MatchExpressions: []expr{{Key: "a", Operator: "In", Values: []string{"1", "3"}}}}, true},
		{labelSelector{MatchExpressions: []expr{{Key: "a", Operator: "NotIn", Values: []string{"1"}}}}, false},
		{labelSelector{MatchExpressions: []expr{{Key: "c", Operator: "NotIn", Values: []string{"1"}}}}, true},
		{labelSelector{MatchExpressions: []expr{{Key: "c", Operator: "Exists"}}}, false},
		{labelSelector{MatchExpressions: []expr{{Key: "c", Operator: "DoesNotExist"}}}, true},
	} {
		if got, err := c.sel.matches(labels); err != nil || got != c.want {
			t.Errorf("%+v: %v, %v", c.sel, got, err)
		}
	}
	if _, err := (labelSelector{MatchExpressions: []expr{{Key: "a", Operator: "Gt"}}}).matches(labels); err == nil {
		t.Error("an unknown operator was guessed")
	}
}

func TestQuantities(t *testing.T) {
	for q, want := range map[string]int64{"256Mi": 256 << 20, "1Gi": 1 << 30, "1000": 1000, "2M": 2e6} {
		if got, err := memoryBytes(q); err != nil || got != want {
			t.Errorf("memory %q: %d, %v", q, got, err)
		}
	}
	for q, want := range map[string]int64{"1": 1000, "500m": 500, "0.25": 250, "2": 2000} {
		if got, err := milliCPU(q); err != nil || got != want {
			t.Errorf("cpu %q: %d, %v", q, got, err)
		}
	}
	for _, q := range []string{"", "1Ti", "-1Mi", "x"} {
		if _, err := memoryBytes(q); err == nil {
			t.Errorf("memory %q accepted", q)
		}
	}
	for _, q := range []string{"", "0.0001", "-1", "1.5m"} {
		if _, err := milliCPU(q); err == nil {
			t.Errorf("cpu %q accepted", q)
		}
	}
}

// runtimeDefault gives the template and every pod the runtime's default seccomp profile.
func runtimeDefault(api *fakeAPI) {
	api.tmplHook = func(s *podSpec) {
		s.Containers[0].SecurityContext.SeccompProfile = &seccompProfile{Type: "RuntimeDefault"}
	}
	api.podHook = func(pd *pod) {
		pd.Spec.Containers[0].SecurityContext.SeccompProfile = &seccompProfile{Type: "RuntimeDefault"}
	}
}

// Under runc the guest's system calls reach the host kernel, so a syscall filter is
// required: none, Unconfined, or a container's Unconfined over the pod's default is
// refused; the pod's default alone, or a node profile, is accepted. Under gVisor none is
// required.
func TestRuncNeedsSeccomp(t *testing.T) {
	for _, c := range []struct {
		name     string
		pod, ctr *seccompProfile
		ok       bool
	}{
		{name: "none"},
		{name: "unconfined", ctr: &seccompProfile{Type: "Unconfined"}},
		{name: "unconfined over the pod's default", pod: &seccompProfile{Type: "RuntimeDefault"}, ctr: &seccompProfile{Type: "Unconfined"}},
		{name: "the pod's default", pod: &seccompProfile{Type: "RuntimeDefault"}, ok: true},
		{name: "a node profile", ctr: &seccompProfile{Type: "Localhost", LocalhostProfile: "plimsoll.json"}, ok: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, api, _ := testProvider(t)
			api.handler = "runc"
			api.tmplHook = func(s *podSpec) {
				if c.pod != nil {
					s.SecurityContext = &struct {
						SeccompProfile *seccompProfile `json:"seccompProfile,omitempty"`
					}{SeccompProfile: c.pod}
				}
				s.Containers[0].SecurityContext.SeccompProfile = c.ctr
			}
			err := p.Preflight(context.Background())
			if c.ok != (err == nil) || (!c.ok && !strings.Contains(err.Error(), "seccomp")) {
				t.Fatalf("got %v", err)
			}
		})
	}
	p, _, _ := testProvider(t)
	if err := p.Preflight(context.Background()); err != nil {
		t.Fatalf("gVisor with no profile: %v", err)
	}
}

// Every volume is mounted whole at a distinct clean path, so the smoke test's writable
// set is exactly those paths.
func TestVolumeMountsAreWhole(t *testing.T) {
	for _, c := range []struct {
		name string
		m    volumeMount
		want string
	}{
		{name: "a subPath", m: volumeMount{Name: "work", MountPath: "/data", SubPath: "x"}, want: "subPath"},
		{name: "a relative path", m: volumeMount{Name: "work", MountPath: "data"}, want: "clean absolute"},
		{name: "an unclean path", m: volumeMount{Name: "work", MountPath: "/data/../work2"}, want: "clean absolute"},
		{name: "the root", m: volumeMount{Name: "work", MountPath: "/"}, want: "clean absolute"},
		{name: "the same path twice", m: volumeMount{Name: "work", MountPath: "/work"}, want: "two volumes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, api, _ := testProvider(t)
			api.tmplHook = func(s *podSpec) { s.Containers[0].VolumeMounts = append(s.Containers[0].VolumeMounts, c.m) }
			if err := p.Preflight(context.Background()); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// SANDBOX_DISK_MB bounds the sum of the template's volume size limits; unset, no sum is
// checked (each volume is still sized).
func TestDiskBudgetBoundsTheVolumes(t *testing.T) {
	for _, c := range []struct {
		name   string
		diskMB int
		want   string // "" passes
	}{
		{"no budget", 0, ""},
		{"the volumes exactly", 128, ""},
		{"room to spare", 512, ""},
		{"a budget below the volumes", 100, "sum to 128 MiB, over SANDBOX_DISK_MB's 100"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, _ := testProvider(t)
			p.cfg.DiskMB = c.diskMB
			err := p.Preflight(context.Background())
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// Once the smoke test has proved a template, a changed one fails Preflight and its runs
// are refused before any claim, until a restart proves it; the same template again is
// accepted.
func TestOnlyTheProvenTemplateRuns(t *testing.T) {
	p, api, sd := testProvider(t)
	p.pf.TTL = 0
	ctx := context.Background()
	if err := p.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.proven = p.templateSum // what SmokeTest records once it passes
	p.mu.Unlock()
	if err := p.Preflight(ctx); err != nil {
		t.Fatalf("the proven template: %v", err)
	}
	api.tmplHook = func(s *podSpec) {
		s.Volumes[0]["emptyDir"] = json.RawMessage(`{"medium":"Memory","sizeLimit":"64Mi"}`)
	}
	if err := p.Preflight(ctx); err == nil || !strings.Contains(err.Error(), "changed after the startup smoke test") {
		t.Fatalf("a changed template: %v", err)
	}
	_, err := p.RunJavaScript(ctx, sandbox.Request{Code: "1"})
	if err == nil || refusal(err) != sandbox.RefusalEnvironment || len(api.claims) != 0 || len(sd.starts) != 0 {
		t.Fatalf("a run on a changed template: %v, %d claims, %d starts", err, len(api.claims), len(sd.starts))
	}
	api.tmplHook = nil
	if err := p.Preflight(ctx); err != nil {
		t.Fatalf("the proven template again: %v", err)
	}
}

// A stream that stays open after the exit event is cut off after the grace, and the
// output kept is reported cut on both streams, never as complete (review, 2026-10-23).
// sandboxd ends the stream right after the exit event, so a normal run is not affected.
func TestOutputCutOffAfterExitIsMarkedCut(t *testing.T) {
	p, _, sd := testProvider(t)
	sd.run = func([]string, []byte) (string, string, int32) { return "1\n", "", 0 }
	sd.holdAfterExit.Store(true)
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if err != nil || res.Stdout != "1\n" || !res.StdoutTruncated || !res.StderrTruncated {
		t.Fatalf("got %q, cut %v and %v, %v", res.Stdout, res.StdoutTruncated, res.StderrTruncated, err)
	}
	drained(t, p)
	sd.holdAfterExit.Store(false)
	if res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil || res.StdoutTruncated || res.StderrTruncated {
		t.Fatalf("a stream that ended after its exit event: cut %v and %v, %v", res.StdoutTruncated, res.StderrTruncated, err)
	}
	drained(t, p)
}
