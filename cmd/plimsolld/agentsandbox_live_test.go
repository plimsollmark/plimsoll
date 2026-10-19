package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// agentsandboxVars are the daemon's cluster settings, which the live test passes through;
// the first is optional (the in-cluster default), the rest required.
var agentsandboxVars = []string{
	"SANDBOX_AGENTSANDBOX_API_SERVER", "SANDBOX_AGENTSANDBOX_CA_FILE", "SANDBOX_AGENTSANDBOX_TOKEN_FILE",
	"SANDBOX_AGENTSANDBOX_NAMESPACE", "SANDBOX_AGENTSANDBOX_WARM_POOL", "SANDBOX_AGENTSANDBOX_RUNTIME_CLASS",
	"SANDBOX_AGENTSANDBOX_IMAGE", "SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE",
}

// envelopeVars are passed through when set, for a template whose limits are not the
// defaults (the read-back requires them to be equal).
var envelopeVars = []string{"SANDBOX_MEMORY_MB", "SANDBOX_CPUS"}

// TestAgentSandboxDaemonLive runs the real daemon against an agent-sandbox cluster:
// startup (the read-back and the smoke test), Describe, a snippet under the tier's floor,
// a vm floor below the vm tier, and a project with an artifact over the RPC client; then
// SIGTERM, after which the cluster must hold no claim of plimsoll's, because shutdown
// waited for every delete. Same opt-in and configuration as the provider's live suite
// (sandbox/agentsandbox/live_test.go): it skips unless AGENTSANDBOX_LIVE=1, and then fails
// if a variable is missing. AGENTSANDBOX_TIER is the tier the cluster was set up for.
func TestAgentSandboxDaemonLive(t *testing.T) {
	if os.Getenv("AGENTSANDBOX_LIVE") != "1" {
		t.Skip("the live agent-sandbox suite runs with AGENTSANDBOX_LIVE=1 and a cluster")
	}
	tier := sandbox.ParseIsolationClass(os.Getenv("AGENTSANDBOX_TIER"))
	if tier != sandbox.IsolationVM && tier != sandbox.IsolationKernel && tier != sandbox.IsolationContainer {
		t.Fatalf("AGENTSANDBOX_TIER is %q; set vm, kernel or container", os.Getenv("AGENTSANDBOX_TIER"))
	}
	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	env := []string{"SANDBOX_PROVIDER=agentsandbox", "PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=off", "PLIMSOLL_TOKEN=" + token}
	var missing []string
	for i, name := range agentsandboxVars {
		if os.Getenv(name) == "" && i > 0 {
			missing = append(missing, name)
		}
		env = append(env, name+"="+os.Getenv(name))
	}
	if len(missing) > 0 {
		t.Fatalf("AGENTSANDBOX_LIVE=1 but %s not set", strings.Join(missing, ", "))
	}
	for _, name := range envelopeVars {
		if v := os.Getenv(name); v != "" {
			env = append(env, name+"="+v)
		}
	}
	before := liveClaims(t)

	start := time.Now()
	d := startDaemon(t, env, 3*time.Minute)
	t.Logf("daemon ready in %v (read-back and smoke test included)", time.Since(start).Round(time.Millisecond))
	if !strings.Contains(d.logText(), "agentsandbox smoke passed") {
		t.Fatalf("the daemon served without logging a passing smoke test:\n%s", d.logText())
	}
	remote, err := client.New("http://"+d.addr, client.WithToken(token))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	info, err := remote.Describe(ctx)
	if err != nil || info.Sandbox != "agentsandbox" || info.Isolation != tier ||
		!info.SupportsProject || info.SupportsModule || info.SupportsJavaScriptGrants || info.SupportsProjectGrants {
		t.Fatalf("Describe = %+v, %v", info, err)
	}

	res, err := remote.RunJavaScript(ctx, sandbox.Request{Code: "console.log(6 * 7)", MinimumIsolation: tier})
	if err != nil || res.ExitCode != 0 || res.Stdout != "42\n" || res.Isolation != tier {
		t.Fatalf("snippet: %+v, %v", res, err)
	}
	t.Logf("snippet over RPC: exit %d, stdout %q, %v", res.ExitCode, res.Stdout, res.Duration.Round(time.Millisecond))

	if tier != sandbox.IsolationVM {
		_, err = remote.RunJavaScript(ctx, sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM})
		if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalIsolation {
			t.Fatalf("a vm floor on the %s tier: err = %v, want an isolation refusal before dispatch", tier, err)
		}
	}

	pres, err := remote.RunProject(ctx, sandbox.ProjectRequest{
		Files:     []sandbox.File{{Path: "main.js", Content: `require("fs").writeFileSync("out.txt", "ok"); console.log("ran")`}},
		Steps:     []string{"node main.js"},
		Artifacts: []string{"out.txt"},
	})
	if err != nil || pres.Outcome != sandbox.ProjectOutcomeCompleted || len(pres.Steps) != 1 || pres.Steps[0].Stdout != "ran\n" ||
		len(pres.Artifacts) != 1 || string(pres.Artifacts[0].Content) != "ok" {
		t.Fatalf("project: %+v, %v", pres, err)
	}

	stop := time.Now()
	d.stop(t, 2*time.Minute)
	t.Logf("daemon drained and exited in %v", time.Since(stop).Round(time.Millisecond))
	var left []string
	for name := range liveClaims(t) {
		if !before[name] {
			left = append(left, name)
		}
	}
	if len(left) > 0 {
		t.Fatalf("claims left after the daemon drained: %v", left)
	}
}

// liveClaims lists plimsoll's SandboxClaims in the namespace by name, read from outside
// the daemon with the same files the daemon gets.
func liveClaims(t *testing.T) map[string]bool {
	t.Helper()
	caPEM, err := os.ReadFile(os.Getenv("SANDBOX_AGENTSANDBOX_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("no certificate in the API server's CA file")
	}
	bearer, err := os.ReadFile(os.Getenv("SANDBOX_AGENTSANDBOX_TOKEN_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	server := os.Getenv("SANDBOX_AGENTSANDBOX_API_SERVER")
	if server == "" {
		server = "https://kubernetes.default.svc"
	}
	u := fmt.Sprintf("%s/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/%s/sandboxclaims?labelSelector=%s",
		strings.TrimRight(server, "/"), url.PathEscape(os.Getenv("SANDBOX_AGENTSANDBOX_NAMESPACE")), url.QueryEscape("plimsoll.run=1"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(bearer)))
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list claims: %s", resp.Status)
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, it := range list.Items {
		names[it.Metadata.Name] = true
	}
	return names
}
