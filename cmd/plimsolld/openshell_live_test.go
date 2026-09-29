package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/datamodelv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1/openshellv1connect"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// openshellVars are the daemon's gateway settings, which the live test passes through.
var openshellVars = []string{
	"SANDBOX_OPENSHELL_GATEWAY_URL", "SANDBOX_OPENSHELL_CA_FILE",
	"SANDBOX_OPENSHELL_CERT_FILE", "SANDBOX_OPENSHELL_KEY_FILE", "SANDBOX_OPENSHELL_IMAGE",
}

// TestOpenShellDaemonLive runs the real daemon against an OpenShell gateway: startup
// (the driver check and the smoke test), Describe, a snippet under a container floor,
// a floor the tier cannot meet, and a project with an artifact over the RPC client;
// then SIGTERM, after which the gateway must list no plimsoll sandbox the daemon
// created, because shutdown waited for every delete. Same opt-in and configuration
// as the provider's live suite (sandbox/openshell/live_test.go): it skips unless
// OPENSHELL_LIVE=1, and then fails if a variable is missing.
func TestOpenShellDaemonLive(t *testing.T) {
	if os.Getenv("OPENSHELL_LIVE") != "1" {
		t.Skip("the live OpenShell suite runs with OPENSHELL_LIVE=1 and a gateway")
	}
	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	env := []string{"SANDBOX_PROVIDER=openshell", "PLIMSOLL_ADDR=127.0.0.1:0", "PLIMSOLL_METRICS_ADDR=off", "PLIMSOLL_TOKEN=" + token}
	var missing []string
	for _, name := range openshellVars {
		if os.Getenv(name) == "" {
			missing = append(missing, name)
		}
		env = append(env, name+"="+os.Getenv(name))
	}
	if len(missing) > 0 {
		t.Fatalf("OPENSHELL_LIVE=1 but %s not set", strings.Join(missing, ", "))
	}
	gw := liveGatewayClient(t)
	before := runSandboxes(t, gw)

	start := time.Now()
	d := startDaemon(t, env, 2*time.Minute)
	t.Logf("daemon ready in %v (driver check and smoke test included)", time.Since(start).Round(time.Millisecond))
	if !strings.Contains(d.logText(), "openshell smoke passed") {
		t.Fatalf("the daemon served without logging a passing smoke test:\n%s", d.logText())
	}
	remote, err := client.New("http://"+d.addr, client.WithToken(token))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	info, err := remote.Describe(ctx)
	if err != nil || info.Sandbox != "openshell" || info.Isolation != sandbox.IsolationContainer ||
		!info.SupportsProject || info.SupportsModule || !info.SupportsJavaScriptGrants || !info.SupportsProjectGrants {
		t.Fatalf("Describe = %+v, %v", info, err)
	}

	res, err := remote.RunJavaScript(ctx, sandbox.Request{Code: "console.log(6 * 7)", MinimumIsolation: sandbox.IsolationContainer})
	if err != nil || res.ExitCode != 0 || res.Stdout != "42\n" || res.Isolation != sandbox.IsolationContainer {
		t.Fatalf("snippet: %+v, %v", res, err)
	}
	t.Logf("snippet over RPC: exit %d, stdout %q, %v", res.ExitCode, res.Stdout, res.Duration.Round(time.Millisecond))

	_, err = remote.RunJavaScript(ctx, sandbox.Request{Code: "1", MinimumIsolation: sandbox.IsolationVM})
	if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalIsolation {
		t.Fatalf("a vm floor on a container tier: err = %v, want an isolation refusal before dispatch", err)
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
	after := runSandboxes(t, gw)
	var left []string
	for name := range after {
		if !before[name] {
			left = append(left, name)
		}
	}
	if len(left) > 0 {
		t.Fatalf("sandboxes left after the daemon drained: %v", left)
	}
}

// liveGatewayClient is a gateway client for checking the daemon from outside, built
// from the same files the daemon gets.
func liveGatewayClient(t *testing.T) openshellv1connect.OpenShellClient {
	t.Helper()
	caPEM, err := os.ReadFile(os.Getenv("SANDBOX_OPENSHELL_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("no certificate in the gateway CA file")
	}
	pair, err := tls.LoadX509KeyPair(os.Getenv("SANDBOX_OPENSHELL_CERT_FILE"), os.Getenv("SANDBOX_OPENSHELL_KEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}}
	return openshellv1connect.NewOpenShellClient(hc, strings.TrimRight(os.Getenv("SANDBOX_OPENSHELL_GATEWAY_URL"), "/"), connect.WithGRPC())
}

// runSandboxes lists the gateway's plimsoll run sandboxes by name.
func runSandboxes(t *testing.T, gw openshellv1connect.OpenShellClient) map[string]bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	names := map[string]bool{}
	token := ""
	for {
		resp, err := gw.ListSandboxes(ctx, connect.NewRequest(&openshellv1.ListSandboxesRequest{
			WorkspaceScope: &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "default"}},
			PageSize:       100, PageToken: token, LabelSelector: "plimsoll.run=1",
		}))
		if err != nil {
			t.Fatalf("list sandboxes: %v", err)
		}
		for _, sb := range resp.Msg.GetSandboxes() {
			names[sb.GetMetadata().GetName()] = true
		}
		if token = resp.Msg.GetNextPageToken(); token == "" {
			return names
		}
	}
}
