package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// shippedSeccomp points d at the shipped default for every run and at the derived
// sdk_env variant for a run whose grant asks for the local address.
func shippedSeccomp(t *testing.T, d *DockerSandbox) {
	t.Helper()
	var err error
	if d.Seccomp, err = filepath.Abs("../docker/seccomp.json"); err != nil {
		t.Fatal(err)
	}
	d.SeccompSDK = SeccompSDKDerived
}

// ipv4Probe is a snippet that reports whether the guest may open an IPv4 TCP socket:
// "INET ok" when a loopback listener binds, or "INET <code>" with the error the kernel
// gave (EPERM under the default profile).
const ipv4Probe = `const net = require("node:net");
const s = net.createServer();
s.on("error", (e) => { console.log("INET", e.code); process.exit(0); });
s.listen(0, "127.0.0.1", () => { console.log("INET ok"); s.close(); });`

// sdkEgressProbe is a snippet that tries the outside world over IPv4 and reports how it
// failed: under --network none nothing is reachable whatever the profile allows.
const sdkEgressProbe = `const net = require("node:net");
const c = net.connect(80, "1.1.1.1");
c.on("error", (e) => { console.log("NET", e.code); process.exit(0); });
c.on("connect", () => { console.log("NET connected"); process.exit(0); });`

func sdkGrant(baseURL string) *HostAPIGrant {
	return &HostAPIGrant{BaseURL: baseURL, Allow: []HostRoute{{Method: "GET", Path: "/v1/models"}}, SDKEnv: map[string]string{"OPENAI_BASE_URL": "{origin}/v1"}}
}

func plainGrant(baseURL string) *HostAPIGrant {
	return &HostAPIGrant{BaseURL: baseURL, Allow: []HostRoute{{Method: "GET", Path: "/v1/models"}}}
}

// TestDockerSeccompProfileIsSelectedPerRun: three runs at once on one provider, each
// getting the profile its grant selects and nothing shared between them: a run whose
// grant sets sdk_env may open an IPv4 socket and its record names the variant; a run
// with a plain grant and a run without a grant may not, and their records name the
// default. Under runsc the host profile is skipped for all three and said so.
func TestDockerSeccompProfileIsSelectedPerRun(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireDocker(t)
	shippedSeccomp(t, d)
	defaultID, sdkID := seccompDigest(t, d.Seccomp), seccompBytesID(derivedSeccompBytes(t))
	if d.Runtime == "runsc" {
		defaultID, sdkID = seccompPolicySkippedRunsc, seccompPolicySkippedRunsc
	}
	cases := []struct {
		name   string
		grant  *HostAPIGrant
		want   string
		policy string
	}{
		{"sdk_env grant", sdkGrant("https://api.internal"), "INET ok", sdkID},
		{"plain grant", plainGrant("https://api.internal"), "INET EPERM", defaultID},
		{"no grant", nil, "INET EPERM", defaultID},
	}
	if d.Runtime == "runsc" {
		for i := range cases {
			cases[i].want = "INET ok" // gVisor filters syscalls itself and the host profile is not applied
		}
	}
	var wg sync.WaitGroup
	for _, c := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := d.RunJavaScript(context.Background(), Request{Code: ipv4Probe, Grant: c.grant, Timeout: 60 * time.Second})
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
				return
			}
			if res.ExitCode != 0 || !strings.Contains(res.Stdout, c.want) {
				t.Errorf("%s: exit %d stdout %q stderr %q, want %q", c.name, res.ExitCode, res.Stdout, res.Stderr, c.want)
			}
			if res.Policy != c.policy {
				t.Errorf("%s: policy %q, want %q", c.name, res.Policy, c.policy)
			}
		}()
	}
	wg.Wait()
	if env := d.Environments(); d.Runtime != "runsc" && env.Policy != defaultID+" sdk_env:"+sdkID {
		t.Errorf("Describe policy = %q", env.Policy)
	}
}

// TestDockerSeccompCustomProfileIsNeverReplaced: an operator's own profile stands for
// every run; a run that asks for the local address is refused before dispatch when no
// variant is configured beside it, and the provider's settings are untouched after.
// Under runsc no host profile is applied (gVisor filters system calls itself), so that
// run needs no variant and proceeds, its record saying the host profile was skipped;
// the test had expected the refusal there too and failed the gVisor docker suite.
func TestDockerSeccompCustomProfileIsNeverReplaced(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireDocker(t)
	shipped, err := filepath.Abs("../docker/seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(shipped)
	if err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(t.TempDir(), "operator.json")
	if err := os.WriteFile(custom, append([]byte(`{"//operator": "my copy, unchanged otherwise",`), raw[1:]...), 0o644); err != nil {
		t.Fatal(err)
	}
	d.Seccomp, d.SeccompSDK = custom, ""
	sdkRes, err := d.RunJavaScript(context.Background(), Request{Code: `console.log("ran")`, Grant: sdkGrant("https://api.internal"), Timeout: 60 * time.Second})
	if d.Runtime == "runsc" {
		if err != nil || sdkRes.ExitCode != 0 || !strings.Contains(sdkRes.Stdout, "ran") || sdkRes.Policy != seccompPolicySkippedRunsc {
			t.Fatalf("sdk_env run under runsc with a custom profile: %v, exit %d stdout %q policy %q, want it run with policy %q",
				err, sdkRes.ExitCode, sdkRes.Stdout, sdkRes.Policy, seccompPolicySkippedRunsc)
		}
	} else {
		reason, marked := NotDispatchedReason(err)
		if !errors.Is(err, ErrNoSDKSeccomp) || !marked || reason != RefusalEnvironment {
			t.Fatalf("sdk_env run with a custom profile and no variant: %v (reason %v, marked %v)", err, reason, marked)
		}
	}
	res, err := d.RunJavaScript(context.Background(), Request{Code: ipv4Probe, Grant: plainGrant("https://api.internal"), Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	want := "INET EPERM"
	wantPolicy := seccompDigest(t, custom)
	if d.Runtime == "runsc" {
		want, wantPolicy = "INET ok", seccompPolicySkippedRunsc
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, want) || res.Policy != wantPolicy {
		t.Fatalf("plain run under the custom profile: exit %d stdout %q policy %q, want %q and %q", res.ExitCode, res.Stdout, res.Policy, want, wantPolicy)
	}
	if d.Seccomp != custom || d.SeccompSDK != "" {
		t.Fatalf("the provider's settings changed: %q %q", d.Seccomp, d.SeccompSDK)
	}
}

// TestDockerForwarderThatCannotListenFailsBeforeGuestCode: with the forwarder's address
// one the guest cannot bind, a snippet exits 126 with the forwarder's message and no
// output of its own, and a project runs no step.
func TestDockerForwarderThatCannotListenFailsBeforeGuestCode(t *testing.T) {
	t.Parallel()
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	requireProjectImage(t, d)
	shippedSeccomp(t, d)
	// An address no interface in the container has (docker leaves only loopback, and
	// lowers the privileged-port floor to 0, so a low port would bind): EADDRNOTAVAIL.
	d.loopbackListen = "10.255.255.1:8471"
	grant := sdkGrant("https://api.internal")
	res, err := d.RunJavaScript(context.Background(), Request{Code: `console.log("GUEST RAN")`, Grant: grant, Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != hostForwarderFailedExit || strings.Contains(res.Stdout, "GUEST RAN") || !strings.Contains(res.Stderr, hostForwarderFailedMarker) {
		t.Fatalf("snippet: exit %d stdout %q stderr %q", res.ExitCode, res.Stdout, res.Stderr)
	}
	pr, err := d.RunProject(context.Background(), ProjectRequest{Files: []File{{Path: "main.py", Content: `print("GUEST RAN")`}}, Steps: []string{"python3 main.py"}, Grant: grant, Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Outcome == ProjectOutcomeCompleted || len(pr.Steps) != 0 || !strings.Contains(pr.Detail, "126") {
		t.Fatalf("project: outcome %v detail %q steps %+v", pr.Outcome, pr.Detail, pr.Steps)
	}
}

// TestDockerSDKRunStillHasNoNetwork: the variant lets a run with sdk_env open IPv4
// sockets, and --network none still leaves it nothing to reach: the outside world is
// unreachable, not merely refused by the profile.
func TestDockerSDKRunStillHasNoNetwork(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireDocker(t)
	shippedSeccomp(t, d)
	res, err := d.RunJavaScript(context.Background(), Request{Code: sdkEgressProbe, Grant: sdkGrant("https://api.internal"), Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || strings.Contains(res.Stdout, "connected") || !strings.Contains(res.Stdout, "NET E") {
		t.Fatalf("exit %d stdout %q stderr %q, want an unreachable network", res.ExitCode, res.Stdout, res.Stderr)
	}
}

// TestDockerCellAndSessionResultsNameTheProfileTheyApplied: with the sdk_env variant
// configured, Describe names two profiles, but a cell run by itself and every call in a
// session (whose container never gets the variant) name the one profile they ran under,
// the default, so a record states the profile that was applied (release review,
// 2026-10-29: a cell's record named Describe's two-profile answer).
func TestDockerCellAndSessionResultsNameTheProfileTheyApplied(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireDocker(t)
	shippedSeccomp(t, d)
	defaultID := seccompDigest(t, d.Seccomp)
	if d.Runtime == "runsc" {
		defaultID = seccompPolicySkippedRunsc
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cell, err := RunCellFresh(ctx, d, CellRequest{Language: LanguageJavaScript, Code: "6 * 7", Timeout: 60 * time.Second})
	if err != nil || cell.ExitCode != 0 || cell.Policy != defaultID {
		t.Fatalf("a cell run by itself: %+v, %v; want policy %q", cell, err, defaultID)
	}
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 3 * time.Minute, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	js, err := s.RunJavaScript(ctx, Request{Code: "console.log(1)", Timeout: 30 * time.Second})
	if err != nil || js.Policy != defaultID {
		t.Fatalf("a session's snippet: policy %q, %v; want %q", js.Policy, err, defaultID)
	}
	proj, err := s.RunProject(ctx, ProjectRequest{Steps: []string{"true"}, Timeout: 30 * time.Second})
	if err != nil || proj.Outcome != ProjectOutcomeCompleted || proj.Policy != defaultID {
		t.Fatalf("a session's project: %s, policy %q, %v; want %q", proj.Outcome, proj.Policy, err, defaultID)
	}
	c, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: "1", Timeout: 30 * time.Second})
	if err != nil || c.Policy != defaultID {
		t.Fatalf("a session's cell: policy %q, %v; want %q", c.Policy, err, defaultID)
	}
}
