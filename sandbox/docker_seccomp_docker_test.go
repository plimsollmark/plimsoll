package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
			// The profile, then the guest guard every command starts behind.
			if want := c.policy + " " + testGuestGuardWord(t); res.Policy != want {
				t.Errorf("%s: policy %q, want %q", c.name, res.Policy, want)
			}
		}()
	}
	wg.Wait()
	if env := d.Environments(); d.Runtime != "runsc" && env.Policy != defaultID+" sdk_env:"+sdkID+" "+testGuestGuardWord(t) {
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
		if err != nil || sdkRes.ExitCode != 0 || !strings.Contains(sdkRes.Stdout, "ran") || sdkRes.Policy != seccompPolicySkippedRunsc+" "+testGuestGuardWord(t) {
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
	wantPolicy += " " + testGuestGuardWord(t) // then the guest guard every command starts behind
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
	defaultID += " " + testGuestGuardWord(t) // then the guest guard every command starts behind
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
	// What the session states at open, which the record of a call that ended without
	// an answer names (finding release-40).
	if got := s.Environments().Policy; got != defaultID {
		t.Fatalf("the session states policy %q at open; want %q", got, defaultID)
	}
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

// seccompEntryRow is one line of testdata/seccomp_entries.py: one system call made through
// one of the kernel's entries on x86-64 (native, the 32-bit int 0x80, x32), in a child of
// its own. Exit is the child's status, negative for the signal that ended it; Ret is what
// the call returned (minus the errno when refused), absent when the child was killed.
type seccompEntryRow struct {
	Case   string `json:"case"`
	Entry  string `json:"entry"`
	Exit   int    `json:"exit"`
	Ret    *int   `json:"ret"`
	Family *int   `json:"family"`
	Stderr string `json:"stderr"`
}

const (
	sigsys, sigsegv = 31, 11
	errEPERM        = 1
	errENOSYS       = 38
)

func (r seccompEntryRow) allowed() bool       { return r.Exit == 0 && r.Ret != nil && *r.Ret >= 0 }
func (r seccompEntryRow) refused(e int) bool  { return r.Exit == 0 && r.Ret != nil && *r.Ret == -e }
func (r seccompEntryRow) killedBy(s int) bool { return r.Exit == -s }

func (r seccompEntryRow) String() string {
	switch {
	case r.Exit < 0:
		return "killed by signal " + strconv.Itoa(-r.Exit)
	case r.Ret == nil:
		return "the child failed (exit " + strconv.Itoa(r.Exit) + "): " + r.Stderr
	case *r.Ret < 0:
		return "refused, errno " + strconv.Itoa(-*r.Ret)
	case r.Family != nil:
		return "allowed, a socket of family " + strconv.Itoa(*r.Family)
	}
	return "allowed, returned " + strconv.Itoa(*r.Ret)
}

// parseSeccompEntries reads the probe's lines, refusing an output that lacks a case the
// probe lists: a row that went missing would otherwise pass for one that was refused.
func parseSeccompEntries(t *testing.T, out string, want []string) map[string]seccompEntryRow {
	t.Helper()
	rows := map[string]seccompEntryRow{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var r seccompEntryRow
		if err := json.Unmarshal([]byte(line), &r); err != nil || r.Case == "" {
			t.Fatalf("the probe printed %q, not a case row (%v); its whole output:\n%s", line, err, out)
		}
		rows[r.Case] = r
	}
	for _, c := range want {
		if _, ok := rows[c]; !ok {
			t.Fatalf("the probe reported no row for %q; its whole output:\n%s", c, out)
		}
	}
	return rows
}

// seccompEntriesDirect runs the probe straight through docker, outside the provider, under a
// profile file and the provider's lockdown flags that bear on system calls (the guest uid, no
// capabilities, no-new-privileges, no network, a read-only root).
func seccompEntriesDirect(t *testing.T, d *DockerSandbox, profile string, probe []byte) string {
	t.Helper()
	args := []string{"run", "--rm", "-i", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + profile, "--user", d.guestUser(), "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m"}
	if d.Runtime != "" {
		args = append(args, "--runtime", d.Runtime)
	}
	args = append(args, "--entrypoint", "/usr/bin/env", d.ProjectImage, "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "python3", "-I", "-")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = bytes.NewReader(probe)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the probe under %s: %v: %s", profile, err, stderr.String())
	}
	return string(out)
}

// TestDockerSeccompKillsEveryNonNativeEntry: on x86-64 a guest can make system calls through
// two entries besides the native one, the 32-bit int 0x80 and x32, and under the shipped
// profile and the sdk_env variant derived from it every call through either is killed, as
// the guest: the profiles list each machine's native architecture alone. Until 2026-11-19
// the shipped profile listed SCMP_ARCH_X86 and SCMP_ARCH_X32 too, and a guest made a socket
// of any family through the 32-bit socketcall, which libseccomp writes for the 32-bit entry
// without socket's family check (finding release-78, docs/seccomp.md "Architectures").
//
// The probe (testdata/seccomp_entries.py, Python's ctypes running a few bytes of machine
// code) makes each call in a child of its own and reports how the child ended. First a
// control, straight through docker since Preflight refuses that profile now: the shipped
// profile with the sub-architectures restored, which tells whether this kernel has each
// entry (its getpid gets through, where a kernel built or booted without the 32-bit entry
// faults with SIGSEGV instead, before any filter runs) and proves the probe sees the hole
// (its 32-bit socketcall makes an AF_INET socket, which the profile refuses natively). Then
// the probe as a project step through the provider, once with no grant (the default) and
// once with an sdk_env grant (the variant): no row of the 32-bit or x32 entry may get
// through, getpid included, so an entry the profile lists fails the test even where its
// rules hold, and each must end killed by SIGSYS, seccomp's kill (EPERM, the profile's own
// refusal, is accepted too); on a kernel without the 32-bit entry its rows fault instead,
// which the test logs, and the x32 rows are still killed, since seccomp sees an x32 number
// before the kernel looks whether x32 is enabled. The restored list is the mutation that
// fails it: both getpids and every socketcall row are allowed under it.
//
// Under gVisor (runsc) the host profile is not applied and the sentry implements neither
// entry; the test then holds gVisor to the same rule, nothing through either entry, and
// accepts its ENOSYS.
func TestDockerSeccompKillsEveryNonNativeEntry(t *testing.T) {
	t.Parallel()
	if runtime.GOARCH != "amd64" {
		t.Skipf("the probe is x86-64 machine code, and %s has no int 0x80 or x32 entry; an aarch64 host's 32-bit ARM entry needs a 32-bit ARM program, which this test does not carry", runtime.GOARCH)
	}
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	requireProjectImage(t, d)
	shippedSeccomp(t, d)
	probe, err := os.ReadFile("testdata/seccomp_entries.py")
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		"i386 getpid", "i386 socketcall socket AF_UNIX", "i386 socketcall socket AF_INET", "i386 socketcall socket AF_NETLINK",
		"i386 socketcall socket AF_ALG", "i386 socketcall socket AF_VSOCK", "i386 socket AF_UNIX", "i386 socket AF_VSOCK",
		"i386 ipc shmget", "i386 shmget", "i386 clone CLONE_NEWUSER", "i386 personality READ_IMPLIES_EXEC",
		"i386 mknodat FIFO", "i386 mknodat regular file", "i386 mknod regular file",
		"x32 getpid", "x32 socket AF_UNIX", "x32 socket AF_VSOCK", "x32 shmget", "x32 clone CLONE_NEWUSER",
		"x32 personality READ_IMPLIES_EXEC", "x32 mknodat regular file",
		"x86_64 socket AF_UNIX", "x86_64 socket AF_INET", "x86_64 socket AF_VSOCK",
	}

	has32BitEntry := true
	if d.Runtime != "runsc" {
		raw, err := os.ReadFile(d.Seccomp)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc["archMap"] = []any{
			map[string]any{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": []any{"SCMP_ARCH_X86", "SCMP_ARCH_X32"}},
			map[string]any{"architecture": "SCMP_ARCH_AARCH64", "subArchitectures": []any{"SCMP_ARCH_ARM"}},
		}
		old, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		oldPath := filepath.Join(t.TempDir(), "seccomp-with-sub-architectures.json")
		if err := os.WriteFile(oldPath, old, 0o644); err != nil {
			t.Fatal(err)
		}
		control := parseSeccompEntries(t, seccompEntriesDirect(t, d, oldPath, probe), cases)
		getpid := control["i386 getpid"]
		switch {
		case getpid.allowed():
			if r := control["i386 socketcall socket AF_INET"]; !r.allowed() {
				t.Fatalf("under the profile with the 32-bit sub-architecture restored, the probe's 32-bit socketcall for AF_INET was %s, not allowed: the probe cannot see the hole this test guards against", r)
			}
		case getpid.killedBy(sigsegv):
			has32BitEntry = false
			t.Logf("this kernel has no 32-bit entry (a 32-bit getpid faults with SIGSEGV under a profile that lists the 32-bit architecture), so the 32-bit rows below prove nothing here; the x32 rows still do")
		default:
			t.Fatalf("under the profile with the 32-bit sub-architecture restored, a 32-bit getpid was %s: neither allowed (the kernel has the entry) nor a fault (it has none)", getpid)
		}
		t.Logf("control, the shipped profile with its old sub-architectures: 32-bit socketcall AF_VSOCK %s; x32 getpid %s",
			control["i386 socketcall socket AF_VSOCK"], control["x32 getpid"])
	}

	for _, run := range []struct {
		name  string
		grant *HostAPIGrant
	}{{"the default profile", nil}, {"the sdk_env variant", sdkGrant("https://api.internal")}} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		res, err := d.RunProject(ctx, ProjectRequest{
			Files:   []File{{Path: "seccomp_entries.py", Content: string(probe)}},
			Steps:   []string{"python3 -I seccomp_entries.py"},
			Grant:   run.grant,
			Timeout: 90 * time.Second,
		})
		cancel()
		if err != nil || res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
			t.Fatalf("%s: the probe did not complete: %+v, %v", run.name, res, err)
		}
		rows := parseSeccompEntries(t, res.Steps[0].Stdout, cases)
		if r := rows["x86_64 socket AF_UNIX"]; !r.allowed() {
			t.Fatalf("%s: a native AF_UNIX socket was %s; the probe itself is not working", run.name, r)
		}
		if r := rows["x86_64 socket AF_VSOCK"]; d.Runtime != "runsc" && !r.refused(errEPERM) {
			t.Errorf("%s: a native AF_VSOCK socket was %s, want refused with EPERM by the family rule", run.name, r)
		}
		for _, c := range cases {
			r := rows[c]
			if r.Entry == "x86_64" {
				continue
			}
			ok := false
			switch {
			case d.Runtime == "runsc":
				ok = r.killedBy(sigsys) || r.refused(errENOSYS) || r.refused(errEPERM)
			case r.Entry == "i386" && !has32BitEntry:
				ok = r.killedBy(sigsegv) || r.killedBy(sigsys)
			default:
				ok = r.killedBy(sigsys) || r.refused(errEPERM)
			}
			if !ok || r.allowed() {
				t.Errorf("%s: %q was %s, want it killed by SIGSYS: a call through a non-native entry must not reach the profile's rules", run.name, c, r)
			}
		}
	}
}
