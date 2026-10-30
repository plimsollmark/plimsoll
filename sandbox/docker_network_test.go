package sandbox

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestDockerLockdownHasNoNetwork pins the flag the whole capability model rests on:
// without a grant a run reaches nothing, and with one it reaches only the broker's
// Unix socket. No daemon needed, so the plain gate catches a deletion too. The flag
// must appear exactly once, so a later argument cannot override it.
func TestDockerLockdownHasNoNetwork(t *testing.T) {
	t.Parallel()
	d := DefaultDocker("")
	for _, runtime := range []string{"", "runsc"} {
		for _, workTmpfs := range []bool{false, true} {
			args := d.lockdownArgs("c", time.Now(), workTmpfs, runtime, d.Seccomp)
			n := 0
			for i, a := range args {
				if a == "--network" || strings.HasPrefix(a, "--network=") || a == "--net" || strings.HasPrefix(a, "--net=") {
					n++
					if a != "--network" || i+1 >= len(args) || args[i+1] != "none" {
						t.Fatalf("runtime %q, work tmpfs %v: network flag is not --network none: %v", runtime, workTmpfs, args)
					}
				}
			}
			if n != 1 {
				t.Fatalf("runtime %q, work tmpfs %v: %d network flags, want exactly one --network none: %v", runtime, workTmpfs, n, args)
			}
		}
	}
}

func TestCheckLoopbackOnly(t *testing.T) {
	if err := checkLoopbackOnly([]string{"lo"}); err != nil {
		t.Fatalf("loopback alone refused: %v", err)
	}
	for _, bad := range [][]string{nil, {}, {"lo", "eth0"}, {"eth0"}, {"lo", "lo"}} {
		if err := checkLoopbackOnly(bad); err == nil {
			t.Fatalf("interfaces %q accepted", bad)
		}
	}
}

// egressProbe reports the network interfaces the run sees and how an attempt to
// reach a public address ended, as one JSON line.
const egressProbe = `(function () {
  const fs = require("node:fs");
  const interfaces = fs.readFileSync("/proc/net/dev", "utf8").split("\n").slice(2)
    .map(l => l.split(":")[0].trim()).filter(Boolean);
  const done = egress => { console.log(JSON.stringify({ interfaces, egress })); };
  let s;
  try { s = require("node:net").connect({host: "1.1.1.1", port: 443}); } catch (e) { done("THROW " + e.code); return; }
  s.setTimeout(5000);
  s.on("connect", () => { done("OPEN"); s.destroy(); });
  s.on("error", e => done("ERROR " + e.code));
  s.on("timeout", () => { done("TIMEOUT"); s.destroy(); });
})();
`

// checkEgressProbe holds a run to loopback alone and to the expected refusal. Under
// --network none the connect fails at once with ENETUNREACH (measured under runc and
// runsc, 2026-09-29); where the shipped seccomp profile applies (runc with a profile),
// it refuses the non-Unix socket first, with EPERM. A timeout is never denial: on an
// offline host a container with a network would time out too. The interface list is
// what proves the missing network under both, since a refused socket says nothing
// about it.
func checkEgressProbe(t *testing.T, d *DockerSandbox, kind, stdout string) {
	t.Helper()
	var got struct {
		Interfaces []string `json:"interfaces"`
		Egress     string   `json:"egress"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &got); err != nil {
		t.Fatalf("%s: unreadable probe output %q: %v", kind, stdout, err)
	}
	if err := checkLoopbackOnly(got.Interfaces); err != nil {
		t.Fatalf("%s: %v", kind, err)
	}
	want := "ERROR ENETUNREACH"
	if d.Seccomp != "" && d.Runtime != "runsc" {
		want = "ERROR EPERM"
	}
	if got.Egress != want {
		t.Fatalf("%s: a connect to a public address ended %q, want %q", kind, got.Egress, want)
	}
}

// TestDockerRunHasNoEgress runs the probe as a snippet and as a project step, the two
// lockdown shapes.
func TestDockerRunHasNoEgress(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	res, err := d.RunJavaScript(context.Background(), Request{Timeout: 30 * time.Second, Code: egressProbe})
	if err != nil {
		t.Fatalf("snippet run: %v", err)
	}
	checkEgressProbe(t, d, "snippet", res.Stdout)

	requireProjectImage(t, d)
	pres, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "probe.js", Content: egressProbe}},
		Steps:   []string{"node probe.js"},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("project run: %v", err)
	}
	if len(pres.Steps) != 1 {
		t.Fatalf("project run: outcome %s, %d steps (%s)", pres.Outcome, len(pres.Steps), pres.Detail)
	}
	checkEgressProbe(t, d, "project step", pres.Steps[0].Stdout)
}

// Every run states its own resource limits instead of inheriting the docker daemon's:
// no core files (a crashing guest would otherwise invoke the host's core_pattern
// handler), a fixed descriptor limit, and a private IPC namespace (v0.15.0 review, L6).
func TestLockdownStatesUlimitsAndIPC(t *testing.T) {
	d := DefaultDocker("")
	for _, runtime := range []string{"runc", "runsc"} {
		args := strings.Join(d.lockdownArgs("c", time.Now(), true, runtime, d.Seccomp), " ")
		for _, want := range []string{"--ulimit core=0", "--ulimit nofile=4096:4096", "--ipc private", "--no-healthcheck"} {
			if !strings.Contains(args, want) {
				t.Errorf("%s: lockdown lacks %q: %s", runtime, want, args)
			}
		}
	}
}

// Every container mounts plimsoll's fixed resolv.conf over /etc/resolv.conf, once,
// read-only, through --mount (which refuses a missing source), and asks docker for no
// DNS setting of its own: docker builds the file it would mount there from the
// host's resolver files (guestResolvConf). No daemon needed.
func TestDockerLockdownMountsTheFixedResolvConf(t *testing.T) {
	t.Parallel()
	files, err := dockerProcessFiles()
	if err != nil {
		t.Fatal(err)
	}
	d := DefaultDocker("")
	for _, runtime := range []string{"", "runsc"} {
		for _, workTmpfs := range []bool{false, true} {
			args := d.lockdownArgs("c", time.Now(), workTmpfs, runtime, d.Seccomp)
			n := 0
			for i, a := range args {
				if strings.HasPrefix(a, "--dns") || strings.Contains(a, "resolv.conf") && (i == 0 || args[i-1] != "--mount") {
					t.Fatalf("runtime %q: unexpected %q in %v", runtime, a, args)
				}
				if a != "--mount" || i+1 >= len(args) {
					continue
				}
				fields, err := csv.NewReader(strings.NewReader(args[i+1])).Read()
				if err != nil {
					t.Fatalf("runtime %q: unreadable --mount %q: %v", runtime, args[i+1], err)
				}
				if slices.Contains(fields, "target=/etc/resolv.conf") {
					n++
					want := []string{"type=bind", "source=" + files.resolvConf, "target=/etc/resolv.conf", "readonly"}
					if !slices.Equal(fields, want) {
						t.Fatalf("runtime %q: the resolv.conf mount is %q, want %q", runtime, fields, want)
					}
				}
			}
			if n != 1 {
				t.Fatalf("runtime %q, work tmpfs %v: %d resolv.conf mounts, want exactly one: %v", runtime, workTmpfs, n, args)
			}
		}
	}
}

// A comma or a quote in a temp directory's path stays inside the source field.
func TestBindMountSpecQuotesItsFields(t *testing.T) {
	t.Parallel()
	for _, src := range []string{"/tmp/a/resolv.conf", "/tmp/a,b/resolv.conf", `/tmp/a"b/resolv.conf`, "/tmp/a b/resolv.conf"} {
		fields, err := csv.NewReader(strings.NewReader(bindMountSpec(src, "/etc/resolv.conf"))).Read()
		want := []string{"type=bind", "source=" + src, "target=/etc/resolv.conf", "readonly"}
		if err != nil || !slices.Equal(fields, want) {
			t.Fatalf("source %q: read back %q (%v), want %q", src, fields, err, want)
		}
	}
}

// The smoke test's check accepts the fixed file alone, and its error never carries
// a value of the file it refused.
func TestCheckGuestResolvConf(t *testing.T) {
	t.Parallel()
	ok := guestResolvConf
	if err := checkGuestResolvConf(&ok); err != nil {
		t.Fatalf("the fixed file refused: %v", err)
	}
	if err := checkGuestResolvConf(nil); err == nil {
		t.Fatal("an unreadable file accepted")
	}
	for _, bad := range []string{
		"",
		"nameserver 10.1.2.3\nsearch canary-tailnet.ts.net canary.corp.example\n",
		"# Generated by Docker Engine.\nnameserver 127.0.0.1\n\n# Based on host file: '/etc/resolv.conf' (legacy)\n",
		guestResolvConf + "search canary.corp.example\n",
		guestResolvConf + "options ndots:5\n",
		guestResolvConf + "sortlist 10.0.0.0/255.0.0.0\n",
		strings.TrimSuffix(guestResolvConf, "\n"),
	} {
		err := checkGuestResolvConf(&bad)
		if err == nil {
			t.Fatalf("%q accepted", bad)
		}
		for _, value := range []string{"canary", "10.1.2.3", "ndots", "sortlist", "legacy"} {
			if strings.Contains(err.Error(), value) {
				t.Fatalf("the error for %q names %q: %v", bad, value, err)
			}
		}
	}
}

// hostResolverValues are the search domains and non-loopback nameservers of this
// host's resolver files: /etc/resolv.conf, and the file systemd-resolved keeps, which
// docker reads in its place when /etc/resolv.conf names only its loopback stub. A
// loopback nameserver is left out: in a container it names the container's own
// loopback, not the host.
func hostResolverValues() []string {
	var values []string
	for _, p := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			switch {
			case len(f) < 2:
			case f[0] == "search" || f[0] == "domain":
				values = append(values, f[1:]...)
			case f[0] == "nameserver":
				if a, err := netip.ParseAddr(f[1]); err != nil || !a.IsLoopback() {
					values = append(values, f[1])
				}
			}
		}
	}
	slices.Sort(values)
	return slices.Compact(values)
}

// checkGuestResolver holds what a guest read from /etc/resolv.conf to the fixed file,
// and counts the host's resolver values in it. Every message states counts, never a
// value, so a failure prints nothing of the host's.
func checkGuestResolver(t *testing.T, kind, got string, host []string) {
	t.Helper()
	shared := 0
	for _, v := range host {
		if strings.Contains(got, v) {
			shared++
		}
	}
	if shared > 0 {
		t.Errorf("%s: the guest's /etc/resolv.conf holds %d of the host's %d search domains and non-loopback nameservers", kind, shared, len(host))
	}
	if err := checkGuestResolvConf(&got); err != nil {
		t.Errorf("%s: %v", kind, err)
	}
}

// resolvProbe prints the guest's /etc/resolv.conf as JSON, so its bytes survive whole.
const resolvProbe = `process.stdout.write(JSON.stringify(require("fs").readFileSync("/etc/resolv.conf", "latin1")))`

// TestDockerGuestSeesNoHostResolver reads /etc/resolv.conf as guest code in a snippet
// run, a project step, and a session's snippet and project calls, and holds each to
// the fixed file with none of the host's search domains or nameservers in it.
// Before the fix every one held the host's search domains and a nameserver (measured
// 2026-10-14 under runc and runsc).
func TestDockerGuestSeesNoHostResolver(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	host := hostResolverValues()
	t.Logf("compared with %d search domains and non-loopback nameservers of this host's resolver files", len(host))
	read := func(kind, stdout string) {
		t.Helper()
		var got string
		if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &got); err != nil {
			t.Fatalf("%s: unreadable probe output (%d bytes): %v", kind, len(stdout), err)
		}
		checkGuestResolver(t, kind, got, host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, err := d.RunJavaScript(ctx, Request{Timeout: 30 * time.Second, Code: resolvProbe})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("snippet run: exit %d, %v", res.ExitCode, err)
	}
	read("snippet run", res.Stdout)
	project := ProjectRequest{
		Files:   []File{{Path: "probe.js", Content: resolvProbe}},
		Steps:   []string{"node probe.js"},
		Timeout: 60 * time.Second,
	}
	pres, err := d.RunProject(ctx, project)
	if err != nil || len(pres.Steps) != 1 || pres.Steps[0].ExitCode != 0 {
		t.Fatalf("project run: %v, outcome %s (%s)", err, pres.Outcome, pres.Detail)
	}
	read("project run", pres.Steps[0].Stdout)

	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 2 * time.Minute, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	sres, err := s.RunJavaScript(ctx, Request{Timeout: 30 * time.Second, Code: resolvProbe})
	if err != nil || sres.ExitCode != 0 {
		t.Fatalf("session snippet: exit %d, %v", sres.ExitCode, err)
	}
	read("session snippet", sres.Stdout)
	spres, err := s.RunProject(ctx, project)
	if err != nil || len(spres.Steps) != 1 || spres.Steps[0].ExitCode != 0 {
		t.Fatalf("session project call: %v, outcome %s (%s)", err, spres.Outcome, spres.Detail)
	}
	read("session project call", spres.Steps[0].Stdout)
}
