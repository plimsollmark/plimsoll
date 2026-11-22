package agentsandbox

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// kataBoot and kataMounts are what a Kata pod of the template reported on kind
// (2026-10-18, Cloud Hypervisor, runtime-rs), as the guest.
const kataBoot = "[    0.000000] Linux version 6.18.35 (@540110ce73d4) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Tue Sep 15 07:34:33 UTC 2026"

var kataMounts = []string{
	"none / virtiofs ro,nodev,relatime 0 0",
	"tmpfs /work tmpfs rw,relatime 0 0",
	"tmpfs /tmp tmpfs rw,relatime 0 0",
	"shm /dev/shm tmpfs rw,relatime 0 0",
}

// Each check the smoke test makes of a boundary report, given a report that passes it
// and the reports that must fail it. The live suite and the docker suite run the script;
// these pin what the checks refuse.
func TestSmokeChecksRefuse(t *testing.T) {
	queue := "mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0"
	filled := func(wrote int64, code string) boundaryReport {
		r := boundaryReport{}
		r.Fill = map[string]struct {
			Wrote int64  `json:"wrote"`
			Code  string `json:"code"`
		}{"/work": {wrote, code}}
		return r
	}
	const size = 128 << 20
	for _, c := range []struct {
		name string
		err  error
		want string // "" passes
	}{
		{"seccomp filter under runc", checkSeccompMode(sandbox.IsolationContainer, "2"), ""},
		{"no seccomp filter under runc", checkSeccompMode(sandbox.IsolationContainer, "0"), "mode \"0\""},
		{"no seccomp field under runc", checkSeccompMode(sandbox.IsolationContainer, ""), "not 2"},
		{"gVisor's emulated status", checkSeccompMode(sandbox.IsolationKernel, "0"), ""},

		{"gVisor's kernel log", checkKernel(sandbox.IsolationKernel, "[   0.000000] Starting gVisor..."), ""},
		{"a handler named runsc on another kernel", checkKernel(sandbox.IsolationKernel, "error: 1"), "not gVisor's"},
		{"runc's refused kernel log", checkKernel(sandbox.IsolationContainer, "error: 1"), ""},
		{"a Kata VM's kernel log", checkKernel(sandbox.IsolationVM, kataBoot), ""},
		{"gVisor's kernel log under a Kata handler", checkKernel(sandbox.IsolationVM, "[   0.000000] Starting gVisor..."), "not a Linux kernel's boot"},
		{"no kernel log under a Kata handler", checkKernel(sandbox.IsolationVM, ""), "not a Linux kernel's boot"},
		{"a later kernel line under a Kata handler", checkKernel(sandbox.IsolationVM, "[178086.727419] Linux version 6.6.87.2 (x)"), "not a Linux kernel's boot"},

		{"a boot ID of the VM's own", checkOwnKernel(sandbox.IsolationVM, fakeBoot, fakeNodeBoot), ""},
		{"the node's boot ID", checkOwnKernel(sandbox.IsolationVM, fakeNodeBoot, fakeNodeBoot), "is its node's"},
		{"the node's boot ID in capitals", checkOwnKernel(sandbox.IsolationVM, fakeNodeBoot, strings.ToUpper(fakeNodeBoot)), "is its node's"},
		{"a node with no boot ID", checkOwnKernel(sandbox.IsolationVM, fakeBoot, ""), "reports no boot ID"},
		{"no boot ID in the guest", checkOwnKernel(sandbox.IsolationVM, "", fakeNodeBoot), "not a boot ID"},
		{"a node's boot ID that is not one", checkOwnKernel(sandbox.IsolationVM, fakeBoot, "unknown"), "node's boot ID reads"},
		{"the boot ID unchecked outside the vm tier", checkOwnKernel(sandbox.IsolationContainer, fakeNodeBoot, fakeNodeBoot), ""},

		{"every root a guest tmpfs", checkRootMountKinds(kataMounts, []string{"/dev/shm", "/tmp", "/work"}, []string{"tmpfs"}), ""},
		{"a root shared from the node", checkRootMountKinds(append(kataMounts, "none /tmp virtiofs rw,nodev,relatime 0 0"), []string{"/dev/shm", "/tmp", "/work"}, []string{"tmpfs"}), `/tmp is mounted as "virtiofs"`},
		{"a root not mounted", checkRootMountKinds(kataMounts[:1], []string{"/dev/shm", "/work"}, []string{"tmpfs"}), `/work is mounted as ""`},

		{"every connection unanswered", checkEgress(map[string]string{"tcp 1.1.1.1:443": "timeout", "tcp 10.0.0.1:10250": "EHOSTUNREACH"}, "10.0.0.1"), ""},
		{"a connection refused by its destination", checkEgress(map[string]string{"tcp 10.0.0.1:10250": "ECONNREFUSED"}, "10.0.0.1"), "connections left the pod"},
		{"a connection open", checkEgress(map[string]string{"tcp 1.1.1.1:443": "open"}, "10.0.0.1"), "connections left the pod"},
		{"no connection tried", checkEgress(nil, "10.0.0.1"), "no connection attempts"},
		{"no default route", checkEgress(map[string]string{"tcp 1.1.1.1:443": "timeout"}, ""), "no default route"},

		{"writes beneath the roots", checkWritable(4900, []string{"/work", "/work/a", "/tmp"}, nil, []string{"/work", "/tmp"}), ""},
		{"a directory outside the roots", checkWritable(4900, []string{"/work", "/etc"}, nil, []string{"/work"}), "/etc"},
		{"a file outside the roots", checkWritable(4900, []string{"/work"}, []string{"/dev/termination-log"}, []string{"/work"}), "/dev/termination-log"},
		{"a root's prefix is not beneath it", checkWritable(4900, []string{"/work", "/workshop"}, nil, []string{"/work"}), "/workshop"},
		{"no /work", checkWritable(4900, []string{"/tmp"}, nil, []string{"/work", "/tmp"}), "/work does not accept"},
		{"too short a sweep", checkWritable(12, []string{"/work"}, nil, []string{"/work"}), "only 12 paths"},

		{"filled to the limit", checkFill(filled(size, "ENOSPC"), map[string]int64{"/work": size}), ""},
		{"filled past the limit", checkFill(filled(size+(9<<20), "none"), map[string]int64{"/work": size}), "not ENOSPC"},
		{"refused far below the limit", checkFill(filled(1<<20, "ENOSPC"), map[string]int64{"/work": size}), "not ENOSPC"},
		{"another error", checkFill(filled(size, "EIO"), map[string]int64{"/work": size}), "not ENOSPC"},
		{"a volume not filled", checkFill(boundaryReport{}, map[string]int64{"/work": size}), "not filled"},
	} {
		switch {
		case c.want == "" && c.err != nil:
			t.Errorf("%s: %v", c.name, c.err)
		case c.want != "" && (c.err == nil || !strings.Contains(c.err.Error(), c.want)):
			t.Errorf("%s: got %v, want %q", c.name, c.err, c.want)
		}
	}

	for _, c := range []struct {
		name    string
		r       boundaryReport
		rest    []string
		wantErr string
	}{
		{"a bounded queue", boundaryReport{Created: []string{mqueueDir}, Mounts: []string{queue}, Msgqueue: "819200"}, nil, ""},
		{"nothing created", boundaryReport{Mounts: []string{queue}, Msgqueue: "819200"}, nil, ""},
		{"a file created elsewhere", boundaryReport{Created: []string{"/etc"}, Mounts: []string{queue}, Msgqueue: "819200"}, []string{"/etc"}, ""},
		{"an unlimited allowance", boundaryReport{Created: []string{mqueueDir}, Mounts: []string{queue}, Msgqueue: "unlimited"}, []string{mqueueDir}, "unlimited"},
		{"a raised allowance", boundaryReport{Created: []string{mqueueDir}, Mounts: []string{queue}, Msgqueue: "67108864"}, []string{mqueueDir}, "67108864"},
		{"not a queue filesystem", boundaryReport{Created: []string{mqueueDir}, Mounts: []string{"tmpfs /dev/mqueue tmpfs rw 0 0"}, Msgqueue: "819200"}, []string{mqueueDir}, "mounted there: false"},
	} {
		rest, err := checkMqueue(c.r)
		if strings.Join(rest, " ") != strings.Join(c.rest, " ") || (c.wantErr == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: got %v, %v; want %v, %q", c.name, rest, err, c.rest, c.wantErr)
		}
	}
}

// From inside the pod: the guest's open of the TLS key must fail for permission, and a
// cleartext process start sent to the terminator must get no gRPC status.
func TestSmokeHoldsTheChannelFromInside(t *testing.T) {
	report := func(key, front string) boundaryReport {
		return boundaryReport{TLSKey: key, Sandboxd: map[string]string{"none": "16", "wrong": "16", "front": front}}
	}
	for _, c := range []struct {
		key, front, want string // want "" passes
	}{
		{"EACCES", "ERR_HTTP2_SESSION_ERROR", ""},
		{"EPERM", "none", ""},
		{"EACCES", "ECONNRESET", ""},
		{"open", "none", "refused for permission"},
		{"ENOENT", "none", "refused for permission"},
		{"", "none", "refused for permission"},
		{"EACCES", "16", "plaintext must reach nothing"},
		{"EACCES", "0", "plaintext must reach nothing"},
		{"EACCES", "", "plaintext must reach nothing"},
	} {
		err := checkChannelFromInside(report(c.key, c.front))
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("key %q, front %q: %v, want %q", c.key, c.front, err, c.want)
		}
	}
}

// The cross-pod check alone: the attempt on the other sandbox's terminator must be in the
// report and unanswered, from a pod other than that sandbox's.
func TestCrossPodCheckRefuses(t *testing.T) {
	const target = "10.244.0.11:9090"
	for _, c := range []struct {
		name        string
		outcomes    map[string]string
		ranIn, peer string
		want        string // "" passes
	}{
		{"unanswered", map[string]string{"tcp " + target: "timeout"}, "k8s-pod-uid:a", "k8s-pod-uid:b", ""},
		{"no route", map[string]string{"tcp " + target: "EHOSTUNREACH"}, "k8s-pod-uid:a", "k8s-pod-uid:b", ""},
		{"open", map[string]string{"tcp " + target: "open"}, "k8s-pod-uid:a", "k8s-pod-uid:b", "reached another sandbox's TLS terminator"},
		{"refused by the other pod", map[string]string{"tcp " + target: "ECONNREFUSED"}, "k8s-pod-uid:a", "k8s-pod-uid:b", "reached another sandbox's TLS terminator"},
		{"reset", map[string]string{"tcp " + target: "ECONNRESET"}, "k8s-pod-uid:a", "k8s-pod-uid:b", "reached another sandbox's TLS terminator"},
		{"not tried", map[string]string{"tcp 1.1.1.1:443": "timeout"}, "k8s-pod-uid:a", "k8s-pod-uid:b", "did not try"},
		{"another port of that pod", map[string]string{"tcp 10.244.0.11:9091": "timeout"}, "k8s-pod-uid:a", "k8s-pod-uid:b", "did not try"},
		{"from the same pod", map[string]string{"tcp " + target: "timeout"}, "k8s-pod-uid:a", "k8s-pod-uid:a", "needs two pods"},
		{"from an unnamed pod", map[string]string{"tcp " + target: "timeout"}, "", "k8s-pod-uid:b", "needs two pods"},
		{"to an unnamed pod", map[string]string{"tcp " + target: "timeout"}, "k8s-pod-uid:a", "", "needs two pods"},
	} {
		err := checkCrossPod(c.outcomes, target, c.ranIn, c.peer)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// The smoke test claims a third sandbox, the peer, before the boundary test; the boundary
// script dials the peer's terminator port; plimsolld reaches the peer (its tier check, and
// nothing else) only after the boundary command; and all three sandboxes are deleted.
func TestSmokeDialsAnotherSandboxsTerminator(t *testing.T) {
	p, api, sd := testProvider(t)
	fakeSmoke(t, p, sd, nil)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	drained(t, p)
	api.mu.Lock()
	var ips []string
	for _, c := range api.created {
		ips = append(ips, api.ips[c.Meta.Name])
	}
	deleted := len(api.deleted)
	api.mu.Unlock()
	if len(ips) != 3 || deleted != 3 {
		t.Fatalf("claims made %v, deleted %d; want three, all deleted", ips, deleted)
	}
	peer, boundaryPod, runnerPod := ips[0], ips[1], ips[2]
	sd.mu.Lock()
	targets, dialed := slices.Clone(sd.targets), slices.Clone(sd.dialed)
	sd.mu.Unlock()
	if want := net.JoinHostPort(peer, "9090"); !slices.Contains(targets, want) {
		t.Fatalf("the boundary script's targets %v leave out the peer's terminator %s", targets, want)
	}
	// The boundary pod's tier check and its command, then the peer's tier check (the
	// positive control), then the runner pod's tier check and its command.
	if want := []string{boundaryPod, boundaryPod, peer, runnerPod, runnerPod}; !slices.Equal(dialed, want) {
		t.Fatalf("pods dialed in order %v, want %v (peer %s)", dialed, want, peer)
	}
}

// A guest that reaches the other sandbox's terminator, or a report that never tried it,
// fails the smoke test, proves nothing, and still deletes every sandbox it claimed. So does
// a peer plimsolld cannot reach after the attempt: the guest's silence then proves nothing.
func TestSmokeRefusesWhatTheCrossPodAttemptDoesNotProve(t *testing.T) {
	peerOutcome := func(outcome string) func(*boundaryReport) {
		return func(r *boundaryReport) {
			for k := range r.Egress {
				if strings.HasSuffix(k, ":9090") {
					if outcome == "" {
						delete(r.Egress, k)
					} else {
						r.Egress[k] = outcome
					}
				}
			}
		}
	}
	for _, c := range []struct {
		name        string
		edit        func(*boundaryReport)
		unreachable bool
		want        string
	}{
		{"open", peerOutcome("open"), false, "reached another sandbox's TLS terminator"},
		{"refused", peerOutcome("ECONNREFUSED"), false, "reached another sandbox's TLS terminator"},
		{"not tried", peerOutcome(""), false, "did not try another sandbox's TLS terminator"},
		{"peer unreachable afterwards", nil, true, "plimsolld could not reach it either"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, api, sd := testProvider(t)
			fakeSmoke(t, p, sd, c.edit)
			if c.unreachable {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				dead := l.Addr().String()
				l.Close()
				p.dialAddr = func(ip string) string {
					api.mu.Lock()
					peer := api.ips[api.created[0].Meta.Name]
					api.mu.Unlock()
					if ip == peer {
						return dead
					}
					return sd.addr(ip)
				}
			}
			err := p.SmokeTest(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			drained(t, p)
			p.mu.Lock()
			proven := p.proven
			p.mu.Unlock()
			api.mu.Lock()
			made, deleted := len(api.created), len(api.deleted)
			api.mu.Unlock()
			if proven != "" || made != 2 || deleted != made {
				t.Fatalf("proven %q, %d claims made, %d deleted; want nothing proven, the peer and the boundary pod made, both deleted", proven, made, deleted)
			}
		})
	}
}

// The runner probe must name a sandboxd below pid 1, the terminator.
func TestSmokeRunnerNamesSandboxdBelowPid1(t *testing.T) {
	for stderr, ok := range map[string]bool{"sandboxd 7\n": true, "x\nsandboxd 12\n": true, "sandboxd 1\n": false, "sandboxd 0\n": false, "": false, "sandboxd 7 8\n": false} {
		m := sandboxdAncestorRE.FindStringSubmatch(stderr)
		if got := m != nil && m[1] != "1"; got != ok {
			t.Errorf("%q: %t", stderr, got)
		}
	}
}
