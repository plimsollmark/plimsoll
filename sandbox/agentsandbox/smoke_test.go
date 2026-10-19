package agentsandbox

import (
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
