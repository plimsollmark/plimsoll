package wslc

import b "github.com/plimsollmark/plimsoll/internal/boundary"

// claims is what the wslc provider's SmokeTest (smoke.go) proves, claim by claim, in both
// modes, and why it does not prove the rest. SmokeTest records each claim as its check
// passes and fails when the record differs from this declaration; docs/isolation-tiers.md
// prints it.
var claims = b.Declare(b.Declaration{
	Provider: Name,
	Source:   "sandbox/wslc/smoke.go",
	Startup:  "It inspects the image, then runs a boundary test as a runner step through exactly the path a run takes and checks what the container it got can do; in the per-run mode it does that in two fresh virtual machines, each torn down after ([wslc.md](wslc.md#startup-smoke-test-and-readiness)).",
	Entries: map[b.Claim]b.Entry{
		b.WritablePlaces: {Steps: []string{"checkBoundary"},
			How: "a write is tried at every mount point and, walking the whole filesystem, at every folder and file the guest user looks able to write: only the four tmpfs mounts (`/tmp`, `/var/tmp`, `/dev/shm` and `/work`) may accept one, and the walk must not stop short. WSL containers cannot mount the root read-only, so this walk is what shows the guest user cannot write to it; a folder the guest user cannot list is not entered (the startup log counts them)."},
		b.WritableBounds: {Steps: []string{"checkBoundary"},
			How: "each of the four must be a tmpfs (a filesystem held in memory) of its configured size, marked `noexec`, `nosuid` and `nodev`."},
		b.LoopbackOnly: {Steps: []string{"checkBoundary"},
			How: "the container's list of network interfaces must be loopback alone."},
		b.NoEgress: {Steps: []string{"checkBoundary"},
			How: "a TCP connection to two public addresses and the cloud metadata address must not connect."},
		b.GuestUser: {Steps: []string{"checkBoundary"},
			How: "every user and group ID of the code must be the guest user's, with no other group."},
		b.NoCapabilities: {Steps: []string{"checkBoundary"},
			How: "every capability set of the code, the bounding set included, must be empty."},
		b.SeccompFilter: {Steps: []string{"checkBoundary"},
			How: "the code's status must say seccomp mode 2, docker's default filter (WSL containers offer no choice of profile); with gVisor, whose own reading differs, every gVisor kernel process in the VM must run under a filter of its own instead."},
		b.GuestGuard: {Not: "not applied yet: the guest guard is built for the docker provider first, and this provider's commands do not start behind it."},
		b.ProcessLimit: {Steps: []string{"checkBoundary"},
			How: "the code's process limit (`--ulimit nproc`, `SANDBOX_WSLC_NPROC`), and its open-file and core-file limits, must be the configured ones. The process limit counts every process of the guest user in the VM, not one run's: WSL containers have no `--pids-limit`, so `SANDBOX_PIDS` fails startup."},
		b.MemoryLimit: {Steps: []string{"checkBoundary"},
			How: "the container's `memory.max` must be the configured limit; with gVisor, the limit on the cgroup that holds gVisor's processes, read in the VM."},
		b.CPULimit: {Not: "`--cpus` is passed to WSL containers, and the test reads only the memory limit back."},
		b.FixedResolver: {Steps: []string{"checkBoundary"},
			How: "the container's resolver settings may name no name server but loopback and no search domain (`--dns 127.0.0.1 --dns-search .`)."},
		b.ClosedEnvironment: {Steps: []string{"checkBoundary"},
			How: "a step's environment may hold no variable but the image's and those the runner and a step's shell set."},
		b.ControlChannel: {Steps: []string{"checkBoundary"},
			How: "the project runner at `/usr/local/libexec/plimsoll-helper` must be a regular file, root's and writable by no one else, whose SHA-256 is that of the copy inside plimsolld (read by the test's step inside the image, so this proves the image is one built with that runner, not that a hostile image could not lie), and a step's open of the runner's memory must be refused."},
		b.NoHostShare: {Steps: []string{"checkBoundary"},
			How: "the container's mount table may hold no 9p, virtiofs, drvfs, SMB or FUSE mount, the ways a Windows folder reaches Linux, and the container must lack the GPU device `/dev/dxg`, which every VM of WSL containers has."},
		b.TierInside: {Steps: []string{"checkBoundary"},
			How: "the container's kernel release and boot ID must be those of the VM the test read; in the per-run mode that VM's boot ID must be one never seen before (not the other test VM's, the shared mode's VM's or the WSL distribution's), so each run lands in a virtual machine of its own. With gVisor in the VMs, the kernel and boot ID must be gVisor's own, and the VM must show the container running under `runsc`. Microsoft states that WSL is not a security sandbox for running untrusted code; that sentence goes with the tier."},
		b.SetupReadBack: {Steps: []string{"SmokeTest", "smokePerRun"},
			How: "WSL must be at least the release whose `wslc` can drop capabilities, and the image must be a Linux image with a `sha256` ID, no `VOLUME`, its pinned digest among its repository digests and no environment variable the C library or loader reads at startup; in the per-run mode the run root must be this process's alone and writable by no one else, and so must the template's folder and disk file."},
		b.RunPath: {Steps: []string{"checkProbe"},
			How: "the boundary test runs as a project step through the runner, which must send an authenticated report of a completed step."},
		b.DeadlineKill: {Not: "the runner ends a step at its time limit, and a run that does not end cleanly has its container force-removed (in the per-run mode its whole VM is torn down)."},
		b.OutputCap:    {Not: "plimsolld caps each stream of a command as it reads it."},
		b.GrantSocket:  {Not: "grants are not offered by this provider."},
		b.Languages:    {Not: "the provider states JavaScript alone, the language of the runner's node, which runs the boundary test."},
		b.Teardown: {Steps: []string{"smokeSession"}, When: "in the per-run mode",
			How: "each of the two test VMs is torn down as a run's is, and its directory must be gone after; the shared mode's runs share one VM, which no run tears down."},
	},
})
