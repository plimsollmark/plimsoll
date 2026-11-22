package openshell

import b "github.com/plimsollmark/plimsoll/internal/boundary"

// claims is what the openshell provider's SmokeTest (smoke.go) proves, claim by claim, and
// why it does not prove the rest. SmokeTest records each claim as its check passes and
// fails when the record differs from this declaration; docs/isolation-tiers.md prints it.
var claims = b.Declare(b.Declaration{
	Provider: Name,
	Source:   "sandbox/openshell/smoke.go",
	Startup:  "It creates one throwaway sandbox as a run does and checks from inside it the writes, the network and the limits; then it round-trips a project at the size ceiling through the runner and kills a hung command.",
	Entries: map[b.Claim]b.Entry{
		b.WritablePlaces: {Steps: []string{"smokeProbe"},
			How: "a write is tried at every path the code can reach (each mount point, the standard top-level directories and every directory beneath them that can be listed, at least 100 paths): only `/tmp` and what lies beneath it may accept one, which shows Landlock (the kernel's path rules for a process) enforcing the policy."},
		b.WritableBounds: {Steps: []string{"smokeProbe"}, When: "when `SANDBOX_DISK_MB` is set",
			How: "`/tmp` must be a tmpfs (a filesystem held in memory) of exactly the configured size, marked `noexec`, `nosuid` and `nodev`."},
		b.LoopbackOnly: {Steps: []string{"smokeProbe"},
			How: "the sandbox's list of network interfaces must be loopback alone."},
		b.NoEgress: {Steps: []string{"smokeProbe"},
			How: "connections to two IPv4 and two IPv6 addresses, and an HTTPS request by name, must go unanswered or be refused inside the sandbox; a refusal or a TLS failure from outside counts as egress."},
		b.GuestUser:      {Not: "every command runs as the gateway's sandbox user, which plimsoll does not choose."},
		b.NoCapabilities: {Not: "the gateway, not plimsoll, sets what its sandbox user holds."},
		b.SeccompFilter:  {Not: "the gateway, not plimsoll, sets the sandbox's seccomp filter; plimsoll's policy requires Landlock, so a command fails where the kernel lacks it."},
		b.GuestGuard:     {Not: "not applied yet: the guest guard is built for the docker provider first, and this provider's commands do not start behind it."},
		b.ProcessLimit:   {Not: "the gateway sets one process limit for all of its sandboxes, so `SANDBOX_PIDS` is refused; the test reads the sandbox's `pids.max` only for the startup log."},
		b.MemoryLimit: {Steps: []string{"smokeProbe"},
			How: "the sandbox's own cgroup (the kernel's record of a group of processes' limits) must carry the requested memory limit, `memory.max`."},
		b.CPULimit: {Steps: []string{"smokeProbe"},
			How: "the sandbox's own cgroup must carry the requested CPU quota, `cpu.max`."},
		b.FixedResolver:     {Not: "the policy has no network rules, so no name is resolved outside the sandbox; the test records what a name resolves to inside (an address the gateway makes up, not a real answer) only for the startup log."},
		b.ClosedEnvironment: {Not: "a v0.1.2 gateway hands every command a fixed set of variables of its own (HOME, PATH, its CA settings, `OPENSHELL_SANDBOX`, TERM, USER), never the image's (measured 2026-10-03), and plimsoll's own programs start under `env -i`."},
		b.ControlChannel: {Steps: []string{"smokeRunner"},
			How: "the project's step must be refused when it opens the runner's plan and report descriptors and its memory."},
		b.NoHostShare: {Not: "the gateway decides what its docker driver mounts into a sandbox; the write sweep above would find a writable folder of the host's, not a read-only one."},
		b.TierInside:  {Not: "the container tier rests on the gateway's own report that it creates sandboxes with docker. The gateway does not say which runtime its docker uses, so plimsoll reports container even where that is gVisor."},
		b.SetupReadBack: {Steps: []string{"SmokeTest"},
			How: "the gateway must report that it creates sandboxes with its docker compute driver (any other driver is refused), and the test's sandbox is created as a run's is, its policy and limits read back exactly."},
		b.RunPath: {Steps: []string{"smokeRunner"},
			How: "a project at the 4 MiB size ceiling must round-trip through the runner by the project exec path, its plan on standard input, and the step's output file must have the length and SHA-256 the host computed."},
		b.DeadlineKill: {Steps: []string{"smokeKill"},
			How: "a command that never ends, and a second process it starts, must both be gone, as a second command counts them, once the first command's exec stream is cancelled: the mechanism behind every timeout."},
		b.OutputCap:   {Not: "plimsolld caps each stream of a command as it reads it."},
		b.GrantSocket: {Not: "a grant reaches the sandbox through a relay inside it that plimsolld connects over the gateway's exec stream, not through a socket mounted from the host."},
		b.Languages: {Steps: []string{"smokeLanguages"},
			How: "each interpreter is run once; node must answer, since snippets, the relays and a session's programs are node, and only the languages that answer are stated."},
		b.Teardown: {Not: "the test's sandbox is deleted when the test ends, and every sandbox carries a label with its lifetime, by which the orphan sweep removes one that outlives its run."},
	},
})
