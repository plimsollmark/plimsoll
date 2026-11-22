package agentsandbox

import b "github.com/plimsollmark/plimsoll/internal/boundary"

// claims is what the agentsandbox provider's SmokeTest (smoke.go) proves, claim by claim,
// and why it does not prove the rest. SmokeTest records each claim as its check passes and
// fails when the record differs from this declaration; docs/isolation-tiers.md prints it.
var claims = b.Declare(b.Declaration{
	Provider: Name,
	Source:   "sandbox/agentsandbox/smoke.go",
	Startup:  "It claims three sandboxes from the warm pool as every run claims them: in the first a snippet tests the wall from inside, and dials the second, which runs no code; in the third a project step tests the channels of the runner and of sandboxd (the agent in the pod that starts its processes); the pool, template, policies and runtime class must read the same before and after.",
	Entries: map[b.Claim]b.Entry{
		b.WritablePlaces: {Steps: []string{"smokeBoundary"},
			How: "a write is tried at every path the code can reach (at least 100 paths): it may succeed only beneath the template's emptyDir mounts and `/dev/shm`, nowhere else may it even create a file (message queues in `/dev/mqueue` excepted, while the guest's allowance for them is small and finite), no file outside them may open for append, and `/work` must accept writes."},
		b.WritableBounds: {Steps: []string{"smokeBoundary"},
			How: "below the vm tier each volume is filled until it refuses a write (ENOSPC) at its size limit; at the vm tier, where Kata keeps no size limit, each writable root must be a tmpfs (a filesystem held in memory) of the VM's own kernel, so it fills the VM's memory, never the node's disk; at every tier no mount may sit beneath a writable root, where the root's limit would not cover it."},
		b.LoopbackOnly: {Not: "a pod has a network interface of its own; the test records the interfaces it sees for the startup log, and the connection attempts below hold the pod's network shut."},
		b.NoEgress: {Steps: []string{"smokeBoundary"},
			How: "connections to public IPv4 and IPv6 addresses, the cloud metadata address, the API server, the node's kubelet and another sandbox pod's TLS terminator port must time out or be unreachable, never open or refused (a refusal is an answer, so the packet left the pod). The other sandbox is claimed for the test, and plimsolld reaches its terminator over TLS after the attempt, so the port was listening."},
		b.GuestUser: {Steps: []string{"smokeBoundary"},
			How: "every user and group ID of the code must be the guest user's, with no supplementary group."},
		b.NoCapabilities: {Steps: []string{"smokeBoundary"},
			How: "the code must hold no effective or permitted capability, and run with `no_new_privs`."},
		b.SeccompFilter: {Steps: []string{"smokeBoundary"}, When: "at the container tier",
			How: "the code's status must say seccomp mode 2, a filter in force (it proves a filter, not which one). Under gVisor the status is gVisor's own emulation, which says nothing of the host's filter, so the kernel tier is held to its kernel log instead (`tier-inside`)."},
		b.GuestGuard:   {Not: "not applied yet: the guest guard is built for the docker provider first, and this provider's commands do not start behind it."},
		b.ProcessLimit: {Not: "a pod's process limit is the kubelet's on each node, which the API does not show, so `SANDBOX_PIDS` is refused."},
		b.MemoryLimit:  {Not: "the read-back holds the template's container to the configured memory limit, and the kubelet applies it to the pod."},
		b.CPULimit:     {Not: "the read-back holds the template's container to the configured CPU limit, and the kubelet applies it to the pod."},
		b.FixedResolver: {Steps: []string{"smokeBoundary"},
			How: "the code's resolver settings must be the one loopback name server and nothing else."},
		b.ClosedEnvironment: {Steps: []string{"smokeBoundary"},
			How: "the code's environment must hold PATH and HOME alone."},
		b.ControlChannel: {Steps: []string{"smokeBoundary", "smokeRunner"},
			How: "from inside the pod, sandboxd must refuse a process start without its token and one with a wrong token (gRPC status 16, unauthenticated), the code's open of the TLS key must be refused for permission, and a cleartext start sent to the TLS terminator's port must get no gRPC status; and a project step must be refused when it opens the runner's plan and report descriptors and memory, and sandboxd's and pid 1's memory, environment and input. Before any project runs, the project runner at `/usr/local/libexec/plimsoll-helper` must be a regular file, root's and writable by no one else, whose SHA-256 is that of the copy inside plimsolld (read by the guest inside the image, so this proves the image is one built with that runner, not that a hostile image could not lie)."},
		b.NoHostShare: {Not: "the read-back refuses a template that shares the node's own network, process list or inter-process communication, or exposes a host port, and allows no volume but memory-backed emptyDir ones."},
		b.TierInside: {Steps: []string{"smokeBoundary"}, When: "at the kernel and vm tiers",
			How: "at the kernel tier the first line of the code's kernel log must be gVisor's own boot line exactly, and at the vm tier a Linux kernel's boot line: a runtime class's handler is only a name in the node's configuration. This is no proof from the hardware, but a handler that names one runtime and a guest that sees another kernel is refused. Every pod, the test's included, is also held at the vm tier to a boot ID that is not its node's."},
		b.SetupReadBack: {Steps: []string{"SmokeTest"},
			How: "Preflight reads the warm pool, its template (whose pod spec must pass every pod's checks) and the runtime class; the test binds the network policies over its sandboxes, and the class, before its three sandboxes, and requires them and the template to read the same after."},
		b.RunPath: {Steps: []string{"smokeBoundary", "smokeRunner"},
			How: "the boundary test runs as a snippet through the run path itself, and the runner test as a project whose one step must complete."},
		b.DeadlineKill: {Not: "a run's sandbox is deleted when the run ends, which ends every process in its pod."},
		b.OutputCap:    {Not: "plimsolld caps each stream of a command as it reads it."},
		b.GrantSocket:  {Not: "grants are not supported yet."},
		b.Languages:    {Not: "the provider states no languages of its own, and the image's node, which the runner needs, runs both tests above."},
		b.Teardown:     {Not: "each sandbox is deleted after its run, and every claim carries this instance's label, by which the orphan sweep finds what a crashed daemon left."},
	},
})
