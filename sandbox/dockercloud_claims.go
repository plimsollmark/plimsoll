package sandbox

import b "github.com/plimsollmark/plimsoll/internal/boundary"

// dockerCloudClaims is what the dockercloud provider's SmokeTest (dockercloud_lifecycle.go)
// proves, claim by claim, and why it does not prove the rest. SmokeTest records each claim
// as its check passes and fails when the record differs from this declaration;
// docs/isolation-tiers.md prints it.
var dockerCloudClaims = hostedMicroVMClaims("dockercloud", "sandbox/dockercloud_lifecycle.go",
	"It checks the token's permissions, then creates one throwaway (billed) sandbox from Docker Cloud Sandboxes as a run does, reads its network policy back, and runs a test program, a hung command and a flood of output through the exact path a project step takes ([dockercloud.md](dockercloud.md#startup-smoke-test)).",
	map[b.Claim]b.Entry{
		b.WritableBounds: {Not: "the service has no disk control, so `SANDBOX_DISK_MB` is refused."},
		b.LoopbackOnly:   {Not: "the microVM has a network interface, which the deny-all policy holds shut; the requests below test it."},
		b.NoEgress: {Steps: []string{"SmokeTest"},
			How: "from inside, HTTPS and HTTP requests to a raw IPv4 address, an HTTPS request to a raw IPv6 address and one to a name must all fail, and the three DNS questions of the `e2b` entry above must get no reply but a refusal. Docker Cloud answers every DNS question on port 53, to any address, with REFUSED and no answer (measured 2026-11-24), so the question reaches Docker's side of the sandbox and nothing is resolved; what Docker's side does with the names it refuses cannot be seen from inside. The startup test with all three questions passed against Docker Cloud on 2026-11-24."},
		b.ProcessLimit: {Not: "the service has no process limit, so `SANDBOX_PIDS` is refused."},
		b.MemoryLimit: {Steps: []string{"SmokeTest"},
			How: "the service's account of the new sandbox must give its memory at or under what was requested (the smallest size when none is configured): read back, not measured inside."},
		b.CPULimit: {Steps: []string{"SmokeTest"},
			How: "the service's account of the new sandbox must give its CPUs at or under what was requested: read back, not measured inside."},
		b.ClosedEnvironment: {Not: "the service starts each command, and the test does not read the environment a command gets."},
		b.ControlChannel:    {Not: "the channel to the sandbox is the service's own endpoint for it, reached with the token."},
		b.TierInside:        {Not: "the vm tier follows from which provider it is, since Docker Cloud Sandboxes runs each sandbox in a microVM; the test proves the policy that blocks every connection and the blocked egress, not the program running the virtual machine."},
		b.SetupReadBack: {Steps: []string{"SmokeTest"},
			How: "the token's permissions are checked first; the new sandbox's endpoint must be one the token may be sent to, and a pinned image must be the digest it booted (under the REST API, which reports none, the pinned reference the service recorded); and its effective network policy, read back, must be deny-all with nothing allowed."},
		b.RunPath: {Steps: []string{"SmokeTest"},
			How: "the project directory is made, a test program and a step script are uploaded, and the script runs it through the exec wrapper around a shell, as a project step runs, which must exit 0 with a node version in the project directory."},
		b.DeadlineKill: {Steps: []string{"SmokeTest"},
			How: "a hung step, in a step's own shape (an outer shell, then the script's), must really be ended at a 1 second limit: busybox's `timeout`, which the image's steps run under, fails open when the kernel refuses its kill."},
		b.OutputCap: {Steps: []string{"SmokeTest"},
			How: "a flood of output must be cut at exactly the cap, with the cut reported and the command failed."},
		b.GrantSocket: {Not: "a grant reaches the sandbox's code through plimsolld's egress guard, not through a socket of the host's."},
		b.Teardown:    {Not: "the test's sandbox is destroyed when the test ends, and the orphan sweep removes what a crashed daemon left."},
	})
