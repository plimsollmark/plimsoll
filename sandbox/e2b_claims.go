package sandbox

import b "github.com/plimsollmark/plimsoll/internal/boundary"

// e2bClaims is what the e2b provider's SmokeTest (e2b.go) proves, claim by claim, and why it
// does not prove the rest. SmokeTest records each claim as its check passes and fails when
// the record differs from this declaration; docs/isolation-tiers.md prints it.
var e2bClaims = hostedMicroVMClaims("e2b", "sandbox/e2b.go",
	"It creates one real (billed) microVM, a small virtual machine made for one run, as a run does, stages files into it, runs a test program through exactly the path a project step takes, and checks live that <dfn>*egress*</dfn> (traffic leaving the VM) is blocked. "+
		"It also keeps the template's node version: a session's own programs start with `--disable-sigusr1`, which node accepts from v22.14.0 (v23.7.0 in the 23 line, every release from 24), so on an older node a session is refused at its open while single runs, which start none of plimsoll's own node programs, are served. "+
		"E2B's `base` template carried node v20.9.0 when a live check read it on 2026-11-20, and E2B removed that template's published recipe on 2026-10-13; plimsoll's recipe in `e2b/` builds one that serves sessions.",
	map[b.Claim]b.Entry{
		b.WritableBounds: {Steps: []string{"SmokeTest"}, When: "when `SANDBOX_DISK_MB` is set",
			How: "E2B's control plane must report the microVM's disk at or under the configured size: read back, not filled."},
		b.LoopbackOnly: {Not: "the microVM has a network interface, which E2B's <dfn>*deny-all*</dfn> policy (one that blocks every connection no rule allows) holds shut; the requests below test it."},
		b.NoEgress: {Steps: []string{"SmokeTest"},
			How: "HTTPS and HTTP requests to a raw IPv4 address, an HTTPS request to a raw IPv6 address and one to a name must all fail. Only a request that gets an answer counts as egress, since E2B's proxy accepts every IPv4 connection under deny-all and then closes it without forwarding (measured 2026-10-24). A DNS question for example.com, sent in a UDP datagram to an outside IPv4 address, over TCP to that address's port 53, and to an outside resolver through node's own resolver, must get no answer either. Every reply counts as egress except a refusal (DNS code REFUSED or NOTIMP, with no answer): a \"no such name\" counts, so a name that resolves while every connection then fails is caught. A resolver on the internet never refuses example.com, so a refusal comes from the sandbox's own side and resolves nothing. The UDP and resolver questions passed against E2B on 2026-11-24; the TCP question was added the same day and has run only on a docker stand-in."},
		b.ProcessLimit: {Not: "E2B has no per-sandbox process limit, so `SANDBOX_PIDS` is refused."},
		b.MemoryLimit: {Steps: []string{"SmokeTest"}, When: "when `SANDBOX_MEMORY_MB` is set",
			How: "the control plane must report the microVM's memory at or under the configured cap (the template sets it; the setting is a maximum): read back, not measured inside."},
		b.CPULimit: {Steps: []string{"SmokeTest"}, When: "when `SANDBOX_CPUS` is set",
			How: "the control plane must report the microVM's virtual CPUs at or under the configured cap: read back, not measured inside."},
		b.ClosedEnvironment: {Not: "E2B's agent in the microVM (envd) starts each command, and the test does not read the environment a command gets."},
		b.ControlChannel:    {Not: "the channel to the microVM is E2B's agent in it (envd), reached with the sandbox's access tokens."},
		b.TierInside:        {Not: "the vm tier follows from which provider it is, since E2B runs each sandbox in a Firecracker microVM; the test proves the microVM behaves as promised, not that the program running the virtual machine is present."},
		b.SetupReadBack:     {Not: "E2B names a template by its name alone, never by a digest that could be read back, so hardened mode requires the name to be explicit; the resources are read back under the limits above."},
		b.RunPath: {Steps: []string{"SmokeTest"},
			How: "the microVM is created as a run's is, with both access tokens (a secured create); a test program and a step script are staged in one upload, and the script runs it through exactly the path a project step takes, a shell running node, which must exit 0 in the project directory."},
		b.DeadlineKill: {Not: "a run's microVM is killed when the run ends."},
		b.OutputCap:    {Not: "plimsolld caps each stream as it reads it."},
		b.GrantSocket:  {Not: "a grant reaches the microVM's code through plimsolld's <dfn>*egress guard*</dfn>, an HTTPS endpoint of the daemon's that is the only address the run may reach, not through a socket of the host's."},
		b.Teardown:     {Not: "the test's microVM is killed when the test ends, and the orphan sweep removes what a crashed daemon left."},
	})
