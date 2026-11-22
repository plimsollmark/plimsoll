package main

import (
	"github.com/plimsollmark/plimsoll/internal/settings"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/agentsandbox"
)

// The agentsandbox provider is built here rather than in sandbox.Build, for the same
// reason as openshell: its generated process-service code registers protobuf names
// agent-sandbox's own Go SDK also registers (sandbox/agentsandbox's package comment).
func init() {
	providers[agentsandbox.Name] = providerDescriptor{
		build: agentsandbox.FromEnv,
		// The template sets memory, CPU and the volumes, which the read-back holds to
		// these; the kubelet sets the process limit, so the provider refuses SANDBOX_PIDS.
		hardenedEnvelope: []settings.Size{settings.MemoryMB, settings.CPUs},
		// Below the vm tier each volume is a tmpfs the kubelet sizes to its limit, so the
		// disk budget is enforced and required; under Kata no volume keeps its limit and
		// the provider refuses SANDBOX_DISK_MB.
		hardenedEnvelopeAt: func(tier sandbox.IsolationClass) []settings.Size {
			if tier == sandbox.IsolationVM {
				return nil
			}
			return []settings.Size{settings.DiskMB}
		},
		pinnedImages: true,
		// The tier is read from the runtime class each check finds (Provider.IsolationClass),
		// and is unknown until the first.
		tierFromChecks: func(sandbox.Sandbox) bool { return true },
		// The channel to sandboxd is TLS, but every pod's terminator serves the same
		// certificate, so it proves the peer is a plimsoll sandbox pod, not the pod dialed
		// (Claude Security scan, 2026-11-07, finding F1). Someone who can rewrite traffic
		// on the pod network could send one caller's run into another caller's pod. The
		// daemon cannot see whether the CNI or a mesh authenticates that path, so hardened
		// mode requires the operator to state it, until each pod has a key of its own.
		hardened: func(getenv func(string) string, fail func(string, ...any), bad func(error)) {
			encrypted, err := settings.AgentsandboxEncryptedPodNetwork.Get(getenv)
			if err != nil {
				bad(err)
			} else if !encrypted {
				fail("hardened mode requires SANDBOX_AGENTSANDBOX_ENCRYPTED_POD_NETWORK=1: every sandbox pod's TLS certificate is the same, so the channel proves the peer is a plimsoll sandbox pod, not the pod this run was sent to; the pod network between plimsolld and the sandbox pods must be authenticated and encrypted (a CNI with WireGuard or IPsec, or a service mesh with mutual TLS) before a result can be trusted against anyone who can rewrite traffic on that path")
			}
		},
	}
}
