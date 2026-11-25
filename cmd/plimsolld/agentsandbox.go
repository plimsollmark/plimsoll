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
		// Each pod serves a certificate of its own, naming that pod's UID, and the channel
		// refuses any other in the handshake, so a run cannot be sent to another pod than
		// the one read (security scan, 2026-11-07, finding F1). The provider requires
		// the trust domain in every mode; hardened mode states it as its own rule, so a
		// later default could not quietly drop the check.
		hardened: func(getenv func(string) string, fail func(string, ...any), _ func(error)) {
			if settings.AgentsandboxSandboxdTrustDomain.Get(getenv) == "" {
				fail("hardened mode requires SANDBOX_AGENTSANDBOX_SANDBOXD_TRUST_DOMAIN: the trust domain of the identity each sandbox pod's own certificate carries, which the channel checks against the pod plimsolld read before anything is sent")
			}
		},
	}
}
