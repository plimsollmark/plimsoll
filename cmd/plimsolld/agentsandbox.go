package main

import (
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/agentsandbox"
)

// The agentsandbox provider is built here rather than in sandbox.Build, for the same
// reason as openshell: its generated process-service code registers protobuf names
// agent-sandbox's own Go SDK also registers (sandbox/agentsandbox's package comment).
func init() {
	providers[agentsandbox.Name] = providerDescriptor{
		build: agentsandbox.FromEnv,
		usage: agentsandboxUsage,
		// The template sets memory, CPU and the volumes, which the read-back holds to
		// these; the kubelet sets the process limit, so the provider refuses SANDBOX_PIDS.
		hardenedEnvelope: []string{"SANDBOX_MEMORY_MB", "SANDBOX_CPUS"},
		// Below the vm tier each volume is a tmpfs the kubelet sizes to its limit, so the
		// disk budget is enforced and required; under Kata no volume keeps its limit and
		// the provider refuses SANDBOX_DISK_MB.
		hardenedEnvelopeAt: func(tier sandbox.IsolationClass) []string {
			if tier == sandbox.IsolationVM {
				return nil
			}
			return []string{"SANDBOX_DISK_MB"}
		},
		pinnedImages: true,
	}
}

const agentsandboxUsage = `
  SANDBOX_PROVIDER=agentsandbox
                             Kubernetes agent-sandbox (v1.0.7): one SandboxClaim per
                             run on a warm pool, deleted after. plimsolld runs in the
                             cluster, since it reaches each pod's sandboxd at the
                             pod's address. The tier is read from the runtime class's
                             handler (runsc: kernel, runc: container, kata, kata-clh
                             and kata-clh-runtime-rs: vm; anything else refused), proven by
                             the startup smoke test and checked again in every pod.
  SANDBOX_AGENTSANDBOX_API_SERVER
                             the API server (default https://kubernetes.default.svc)
  SANDBOX_AGENTSANDBOX_CA_FILE / SANDBOX_AGENTSANDBOX_TOKEN_FILE
                             its CA and a bearer token file, read at every request
                             (default: the pod's service account files under
                             /var/run/secrets/kubernetes.io/serviceaccount)
  SANDBOX_AGENTSANDBOX_NAMESPACE
                             the namespace of the pool, its template and every claim
  SANDBOX_AGENTSANDBOX_WARM_POOL
                             the SandboxWarmPool each run claims from
  SANDBOX_AGENTSANDBOX_RUNTIME_CLASS
                             the RuntimeClass the template's pods must name
  SANDBOX_AGENTSANDBOX_IMAGE the image the template's one container must run, as the
                             template writes it (@sha256: when
                             SANDBOX_REQUIRE_PINNED_IMAGES=1)
  SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE
                             a file holding the token sandboxd checks; the template
                             starts sandboxd with --auth-token-sha256 of it.
                             SANDBOX_MEMORY_MB and SANDBOX_CPUS must equal the
                             template's limits (default 256 MiB and 1 CPU);
                             SANDBOX_DISK_MB, when set, bounds the sum of its volumes'
                             size limits; SANDBOX_PIDS fails startup, because the
                             kubelet sets the process limit
`
