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
		// sandboxd serves no TLS, so its token, the code, each run's plan with its report
		// key, and every result cross the pod network as cleartext HTTP/2. The network
		// policy decides who may connect, not who may watch or rewrite the traffic. The
		// daemon cannot see whether the CNI or a mesh encrypts that path, so hardened mode
		// requires the operator to state it (Claude Security scan, 2026-10-27).
		hardened: func(getenv func(string) string, fail func(string, ...any), bad func(error)) {
			encrypted, err := sandbox.BoolFromEnv(getenv, "SANDBOX_AGENTSANDBOX_ENCRYPTED_POD_NETWORK")
			if err != nil {
				bad(err)
			} else if !encrypted {
				fail("hardened mode requires SANDBOX_AGENTSANDBOX_ENCRYPTED_POD_NETWORK=1: sandboxd's channel is cleartext HTTP/2 carrying its token, the code, each run's report key and the results, so the pod network between plimsolld and the sandbox pods must be encrypted (a CNI with WireGuard or IPsec, or a service mesh with mutual TLS) before a result can be trusted against anyone on that path")
			}
		},
	}
}

const agentsandboxUsage = `
  SANDBOX_PROVIDER=agentsandbox
                             Kubernetes agent-sandbox (v1.0.7): one SandboxClaim per
                             run on a warm pool, deleted after. plimsolld runs in the
                             cluster, since it reaches each pod's sandboxd at the
                             pod's address. The tier is read from the runtime class's
                             handler (runsc and any declared below: kernel, runc:
                             container, kata, kata-clh and kata-clh-runtime-rs: vm;
                             anything else refused), proven by the startup smoke
                             test and checked again in every pod.
                             The class the smoke test ran on (its UID, handler,
                             overhead and scheduling) is the only one accepted after;
                             a class changed since is refused until a restart.
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
  SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS
                             a comma list of further handler names this operator
                             declares as gVisor (a containerd runtime of its own for
                             the runsc shim, such as one with a debug log). Each is
                             the kernel tier only, held to gVisor's boot line by the
                             smoke test and in every pod exactly as runsc is, so a
                             name that maps to another runtime is refused before
                             code runs. Each must be a DNS label; an empty entry, a
                             repeat, or a handler named above fails startup.
                             Hardened mode accepts it
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
  SANDBOX_AGENTSANDBOX_ENCRYPTED_POD_NETWORK
                             =1 states that the pod network between plimsolld and
                             the sandbox pods is encrypted (a CNI with WireGuard or
                             IPsec, or a mesh with mutual TLS). sandboxd's channel
                             is cleartext HTTP/2 carrying its token, the code, each
                             run's report key and the results; hardened mode
                             requires the statement
`
