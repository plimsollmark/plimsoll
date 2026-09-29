package main

import "github.com/plimsollmark/plimsoll/sandbox/openshell"

// The openshell provider is built here rather than in sandbox.Build: its generated
// OpenShell protocol code registers the protobuf names NVIDIA's OpenShell Go SDK also
// registers, so only this binary links it (sandbox/openshell's package comment).
func init() {
	daemonProviders[openshell.Name] = daemonProvider{
		build: openshell.FromEnv,
		usage: openshellUsage,
		// The gateway sets the process limit for all its sandboxes, so the provider
		// refuses SANDBOX_PIDS; SANDBOX_DISK_MB sizes /tmp.
		hardenedEnvelope: []string{"SANDBOX_MEMORY_MB", "SANDBOX_CPUS", "SANDBOX_DISK_MB"},
		pinnedImages:     true,
	}
}

const openshellUsage = `
  SANDBOX_PROVIDER=openshell NVIDIA OpenShell sandboxes through a gateway: the
                             docker compute driver only, reported as container
                             isolation (hardened mode refuses it). Each run creates
                             a sandbox with no network and deletes it. All five are
                             required (the gateway uses mutual TLS):
  SANDBOX_OPENSHELL_GATEWAY_URL
                             the gateway, https://host:port with no path
  SANDBOX_OPENSHELL_CA_FILE  PEM CA the gateway's certificate must chain to
  SANDBOX_OPENSHELL_CERT_FILE / SANDBOX_OPENSHELL_KEY_FILE
                             PEM client certificate and key
  SANDBOX_OPENSHELL_IMAGE    the image every sandbox boots; it must carry node, sh
                             and /runner.mjs, as plimsoll/sandbox does (@sha256:
                             when SANDBOX_REQUIRE_PINNED_IMAGES=1). openshell
                             honors SANDBOX_MEMORY_MB and SANDBOX_CPUS (default 256
                             MiB and 1 CPU, since OpenShell's own default is no
                             limit). SANDBOX_DISK_MB mounts each run's /tmp, the
                             only writable directory, as a noexec tmpfs of that
                             size (never a session's, whose files a suspend would
                             discard); the gateway must set allow_driver_config =
                             true. Unset, /tmp is bounded only by the host's disk.
                             SANDBOX_PIDS fails startup,
                             because the gateway sets it for all its sandboxes
`
