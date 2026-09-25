# The Docker Cloud Sandboxes provider

`SANDBOX_PROVIDER=dockercloud` runs each snippet or project in a Docker Cloud
Sandboxes microVM: a hardware-virtualized VM, reported as the `vm` tier. The code is
[sandbox/dockercloud.go](../sandbox/dockercloud.go).

## How it was built and verified

It is written against Docker's published API contract (the
`github.com/docker/sandboxes-api` protobuf API, v0.36.0) and spoken by hand as
Connect JSON over `net/http`, so it adds no module to the dependency graph. The live
suite (`make audit DOCKERCLOUD=1`) passed against the real service on 2026-09-24:
smoke test, snippet, project, resource bounds, and orphan listing.

## Three things an operator must set up

That live run surfaced three requirements the published contract does not state:

- **Token exchange.** The sandbox API refuses a personal access token. The provider
  exchanges `DOCKER_SBX_USERNAME` plus `DOCKER_SBX_TOKEN` at Docker Hub
  (`SANDBOX_DOCKERCLOUD_AUTH_URL`) for a short-lived bearer.
- **Deny-all account policy.** The account's cloud network policy must default to
  deny-all (`sbx --cloud policy init deny-all`), because a create request carrying
  an inline policy fails.
- **A single-platform image digest.** A pinned `SANDBOX_DOCKERCLOUD_IMAGE` must name
  its linux/amd64 manifest digest, not a multi-platform index, because the cloud
  reports the manifest it booted and the provider compares against that.

## What each run does

1. Creates a sandbox from the one configured raw OCI image, pinned to linux/amd64,
   named with a per-instance prefix that is tracked before the create call.
2. Reads the sandbox's effective network policy back through the published contract
   and refuses to run unless it is deny-all with exactly the rules the run is
   entitled to: none for a run without a grant, the guard's `host:443` for a grant run.
3. Runs every guest command under an in-guest wrapper (`timeout -s KILL`, each output
   stream capped by `head -c`), because the exec API has no timeout and no output
   bound. The host bounds the response as well. A guest that floods its output is a
   failed user run with the truncation flags set, not an infrastructure error.
4. Deletes the sandbox on every exit path. The cloud TTL with delete-on-timeout is
   the backstop, and `ReconcileOrphans` deletes any prefixed sandbox the process is
   not tracking.

Resources: `SANDBOX_MEMORY_MB` and whole `SANDBOX_CPUS` are requested at create and
verified after it. `SANDBOX_PIDS` and `SANDBOX_DISK_MB` are rejected, since the
service has no control for them.

## Host-API grants

Grants are supported when `SANDBOX_DOCKERCLOUD_GUARD_URL` is configured and return
`ErrUnsupported` otherwise. They use the same shared egress guard as E2B, which
delegates to the shared broker, with two differences an operator must know:

- **The network rule is applied outside the published contract.** A grant run's
  single rule (the guard's `host:443`) goes through `PUT /sandboxes/{id}/network-policy`,
  the REST call the `sbx` CLI makes (base URL `SANDBOX_DOCKERCLOUD_POLICY_URL`). The
  read-back in step 2 still goes through the published contract.
- **The guest holds its own run's guard credential.** Docker's proxy injects
  credentials only for its fixed list of services, so the provider cannot keep the
  guard credential outside the VM the way E2B's proxy does. That credential is per
  run, valid only at the guard, only for that run's frozen grant, and dead when the
  run ends. The downstream API credential never enters the VM.

## Startup smoke test

`CapabilityService.GetCapabilities` must list, when it lists permissions at all, the
read, create, delete and network-policy-read permissions a run needs. Exec and file
permissions are not required: the cloud does not list them for a Cloud Sandboxes
token, yet serves them. Then one throwaway sandbox must come up with a deny-all
effective policy, accept a directory and a file upload, and run a probe through the
exact project-step path (the exec wrapper around `sh <script>`). That proves `node`,
`timeout` and `head` are present, the step's working directory is honored, and
egress is denied from inside the guest.

The smoke test creates a billable sandbox, so it runs once at startup and never on
the unauthenticated `/readyz` path, which checks configuration only.
