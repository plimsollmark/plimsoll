# The Docker Cloud Sandboxes provider

`SANDBOX_PROVIDER=dockercloud` runs each snippet or project on <dfn>*Docker Cloud
Sandboxes*</dfn>, Docker's hosted sandbox service, in a <dfn>*microVM*</dfn>: a small
virtual machine made for one run, kept apart from others by the processor's
<dfn>*hardware virtualization*</dfn>. This <dfn>*provider*</dfn> (a provider is the
backend that runs the code) reports it as the `vm` <dfn>*isolation tier*</dfn>, the
strongest of the four levels. The code is
[sandbox/dockercloud.go](../sandbox/dockercloud.go).

## How it was built and verified

It is written against the API Docker released as `github.com/docker/sandboxes-api`
v0.36.0, a <dfn>*protobuf*</dfn> API (protobuf is Google's schema format for messages).
The provider speaks that API by hand, as <dfn>*Connect*</dfn> JSON over `net/http`
(Connect is an RPC protocol that carries JSON or protobuf over ordinary HTTP), so it
adds no module to the dependency graph. The live suite (`make audit DOCKERCLOUD=1`)
passed against the real service at `https://sandboxes.connect.docker.com/sbx` on
2026-09-24: smoke test, snippet, project, resource bounds, and listing leftover
sandboxes (orphans). "The published contract" below means that release.

**Docker's documentation has since moved on.** On 2026-10-04 Docker's API reference
documents a different, experimental REST API at `https://connect.docker.com/sandboxes`:
`POST /v1/sandboxes` to create, and `DELETE /v1/sandboxes/{id}` by ID only, with a
required `If-Match` header
([EXTERNAL · official docs ↗](https://docs.docker.com/reference/api/sandboxes/latest/operations/createSandbox/)).
This provider does not speak that API, and whether the Connect endpoint above still
answers has not been checked since 2026-09-24. Before relying on this provider, run the
live suite (it creates billable microVMs, a few cents' worth); a failure there is the
signal that the provider needs porting.

## Three things an operator must set up

That live run surfaced three requirements the published contract does not state:

- **Token exchange.** The sandbox API refuses a personal access token. The provider
  exchanges `DOCKER_SBX_USERNAME` plus `DOCKER_SBX_TOKEN` at Docker Hub
  (`SANDBOX_DOCKERCLOUD_AUTH_URL`) for a short-lived bearer token.
- **<dfn>*Deny-all*</dfn> account policy.** The account's cloud network policy, the
  rules for which connections a sandbox may make, must default to deny-all: every
  connection is blocked unless a rule allows it (`sbx --cloud policy init deny-all`).
  It has to be the account's default because a create request carrying a policy of
  its own fails.
- **A single-platform image <dfn>*digest*</dfn>.** A digest is the SHA-256 hash of an
  image's content, used as its name. A <dfn>*pinned*</dfn> `SANDBOX_DOCKERCLOUD_IMAGE`,
  one fixed to an exact version by digest, must name the digest of its linux/amd64
  <dfn>*manifest*</dfn> (the file that lists that one platform's image layers), not the
  digest of a multi-platform index (the list that points to one manifest per
  platform). The cloud reports the manifest it booted, and the provider compares
  against that.

## What each run does

1. Creates a sandbox from the one configured image, a plain OCI image (the standard
   container image format), pinned to linux/amd64. Its name starts with a prefix
   unique to this daemon instance, and the daemon records the sandbox as its own
   before making the create call.
2. Reads back, through the published contract, the network policy actually in force
   on the sandbox, and refuses to run unless it is deny-all with exactly the rules the
   run is entitled to. A run without a <dfn>*grant*</dfn> (permission to call listed
   routes of one API) is entitled to none. A run with one is entitled to a single
   rule, for the <dfn>*guard*</dfn>'s `host:443`: the guard is the HTTPS endpoint on
   the plimsoll daemon that is the only address a grant run may reach.
3. Runs every command of the <dfn>*guest*</dfn>, the code in the sandbox, under a
   wrapper inside the sandbox (`timeout -s KILL`, and each output stream capped by
   `head -c`), because Docker's API for running a command has no timeout and no
   output limit. The host limits the response as well. A guest that floods its output
   is a failed user run with the truncation flags set, not an infrastructure error.
4. Deletes the sandbox on every exit path. As a backstop, each sandbox is created with
   a time-to-live (TTL) on Docker's side, after which Docker deletes it, and
   `ReconcileOrphans` deletes any sandbox carrying this instance's prefix that the
   process is not tracking.

Resources: `SANDBOX_MEMORY_MB` and `SANDBOX_CPUS` (whole CPUs only) are requested at
create and verified after it. `SANDBOX_PIDS` and `SANDBOX_DISK_MB` are rejected,
since the service has no control for them.

## Host-API grants

Grants are supported when `SANDBOX_DOCKERCLOUD_GUARD_URL` is configured and return
`ErrUnsupported` otherwise. They use the same shared guard as <dfn>*E2B*</dfn>, the
other hosted microVM service plimsoll supports. The guard hands each call to the
shared <dfn>*broker*</dfn>, the part of plimsoll that makes the real API call and
attaches the credential. There are two differences an operator must know:

- **The network rule is applied outside the published contract.** A grant run's
  single rule (the guard's `host:443`) goes through `PUT /sandboxes/{id}/network-policy`,
  the REST call the `sbx` CLI makes (base URL `SANDBOX_DOCKERCLOUD_POLICY_URL`). The
  read-back in step 2 still goes through the published contract.
- **The guest holds its own run's guard credential.** Docker's proxy adds
  credentials to outgoing requests only for its own fixed list of services, so the
  provider cannot keep the guard credential outside the VM the way E2B's proxy does.
  That credential is per run, valid only at the guard, only for that run's grant
  (which cannot change once the run starts), and dead when the run ends. The
  credential for your own API never enters the VM.

## Startup smoke test

First, Docker's `CapabilityService.GetCapabilities`, which reports what the token
may do, must list, when it lists permissions at all, the read, create, delete and
network-policy-read permissions a run needs. Exec and file permissions are not
required: the cloud does not list them for a Cloud Sandboxes token, yet serves them.
Then one throwaway sandbox must come up with a deny-all policy in force, accept a
directory and a file upload, and run a probe the exact way a project step runs (the
command wrapper around `sh <script>`). That proves `node`, `timeout` and `head` are
present, the step's working directory is honored, and <dfn>*egress*</dfn> (network
traffic leaving the sandbox) is denied from inside the guest.

The smoke test creates a billable sandbox, so it runs once at startup and never on
the unauthenticated `/readyz` path, which checks configuration only.
