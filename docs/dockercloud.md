# The Docker Cloud Sandboxes provider

`SANDBOX_PROVIDER=dockercloud` runs each snippet or project on <dfn>*Docker Cloud
Sandboxes*</dfn>, Docker's hosted sandbox service, in a <dfn>*microVM*</dfn>: a small
virtual machine made for one run, kept apart from others by the processor's
<dfn>*hardware virtualization*</dfn>. This <dfn>*provider*</dfn> (a provider is the
backend that runs the code) reports it as the `vm` <dfn>*isolation tier*</dfn>, the
strongest of the four levels. The code is
[sandbox/dockercloud.go](../sandbox/dockercloud.go).

## How it was built and verified

It was first written against the API Docker released as `github.com/docker/sandboxes-api`
v0.36.0 (tagged 2026-09-03, before the service launched), a <dfn>*protobuf*</dfn> API
(protobuf is Google's schema format for messages). The provider speaks that API by
hand, as <dfn>*Connect*</dfn> JSON over `net/http` (Connect is an RPC protocol that
carries JSON or protobuf over ordinary HTTP), so it adds no module to the dependency
graph. The live suite (`make audit DOCKERCLOUD=1`) passed against the real service at
`https://sandboxes.connect.docker.com/sbx` on 2026-09-24 and again on 2026-10-04: smoke
test, snippet, project, resource bounds, and listing leftover sandboxes (orphans). "The
published contract" below means that release.

**That contract is no longer the one Docker documents.** When the service launched on
2026-09-24, Docker published an experimental REST API at
`https://connect.docker.com/sandboxes` and documents only that one
([EXTERNAL · official docs ↗](https://docs.docker.com/ai/sandboxes-api/)). Its operations
mirror the protobuf contract's, but the paths, the delete precondition (`If-Match`) and the
network-policy read-back differ. The
`sandboxes-api` repository is no longer public (404 on 2026-10-04), and Docker has stated
neither a deprecation nor a sunset date for the Connect endpoint. Treat the endpoint as
undocumented: it can change without notice. Since 2026-10-04 the provider can also speak
the REST API, kept as the backup while Connect stays the default, as
[Choosing the API](#choosing-the-api) describes; run the live suite (it creates billable microVMs, a few cents' worth) before
relying on either.

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

## An image kept in the account's own store

`SANDBOX_DOCKERCLOUD_IMAGE` names an image the service pulls from a registry, so a
private image needs a registry the service can read. Instead,
`SANDBOX_DOCKERCLOUD_STORE_IMAGE` names an image in the account's own Cloud Sandboxes
image store, as `<image id>@sha256:<manifest digest>`: the service boots it by its ID
with no pull, and nothing outside the account can boot it. Set one of the two, never
both. What was verified live on 2026-10-05, with the Connect API:

- **Putting an image there.** `ImageService.CreateImage` with `from_image` answers a
  push target: a registry reference the service owns and a short-lived token
  that may push to that one reference, logging in with the reference's first path segment (the owning organization) as its
  user name. After the push the image reads `IMAGE_STATUS_COMPLETED` and reports the
  pushed manifest digest. The request must name a size the service offers (Micro, 1 CPU and
  2 GiB, is the smallest) and no platform, which it takes from the push, and it should set
  the start command `tail -f /dev/null`, plimsoll's for raw images, because a sandbox
  booted from the store runs the image's own start command.
- **Booting it.** A create naming the ID boots it (running in 1.4 s), with the run's
  lifetime, delete on timeout, no automatic resume and the linux/amd64 platform honored.
  The service refuses a start command or a size beside an image ID: both are the image's.
  So `SANDBOX_CPUS` and `SANDBOX_MEMORY_MB` only cap the image's size here; a sandbox
  larger than they allow (or than Micro, when they are unset) is refused before any code
  runs. Naming the push target's reference instead is refused ("image not found or access
  denied").
- **Evidence.** The sandbox reports the digest it booted, and every run is refused unless
  it equals the configured one, so the digest is required and no pinning flag is needed,
  in the strict production check either. The REST API reports no booted digest, so a store
  image needs `SANDBOX_DOCKERCLOUD_API=connect`.

Whoever holds the account's token can boot the image and read it, as with any image the
account can boot.

## What each run does

1. Creates a sandbox from the one configured image, a plain OCI image (the standard
   container image format) or a store image, pinned to linux/amd64. Its name starts with a prefix
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

## Choosing the API

`SANDBOX_DOCKERCLOUD_API` chooses the API once, at startup. The provider never falls
back from one to the other: the startup smoke test proves only the API in use, and the
two give different evidence. Connect is the default, because it is the only one with
host-API grants, the booted image's identity, the daemon's strict production check and runs
past 270 s; REST is
kept as the backup until it covers those.

| | `rest` | `connect` (the default) |
|---|---|---|
| What it is | the API Docker documents | the pre-launch API described above |
| Live suite through the provider | passed on 2026-10-04 | passed on 2026-09-24 and 2026-10-04 |
| `SANDBOX_DOCKERCLOUD_API_URL` | defaults to `https://connect.docker.com/sandboxes` | required |
| Pinned image | the API reports no booted digest, so each run checks only that the service recorded the pinned reference; no identity is stated, so a caller's software rule refuses the run | each run checks the digest the sandbox booted, and `Describe` states it as the image's identity |
| The daemon's strict production check, `PLIMSOLL_HARDENED=1` | refused | allowed, and must be named: `SANDBOX_DOCKERCLOUD_API=connect` |
| Host-API grants | refused; a configured `SANDBOX_DOCKERCLOUD_GUARD_URL` fails startup | supported |
| Longest run | 270 s | the configured ceiling (default 120 s) |

On REST, commands and file transfers go to the sandbox's own endpoint, which refuses
the account's token. The provider creates a separate credential, valid for that one
sandbox, and uses it for the run's calls while it outlives each call's deadline; the
service limits how often one may be created (on 2026-10-04 one per call was answered
"Too Many Requests"). A credential lives at most 300 seconds, and a command still
running when its credential expires is cut off, which is why a REST run is capped at
270 seconds: 30 seconds of margin for the run's setup. Grants stay on Connect: the call
that sets the guard's network rule (see [Host-API grants](#host-api-grants)) is
accepted on a sandbox the REST API created, but the REST API then refuses to report
that sandbox's policy ("installed network policy is unavailable", 2026-10-04), so a
grant run could not prove its network before running anything. The live suite checks
that refusal on every REST run, so a change on Docker's side shows up. Keep the account's deny-all default for either API: while it is in force the
REST API refuses a sandbox that carries its own network policy, and the Connect API
cannot send one. On REST a delete's answer proves nothing (it reports success for a
sandbox that does not exist), so the provider reads the sandbox until it is gone.
