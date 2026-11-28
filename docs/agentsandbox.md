# The agent-sandbox provider

`SANDBOX_PROVIDER=agentsandbox` selects the `agentsandbox` <dfn>*provider*</dfn> (the backend
that actually runs the code): Kubernetes agent-sandbox, a Kubernetes project that keeps
sandboxes as <dfn>*pods*</dfn> (Kubernetes' unit of one or more containers run together)
with a warm pool of them ready to hand out
([Agent Sandbox (EXTERNAL · official docs ↗)](https://agent-sandbox.sigs.k8s.io/),
[kubernetes-sigs/agent-sandbox (EXTERNAL · source repo ↗)](https://github.com/kubernetes-sigs/agent-sandbox)).
Each snippet or project <dfn>*claims*</dfn> one sandbox from the pool (a SandboxClaim, the
object that asks for one), runs in it, and the claim is deleted after, which deletes the
pod. Snippets and projects only: no sessions, grants or module runs yet. The code is
[sandbox/agentsandbox](../sandbox/agentsandbox/agentsandbox.go), and plimsolld builds it in
[cmd/plimsolld/agentsandbox.go](../cmd/plimsolld/agentsandbox.go).

agent-sandbox lets a template name a <dfn>*runtime class*</dfn> (the Kubernetes object that
picks the program a node starts containers with), and that is its whole isolation story: it
does not check the class, and nothing in a sandbox's status says which one it got. So
plimsoll reads the tier, never takes it as configuration: the runtime class's handler
`runsc` (<dfn>*gVisor*</dfn>, a stand-in kernel that runs as an ordinary program) is the
`kernel` tier, `runc` (an ordinary container) the `container` tier, Kata Containers' Cloud
Hypervisor handlers `kata-clh` and `kata-clh-runtime-rs` and AKS Pod Sandboxing's `kata` (a
small virtual machine with its own Linux kernel per pod, [below](#kata-containers-the-vm-tier))
the `vm` tier, and any other handler is refused unless the operator declares it as gVisor
([below](#what-the-operator-sets-up)). The startup smoke test then holds each tier to what a guest can observe
(below), and every run holds its own pod to it again. As
for every provider, a reported tier is configuration and provider evidence plus that
behavioural test, never attestation.

Every run's record also names the pod that ran it, as `k8s-pod-uid:` and the UID the API
server gave the pod when it was made, which Kubernetes never gives another object in the
cluster's history. The provider reads the pod back on every run before it sends any code, so
the UID is the pod's own, not the template's. It lets evidence kept outside plimsoll about that
pod, such as a container runtime's log of it, be tied to the run's signed record
([run-records.md](run-records.md)).

## How it was built and verified

plimsoll talks to the Kubernetes API over plain HTTPS with a bearer token, with no Kubernetes
client library. It runs each command through sandboxd, the daemon agent-sandbox puts in every
sandbox's pod, over sandboxd's gRPC process service: its `.proto` files are copied at v1.0.7
under [third_party/agentsandbox](../third_party/agentsandbox/README.md) (Apache-2.0) and
spoken through connect-go, the RPC library plimsoll already uses, over TLS to a terminator of
plimsoll's in the pod, since sandboxd itself serves none ([below](#the-control-channel-is-tls)).
The package is separate
from package `sandbox` because the generated code registers the same protobuf names as
agent-sandbox's own Go SDK. plimsoll is an independent project, not affiliated with or
endorsed by the Kubernetes project.

`make agentsandbox-suite` (or `make audit AGENTSANDBOX=1`) runs the live suite against a
cluster: the provider's tests (snippets, the guest's identity, egress, a project with an
artifact, a hung snippet timed out, the startup smoke test, nothing left after a drain) and a
daemon test that starts plimsolld, serves a snippet, a refused isolation floor and a project
over RPC, then sends SIGTERM and requires the cluster to hold no claim of plimsoll's. It
passed on 2026-10-18 on a kind cluster (Kubernetes 1.37.0, containerd 2.3.4, agent-sandbox
v1.0.7) under both a gVisor runtime class and a runc one, and the same day under Kata
Containers 4.2.0 with Cloud Hypervisor, under both of Kata's runtimes. On that cluster a warm
pod answered a snippet in 50 to 250 ms from claim to result (160 to 360 ms under Kata), and
the daemon was ready, smoke test included, in about 3 seconds (about 4 under Kata). The docker suite also runs the scripts the smoke test sends
into a pod, in docker's locked-down container, so a broken script fails the ordinary gate.
With the TLS channel ([below](#the-control-channel-is-tls)) the whole suite passed again on
2026-11-05 on that cluster under gVisor, and the provider's tests passed under runc and under
Kata (`kata-clh-runtime-rs`), each smoke test reporting the guest's open of the key refused
for permission and no answer to cleartext on the terminator's port. Under runc and Kata the
daemon test then waited on the cluster, not the channel: with the node's CPU reserved by
other pools, a claim's new pod was not scheduled within a snippet's 5 seconds (the daemon's
log: "claim not ready"). The same suite with another CA pinned, and with another server
name, refused every run at its first command, before anything was sent.
With each pod's own key ([below](#the-control-channel-is-tls)) the whole suite passed on
2026-11-24 on a fresh kind cluster (Kubernetes 1.37.0, agent-sandbox v1.0.7, cert-manager
v1.21.3 and its CSI driver v0.16.1) under gVisor, runc and both Kata handlers (`kata-clh` and
`kata-clh-runtime-rs`), daemon test included. Its added test claims a second pod and sends a
fresh claim's connection to that pod's real terminator instead, as a rewritten route would:
under every one of the four, the run was refused before anything was sent, naming the
certificate's identity and the one expected, and the second pod then answered as itself.

[The evidence page (INTERNAL · example page →)](examples/agentsandbox/index.html) shows two
requests on that cluster through a hardened daemon, under gVisor and again under Kata
(`kata-clh-runtime-rs`, the `vm` tier), each run signed and converted to a CycloneDX bill of
materials, whose results are byte for byte those of the same requests on docker under gVisor
and on a Docker Cloud microVM; what a Kata pod's kernel said (its Linux boot line and a boot ID
other than the node's, the two things the per-pod check reads); and five refusals, among them
a node whose runsc handler was remapped to runc under a running daemon. It was recorded before
the control channel was encrypted, so its pods ran sandboxd directly on cleartext HTTP/2.

## What the operator sets up

- **agent-sandbox v1.0.7 with its extensions** (the SandboxTemplate, SandboxWarmPool and
  SandboxClaim kinds), and a runtime class whose handler is `runsc` (gVisor), `runc`, or one
  of Kata's two Cloud Hypervisor handlers. Prefer gVisor or Kata: hardened mode accepts only
  the kernel and vm tiers.
- **Optionally, gVisor under another handler name.** gVisor's options (its debug log, for
  one) are set per containerd runtime, so a cluster can register the same runsc shim a
  second time under another handler, such as `runsc-receipt`.
  `SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS` is a comma list of such names, which this daemon then
  reads as the `kernel` tier only. A declaration is not trusted: the smoke test and every
  pod's own check hold a declared handler to gVisor's boot line exactly as they hold
  `runsc`, so a name the node maps to runc or to Kata is refused before any code runs.
  Each name must be a DNS label (the form Kubernetes requires of a handler); an empty entry,
  a name given twice, or one of the handlers above stops startup. Hardened mode accepts the
  setting.
- **plimsolld running in the cluster.** It reaches each pod's sandboxd at the pod's address,
  which only the cluster network routes; Kubernetes' port-forward does not reach a pod under
  gVisor. Its own callers reach it at `PLIMSOLL_ADDR`, which its pod sets to an address the
  cluster can route to, such as `0.0.0.0:8746`: unset, the daemon listens on its pod's
  loopback address only (`127.0.0.1:8746`), which no other pod and no Service reaches. With no settings for them, the API server, its certificate authority and the token
  are the pod's own service account (`https://kubernetes.default.svc` and the files under
  `/var/run/secrets/kubernetes.io/serviceaccount`); the token file is read at every request,
  since Kubernetes rotates it in place. The service account needs, in the namespace: create,
  get, list and delete on `sandboxclaims`; get on `sandboxwarmpools`, `sandboxtemplates`,
  `sandboxes` and `pods`; list on `networkpolicies`; and, cluster-wide, get on
  `runtimeclasses`, and under Kata get on `nodes` (each run compares its pod's kernel with
  its node's). Nothing else.
- **An image with sandboxd and plimsoll's runner.**
  [docker/agentsandbox.Dockerfile](../docker/agentsandbox.Dockerfile) builds it from
  `plimsoll/sandbox`: sandboxd from the v1.0.7 commit at `/usr/local/bin/sandboxd`;
  plimsoll's TLS terminator at `/usr/local/bin/plimsoll-sandboxd-tls`
  ([docker/sandboxdtls](../docker/sandboxdtls/main.go), Go's standard library only), which
  starts sandboxd and stands in front of it ([below](#the-control-channel-is-tls)); the
  directory `/etc/plimsoll`, root's and mode 0700, where each pod's own key is mounted; and
  util-linux's `setpriv` at `/bin/setpriv`, which drops every command to the guest user.
  `SANDBOX_AGENTSANDBOX_IMAGE` names it exactly as the template writes it; with
  `SANDBOX_REQUIRE_PINNED_IMAGES=1` it must be pinned by `@sha256:`, and that digest is
  checked against each pod's image on every run. plimsoll's runner is the native helper it
  inherits from `plimsoll/sandbox`, `/usr/local/libexec/plimsoll-helper` (root's, mode 0711,
  [docs/guest-dependencies.md](guest-dependencies.md)): the startup test reads it from inside a
  pod, as the guest, and refuses the image unless it is a regular file, root's, writable by no
  one else, readable by root alone (the guest's read of it is refused), with no setuid or setgid
  bit, the size of the helper this plimsolld was built with, and, started with its `identity`
  command, prints that build's line (`inputs` and the SHA-256 of the build's inputs, compiled
  in). The guest cannot read its bytes, so the test also reads the file as root, on the second
  pod it claims (sandboxd starts every command as root; plimsoll's drop to the guest is
  `setpriv`), before any guest code has run there, and requires the SHA-256 of the copy inside
  plimsolld. So an
  image built on a `plimsoll/sandbox` from before v0.28.0 (whose runner was the Node program
  `/runner.mjs`) or from another release is refused; rebuild it from the same release as
  plimsolld (`make docker-images`, then this Dockerfile). Only an x86-64 build exists, so the
  pods must run on x86-64 nodes, and the startup test refuses any other machine by name;
  plimsolld's own machine does not matter.
- **A token for sandboxd.** A random string of 32 to 512 characters in a file named by
  `SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE`, never in the environment. The template starts
  sandboxd with `--auth-token-sha256=` and the token's SHA-256 in hex: sandboxd runs as root,
  and without a token, code in the pod could ask it on loopback to run a command as root.
- **A certificate of its own for each sandbox pod, from an issuer in the cluster.** Each pod
  serves a key and certificate made for it alone, and plimsolld refuses any pod whose
  certificate does not name the pod it read from the API server
  ([below](#the-control-channel-is-tls)). The setup plimsoll was run with
  ([its record](#how-it-was-built-and-verified)):
  1. [cert-manager](https://cert-manager.io/docs/installation/) (`EXTERNAL · official docs ↗`),
     the Kubernetes add-on that signs certificates, and its
     [CSI driver](https://cert-manager.io/docs/usage/csi-driver/) (`EXTERNAL · official docs ↗`).
     A CSI driver is a plugin on every node that the kubelet (Kubernetes' agent on each node)
     asks to mount a volume into a pod; this one makes a key on the node as the pod starts,
     has the issuer sign a certificate for that pod, and mounts both into the pod, renewing
     them before they expire. Measured with cert-manager v1.21.3 and the driver v0.16.1 on
     Kubernetes 1.37.
  2. A namespaced CA issuer in the pool's namespace (an `Issuer` of kind `ca`, whose signing
     key cert-manager keeps in a Secret of its own; [an example](agentsandbox-example.yaml)).
     Its CA certificate goes in a file named by `SANDBOX_AGENTSANDBOX_SANDBOXD_CA_FILE`, which
     plimsolld reads at startup: PEM certificates and nothing else. plimsolld trusts that file
     alone, never the system's roots, and reads no Secret, so its service account needs no
     access to secrets. Use this CA for nothing else.
  3. `SANDBOX_AGENTSANDBOX_SANDBOXD_TRUST_DOMAIN`, the first part of each pod's identity, for
     example your cluster's name as a DNS name. Each certificate must carry exactly one URI
     name, `spiffe://<trust domain>/ns/<namespace>/pod/<pod name>/<pod UID>` (a SPIFFE ID, the
     usual form of a workload identity in a certificate), and exactly one DNS name,
     `sandboxd.plimsoll.invalid` unless `SANDBOX_AGENTSANDBOX_SANDBOXD_SERVER_NAME` names
     another (`.invalid` is reserved never to resolve, so the name can be checked but never
     dialed: plimsolld dials each pod's address). The UID is what binds: Kubernetes gives
     every pod a new one, and the warm pool reuses pod names when it refills.
  4. Who may have a certificate signed. cert-manager's built-in approver signs every request
     for a namespaced issuer that is made in its namespace, so anyone who may create a
     `CertificateRequest` in the pool's namespace can get a certificate naming any pod there,
     and pass for it (measured: a request for a running pod's identity was signed). So can
     anyone who may create a pod there: the driver takes `uri-sans` from the pod's own volume,
     so a pod that writes another pod's identity out in full, with no `${POD_...}` in it, gets
     a certificate for that identity (read from the driver's documentation, not measured
     here). So no account but the operator's and the driver's may create
     `certificaterequests` or pods in that namespace, and the issuer must be a namespaced
     `Issuer` there (plimsoll refuses a `ClusterIssuer`). Kubernetes' `edit` and `admin` roles
     include both (pods always; cert-manager adds `certificaterequests`), so bind neither
     there to anyone else. cert-manager's
     [approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/)
     (`EXTERNAL · official docs ↗`) can narrow approval further, to one issuer and the
     identity's pattern, but it needs the built-in approver switched off for the whole
     cluster, which stops every other certificate the cluster issues until a policy allows
     it; and no policy can tie the name and UID in a request to a real pod.
- **A template and a warm pool**, named by `SANDBOX_AGENTSANDBOX_WARM_POOL` (the pool, which
  names its template) in `SANDBOX_AGENTSANDBOX_NAMESPACE`, whose pods plimsoll's read-back
  accepts:
  - the runtime class `SANDBOX_AGENTSANDBOX_RUNTIME_CLASS`, and under runc a seccomp profile
    (`RuntimeDefault` or `Localhost`; <dfn>*seccomp*</dfn> is the kernel feature that limits
    which requests a process may make to the kernel). None is required under gVisor or Kata,
    whose guests talk to a kernel of their own;
  - `automountServiceAccountToken: false`, no host network, process or IPC namespace, no
    shared process namespace, no init or ephemeral container, one container;
  - `dnsPolicy: None` with the one nameserver `127.0.0.1` and no search domain: Kubernetes'
    default writes the node's search domains into the pod;
  - the container: the image, `/usr/local/bin/plimsoll-sandboxd-tls` as its command,
    followed by sandboxd's flags, which the terminator passes on: the token digest, exactly
    one `--listen-host=127.0.0.1` and one `--grpc-port=9091` (sandboxd on loopback, where only
    the terminator forwards), and every argument in the `--name=value` form (sandboxd's flag
    parser stops at `--` or a bare word, and lets a flag without `=` take the next argument
    as its value, so any other form could make it read other flags than plimsoll checked;
    the terminator refuses them too), each naming a flag the pinned sandboxd takes (the 17
    its own `-h` lists at the commit the image builds; a flag a later sandboxd adds is
    refused until the list is read again, by the read-back and the terminator alike),
    `allowPrivilegeEscalation: false`, a read-only root
    filesystem, all capabilities dropped but `SETUID` and `SETGID`, and memory and CPU limits
    equal to `SANDBOX_MEMORY_MB` and `SANDBOX_CPUS` (default 256 MiB and 1 CPU). A readiness
    probe, if any, is a TCP probe on port 9090: sandboxd's own ports, the REST one included,
    are on loopback, and the terminator answers nothing but TLS with HTTP/2, so an HTTP
    probe never succeeds;
  - every volume an `emptyDir` with `medium: Memory` and a `sizeLimit`, mounted whole at a
    clean path, one of them `/work`. A disk-backed one is capped only when the kubelet's
    periodic eviction notices, so a run could fill the node's disk until then; with
    `SANDBOX_DISK_MB` set, the size limits must sum to no more than it. The guest mount table must show no mount strictly beneath any writable root,
    under every tier: a tmpfs root cannot bound a node-backed file mounted inside it, even
    when an image symlink hides the relationship from the API path check. Under Kata no volume
    keeps its size limit, so `SANDBOX_DISK_MB` fails startup there
    ([below](#kata-containers-the-vm-tier));
  - one more volume, the pod's key: a `csi` volume of the driver `csi.cert-manager.io`,
    `readOnly: true`, mounted once, read-only, at `/etc/plimsoll/sandboxd-tls`, with no
    other volume mounted at, over or inside `/etc/plimsoll`. Its attributes are a closed
    list: `issuer-name`, `issuer-kind` (`Issuer` only: a `ClusterIssuer` signs requests made in
    every namespace, so a pod anywhere in the cluster could have a pool pod's identity signed)
    and, for an issuer
    outside cert-manager's own group, `issuer-group`; `dns-names` the one name above;
    `uri-sans` exactly `spiffe://<trust domain>/ns/${POD_NAMESPACE}/pod/${POD_NAME}/${POD_UID}`,
    which the driver fills from the pod being mounted, never from anything the pod says;
    `key-algorithm: ECDSA`, `key-size: "256"`, `key-encoding: PKCS8` and `key-usages: server
    auth,digital signature` (the driver's defaults are an RSA key with no server use); and,
    optionally, `duration`, the certificate's lifetime. Any other attribute is refused, among
    them `fs-group` (it would make the key readable by a group of the pod's choosing),
    `pkcs12-enable` (a second copy of the key) and `reuse-private-key` (a renewal must bring
    a new key). The volume is outside the writable volumes and outside `SANDBOX_DISK_MB`'s
    sum. A `secret` volume, which earlier releases took for one key shared by every pod, is
    refused. Choose a lifetime longer than a pod ever lives (the driver's default is 30
    days): a pod waits, unready, until its certificate is signed, so a running pod then never
    needs cert-manager, and a pod lives no longer than its claim;
  - `terminationMessagePath` somewhere the guest cannot reach, such as
    `/root/termination-log`. The default, `/dev/termination-log`, is a file the kubelet
    mounts from the node's disk, writable by every user in the container (measured: 64 MiB
    written by the guest landed on the node). Every pod is held to it, outside `/tmp`,
    `/dev` and every volume, so a warm pod made from an older template is refused too.
  - a network policy (the template's own `networkPolicy` will do) that denies egress, and
    none in the namespace that allows any; ingress only to the TLS terminator's port, 9090,
    from where plimsolld runs.

  [An example template, pool and service account](agentsandbox-example.yaml) passes the
  read-back.

### Hardened mode and the pod network

With `PLIMSOLL_HARDENED=1` plimsolld requires `SANDBOX_AGENTSANDBOX_SANDBOXD_TRUST_DOMAIN`,
the trust domain of each pod's identity, which the provider requires in every mode too. It
asks for no statement about the pod network: the channel below checks, in every handshake,
that the peer is the pod plimsolld read. `SANDBOX_AGENTSANDBOX_ENCRYPTED_POD_NETWORK`, the
statement earlier releases asked for, is gone.

### The control channel is TLS

Everything a run needs crosses one connection from plimsolld to the pod: the sandboxd token
in every request, the code and files, each project's plan with the run's report key (the key
that proves a result came from plimsoll's runner and not from the guest), and every byte of
output. sandboxd serves no TLS (its own guide says so), and the network policy above decides
only who may connect, not who may read or rewrite the traffic. So the channel is encrypted
and authenticated by plimsoll itself:

- In the pod, `plimsoll-sandboxd-tls` is the container's first process. It refuses to start
  unless sandboxd's flags put it on loopback port 9091 alone and give it one token digest to
  check (`--auth-token-sha256`, never a token file), `/etc/plimsoll` is root's and closed to
  everyone else, and the key and certificate have exactly mode 0440 for owner root and group
  root, as the driver writes them; then it starts sandboxd, waits for its port, and listens
  on 9090 (so a readiness probe on 9090 means the whole chain is up). Each connection must
  finish a TLS 1.3 handshake within 10 seconds and agree on HTTP/2 before a byte reaches
  sandboxd; the bytes are then copied unchanged both ways. It reads the certificate and key
  again at every handshake, so a certificate the driver renewed is served without a
  restart (measured under runc, gVisor and both Kata handlers). A failed handshake is
  logged by its kind (not TLS, timed out, no protocol in common), never with the error's text,
  which can quote what the client sent, and at most 16 lines a minute.
- plimsolld speaks HTTP/2 over TLS 1.3 alone, to `https://<pod address>:9090`: no HTTP/1.1, no
  cleartext HTTP/2 and no proxy. It accepts only a certificate that chains to the CA in
  `SANDBOX_AGENTSANDBOX_SANDBOXD_CA_FILE`, carries exactly the configured DNS name, and
  carries exactly one URI name, the identity of the pod this run claimed, built from the
  namespace, name and UID plimsolld read from the API server just before; no IP address or
  other name may stand beside them. It refuses a connection with no verified chain or no
  HTTP/2 even if a later change skipped a check.
- Each claim has a connection of its own: a client made for that pod, closed when the
  claim is released. A pod's address passes to another pod once it is deleted, and a pooled
  connection is checked only at its handshake, so one client shared by every claim could
  carry a later run's token over a connection checked for an earlier pod.
- A pod that cannot prove itself (a certificate from another CA, another name, another
  pod's identity, the same name with another UID, an expired one, a port that speaks no
  TLS) gets nothing: the handshake comes before any request, so neither the token nor any
  code is sent, and the run is refused, marked not dispatched (reason `environment`), with
  the CA file, the name and the identity expected in the message. At startup the smoke
  test's own claims take the same path, so a wrong CA, name or trust domain stops plimsolld
  from serving. A terminator that refuses to start leaves its pod unready; its reason is in
  the pod's log.
- The guest cannot read the key: `/etc/plimsoll` is root's with mode 0700, the key file is
  root's and group root's, mode 0440, the guest is another user with no group and no
  capabilities, and the key's only other copy is in the terminator's memory, process 1,
  which the guest cannot open. The smoke test proves from inside the pod that the guest's
  open of the key is refused and that the guest holds no group
  ([below](#startup-smoke-test)).

**What it proves: which pod answered.** Each pod's certificate names that pod's UID, and
plimsolld checks it against the pod it read, so someone who can rewrite traffic on the pod
network (address or route manipulation, a compromised network plugin component) and owns
another pod of the deployment, for example one their own run claimed, cannot receive a
caller's run by redirecting plimsolld's connection there: the other pod's certificate is
valid but names another UID, and the handshake fails before anything is sent. A pod
deleted and made again under the same name has a new UID and fails the same way. A guest
that became root in its pod (which takes a flaw in the runtime's boundary, not a setting)
reads that pod's key, which passes for that pod alone, for as long as that pod lives.

**What it does not stop: a compromised node, or anyone who may have a pod's certificate
signed.** The driver runs on every node with a service account that may create certificate
requests in every namespace and read every pod (measured on its v0.16.1), so root on any
node, or anyone holding the driver's token, can have a certificate signed for any pod's
identity and pass for it. So can any account that may create certificate requests or pods in
the pool's namespace while cert-manager's built-in approver signs them (step 4
[above](#what-the-operator-sets-up)). Per-pod keys move the attacker from "on the pod
network" to "holds a node or the issuer"; they do not take the node out of the trusted
base. Rotate the sandboxd token on a schedule (a new token file, the template's
`--auth-token-sha256` of it, and a daemon restart). To change the CA, put the old and the
new certificate in the CA file, restart plimsolld, change the issuer, let the pool refill,
then drop the old certificate.

**A closed pod and container schema.** Both the template and each actual pod refuse unknown
pod-spec and container fields, including unknown fields inside decoded probes, mounts and
security contexts. Exec handlers in readiness, liveness and startup probes and in lifecycle
hooks are refused: Kubernetes would run them as sandboxd's root user, and a command could
name a file the guest wrote. TCP, HTTP and gRPC probes and HTTP or TCP lifecycle hooks are
allowed. Scheduling defaults, RuntimeClass overhead, node selectors and tolerations are
allowed because they affect placement and accounting rather than granting guest privileges.
Service-account names are allowed with token mounting disabled; resource requests, image
pull policy and termination-message policy do not relax the checked execution boundary.
Host ports are refused; sandboxd's explicit user and group must be root so it can drop each
command to the guest user. Environment injection, device mounts and other fields outside
the schema require review before they can be accepted.

**After startup, only the template the smoke test proved.** The read-back decodes the fields
it checks and no others, and the smoke test proves the rest (where the guest can write, what
it can reach) for one template. So once it passes, a template whose name or spec differs
from the one it ran on fails Preflight and readiness, and its runs are refused before
anything is claimed (reason `environment`), until a restart proves it, as a docker tag
re-pointed after startup is. `Preflight`'s answer is reused for 5 seconds (`/readyz` is
unauthenticated); every run reads the warm pool, the template and the runtime class again
before it claims a pod.

**The proven network policy set.** Before the smoke test sends a command, plimsoll records
all policies in the namespace by name, UID (Kubernetes' identity for that object) and the
digest of the complete spec, including fields the semantic checker does not decode. Both
claimed pods and a final read must see that same set. Every later pod read-back refuses
an added, removed, replaced or changed policy before dispatch, reason `environment`; restart
plimsolld to prove a new set. Once observed, a difference remains a refusal even if the
original set is restored. Metadata-only edits and list ordering do not change the pin.
The whole namespace set is pinned, including policies that select other pods, because a
policy's selector can change which pods it affects. A recreated deny policy cannot borrow
its predecessor's proof while the network plugin is still applying it. Cluster-scoped
policies, network-plugin state and changes after the read-back remain outside this pin.
The smoke test checks that the policies are enforced, once, from inside a pod
([below](#startup-smoke-test)). A per-run connection test could check enforcement again, at
the cost of waiting for blocked connections to time out; it is not implemented.

**The proven runtime class.** The smoke test also records the runtime class it runs on:
its UID, its handler, and its `overhead` and `scheduling` settings, which decide where its
pods run. Kubernetes keeps a class's handler immutable, so a class whose handler changes is
one deleted and made again under the same name, with a new UID. Every later read of the
class (Preflight, each run's check before it claims a pod, and each pod's read-back) refuses
a class that differs, reason `environment`, before anything is claimed or sent; restart
plimsolld to prove the new one. Once observed, a difference remains a refusal even if the
original is restored, since the warm pool may still hold pods made from the other class.
Labels and annotations do not change the pin. This applies with or without hardened mode,
so an operator who changes the class restarts the daemon, as for a changed template.

## What each run does

1. Reads the warm pool, its template and the runtime class, and refuses any difference from
   the above, or a template or runtime class other than the one the smoke test proved. The
   tier is the handler's, read again on every run, and compared with the run's floor: the
   caller's `minimum_isolation`, raised in hardened mode to the daemon's own floor of
   `kernel` ([hardened mode](hardened-mode.md#isolation-is-a-floor-on-every-run-not-only-a-startup-check)),
   so a weaker tier is refused, reason `isolation`, before anything is claimed.
2. Creates a claim on the pool, labelled with this daemon instance, `plimsoll.run=1` and
   the run's lifetime, and with a shutdown time five minutes past the run's end, at which
   agent-sandbox deletes it even if plimsolld is gone. A claim is refused when the API
   server's clock is more than a minute from plimsolld's.
3. Reads the claimed pod back (the same checks, its image by digest, every network policy
   that selects it, the runtime class again) before any code is sent.
4. Runs one command of its own in the pod, as the guest, before any of the run's code, over
   the TLS channel, so a pod whose terminator cannot prove itself is refused here: the
   first line of the kernel log, which under the kernel tier must be gVisor's boot line and
   under Kata a Linux kernel's; the kernel's boot ID, which under Kata must differ from the
   one the pod's node reports, since a pod on the node's own kernel shares it; and the seccomp
   mode, which under runc must show a filter. A handler's name is configuration on
   each node, which the API does not show: live on kind, with a node's runsc handler remapped
   to runc after the smoke test had passed, a run was signed at the kernel tier on the host's
   kernel until this check was added. A pod that fails it is refused, not dispatched, reason
   `environment`; one that passes is held to the run's floor at its tier, reason `isolation`. On kind it cost nothing measurable (a median of 75 ms per snippet with and
   without it).
5. Sends one command to sandboxd: the snippet to `node -`, or a project's plan to the
   runner, as the guest user (uid 61000, no capabilities, `no_new_privs`, under `env -i`).
   Every request that carries sandboxd's token is sent before the guest's code starts. The
   deadline is plimsoll's: when it passes, plimsoll cancels the stream, which makes sandboxd
   kill the command's process group; sandboxd itself bounds neither time nor output, so
   plimsoll keeps the first 64 KiB of each of a snippet's streams, 16 MiB of the runner's
   stdout and 64 KiB of its stderr (a project step's own streams are capped at 1 MiB each
   by the runner), and flags the rest as dropped.
6. Returns the result, then deletes the claim in the foreground, so the pod is gone before
   the run gives back its capacity. A delete that exhausts its retry budget stays tracked
   as pending and keeps the capacity held. `ReconcileOrphans` retries it by name, with or
   without a deletion timestamp, including a claim no longer present in the namespace
   listing. Only confirmed absence releases the reservation. Concurrent reconciliation
   cannot take over a create, a live run or a deletion already in progress. Daemon shutdown
   waits for deletion, and `Drain` names remaining claims if its deadline expires.

## Startup smoke test

Before the provider serves, it claims three sandboxes as runs do and proves from inside what
the read-back cannot see:

- the guest runs as uid 61000 alone, with no capability, `no_new_privs`, only `PATH` and
  `HOME`, and the fixed resolver;
- a write attempted at every path the guest can reach (about 4,900 on the test cluster)
  succeeds only in the template's volumes and `/dev/shm`, and a file can be created nowhere
  else, except a message queue in `/dev/mqueue` (below);
- each volume refuses writes once its size limit is full; under Kata, where none does, every
  volume and `/dev/shm` is instead a tmpfs of the VM's own kernel, so in its memory;
- no connection leaves the pod: to the internet, the cloud metadata address, the API
  server's address and the node's kubelet, every attempt times out or is refused inside the
  pod;
- nor does one to another sandbox pod's TLS terminator port, 9090: the test claims a second
  sandbox, which runs no code, and the guest of the first dials it. The addresses above are
  outside the cluster, and a network plugin can treat traffic between pods apart, so this is
  the check that the network policy keeps one sandbox from another's sandboxd. After the
  attempt plimsolld reaches that port itself over TLS, so the port the guest could not reach
  was listening;
- under the kernel tier, the guest's kernel log begins with gVisor's boot line (a handler
  named `runsc` is only a name in the node's configuration, and a host's own log can name
  gVisor too); under Kata, the log begins with a Linux kernel's boot and the boot ID is not
  the node's; under runc, a seccomp filter is in force on the guest. Every run repeats this
  check in its own pod (step 4 above), since the smoke test sees only the nodes its three
  pods landed on;
- sandboxd refuses the guest's process starts on its loopback port without the token and
  with a wrong one;
- the guest's open of the TLS key fails for lack of permission, and a cleartext process start
  sent to the terminator's port gets no answer from sandboxd;
- a project step cannot open the runner's plan and report descriptors or memory, nor
  sandboxd's memory, environment or input, nor those of the terminator (process 1, which
  holds the TLS key).

A failure refuses startup. The test takes three sandboxes from the warm pool, so from a pool
of fewer than three warm pods it waits for the pool to start one, and it must finish within
two minutes, plimsolld's bound on startup.

## Claims a crashed daemon leaves behind

Once a minute the daemon deletes its own claims that no run tracks, and any other instance's
once the API server's creation time plus the declared lifetime plus 5 minutes has passed. A
claim's own shutdown time deletes it anyway, at the same mark, if no plimsolld is left to.

## What it does not do, and what it leaves to the node

- **No sessions, grants or module runs.** They are refused before anything is claimed.
- **Memory.** Under gVisor the pod's limit caps memory in RAM only: on a node with swap a
  gVisor pod swaps past it under the kubelet's default swap setting, NoSwap (gVisor issue
  [google/gvisor#15756 (EXTERNAL · issue tracker ↗)](https://github.com/google/gvisor/issues/15756);
  measured on kind on 2026-10-18: a 128 MiB pod held 1024 MiB, 932 of it in swap, and was never
  killed, where runc killed the same pod at 112 MiB). Until gVisor fixes it, take swap from the
  pods' parent cgroup: `memory.swap.max=0` on the kubepods cgroup in the cgroupfs layout (the
  same pod was then killed at 96 MiB), or a `MemorySwapMax=0` drop-in on the kubepods slice
  under the systemd driver, which the issue's reporter confirmed. Either takes swap from every
  pod on the node. The volumes are tmpfs, so they count against that memory too. `/dev/shm` is outside the
  volumes' sum: under runc the runtime's own 64 MiB tmpfs, under gVisor bounded only by the
  pod's memory.
- **Message queues.** Under runc the guest can create POSIX message queues in its pod's own
  IPC namespace, freed with the pod. Their size is counted per user across the node (819,200
  bytes by default), so concurrent guests share one allowance: one can use it up and deny the
  others queues, never read theirs. The smoke test refuses a node whose allowance is
  unlimited or above 1 MiB.
- **Process count.** The kubelet sets it for every pod on a node (`podPidsLimit`), which the
  API does not show, so `SANDBOX_PIDS` fails startup.
- **Other runtimes.** Kata's QEMU handlers and any other handler are refused until plimsoll
  has tested them; the one exception is a handler the operator declares as gVisor, which is
  held to gVisor's boot line like `runsc`. That check reads what the guest sees, so like every
  tier here it is evidence, not attestation: a node that forged gVisor's boot line would
  pass it, under `runsc` as under a declared name.
- **Policies outside the namespace.** The read-back sees Kubernetes NetworkPolicy objects
  only; a cluster-wide admin policy or a network plugin's own kinds can allow traffic too,
  which only the smoke test's connection attempts would catch.

## Kata Containers: the vm tier

[Kata Containers (EXTERNAL · official docs ↗)](https://kata-containers.github.io/kata-containers/installation/)
starts each pod inside a small virtual machine of its own, with its own Linux kernel, using the
CPU's hardware virtualization (KVM on Linux), so a node needs `/dev/kvm`, and on a cloud VM
nested virtualization. Its installer, kata-deploy, registers one runtime class per
<dfn>*shim*</dfn> (Kata's program for one hypervisor and runtime) with the handler named after
it. plimsoll treats two as the `vm` tier: `kata-clh` (Cloud Hypervisor on Kata's Go runtime)
and `kata-clh-runtime-rs` (Cloud Hypervisor on runtime-rs, the Rust runtime Kata recommends
since 4.0). Both were run with kata-deploy 4.2.0 on the kind cluster above, which runs on a
virtual machine with nested virtualization, and both pass the whole live suite. Kata's QEMU
shim never started a pod there (the guest agent did not answer within the shim's 10 seconds),
so its handlers stay refused. The third `vm` handler is `kata`, the one behind AKS Pod
Sandboxing's runtime class ([below](#on-aks-pod-sandboxing)).

How plimsoll holds a pod to the tier: before any of a run's code, the guest reads its kernel
log, whose first line must be a Linux kernel's boot line (gVisor's is not), and its kernel's
boot ID, a random identifier each boot, which must differ from the boot ID the pod's node
reports through the API: a pod that a node's Kata handler actually started under runc shares
the node's kernel, and so its boot ID. Measured on kind with the node's `kata-clh` handler
remapped to runc, every run was refused on both counts. As with gVisor's boot line, a node's
root could forge either, so this catches a node that runs something other than its handler
says, not a hostile node. It also assumes the kubelet reads the node kernel's own boot ID: a
kubelet inside systemd-nspawn reads one nspawn made for its container, which a runc pod on
that node would not share, so there the boot ID tells nothing.

What changes under Kata, measured on that cluster:

- **No volume keeps its size limit.** Kata mounts each memory-backed `emptyDir` as a tmpfs of
  the VM's own kernel: runtime-rs with no size (Linux's default, half the VM's memory), the Go
  runtime with the VM's whole memory; a guest wrote 100 MB into a volume limited to 32 MiB
  ([kata-containers#2438 (EXTERNAL · issue tracker ↗)](https://github.com/kata-containers/kata-containers/issues/2438)).
  The writes stay in the VM's memory, not in any file system of the node's (the VM's memory
  can still reach the node's swap, or the guest's own swap where Kata's configuration turns it
  on; plimsoll checks neither), so the smoke test checks that every writable mount is such a
  tmpfs instead of filling each one, and
  `SANDBOX_DISK_MB` fails startup: no disk budget can be promised. Hardened mode does not
  require it under Kata. A disk-backed `emptyDir` is a share of the node's own directory under
  Kata, so it stays refused.
- **Memory.** runtime-rs sizes the VM to the pod's limit (the guest saw 257 MiB for 256 MiB);
  the Go runtime boots a 2 GiB VM and applies the container's limit inside it. Both runtime
  classes add a fixed overhead per pod (130 MiB and 250 millicores, as kata-deploy 4.2.0
  writes them), which the scheduler counts outside the template's limits.
- **No seccomp in the guest.** Kata applies no seccomp profile inside the VM unless its
  configuration sets `disable_guest_seccomp = false`; the guest saw none with the template's
  `RuntimeDefault`. The boundary is the VM, so plimsoll requires none, as under gVisor, and
  states only the tier.
- **Start time.** A pod is ready in seconds, and the warm pool hides it; a snippet took 160 to
  360 ms from claim to result against 50 to 250 ms under gVisor.

### On AKS Pod Sandboxing

[AKS Pod Sandboxing (EXTERNAL · official docs ↗)](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)
is Kata on Cloud Hypervisor over Microsoft's own hypervisor, on Azure Linux nodes. A node pool
created with `--workload-runtime KataVmIsolation` gets the runtime class `kata-vm-isolation`,
whose handler is `kata`; the class adds a fixed 600 MiB of memory per pod (`overhead`) and a
node selector for those nodes. Run on 2026-10-18 on one `Standard_D4s_v4` node (Kubernetes
1.36.4, containerd 2.3.4) with Cilium enforcing network policy, the whole live suite passed at
the `vm` tier, the provider's tests and the daemon's over RPC. What the guest saw:

- its own kernel, a build of the node's (`6.6.137.mshv1-1.azl3` inside, `6.6.137.mshv2-2.azl3`
  on the node), a Linux boot line readable as the guest's uid, and a boot ID other than the
  node's;
- 225 MiB of memory for a 256 MiB limit, so the VM is sized to the pod as under runtime-rs;
- each memory-backed volume and `/dev/shm` a tmpfs of the VM's kernel with no size (half the
  VM's memory), the root read-only, and no seccomp, the same as on kind;
- no connection out to any address the smoke test tries, the node's metadata service and its
  kubelet included.

The daemon was ready in 9.5 seconds, its smoke test included, and a snippet over RPC took 458
ms. Two things differ from kind. The overhead holds memory only, so a template's CPU limit is
counted whole against the node: with the system pods on that 4-vCPU node, a pool of two pods
at one CPU each left no room for the pod a run claims while another is deleted, and the run
timed out waiting for it; at 500 millicores (`SANDBOX_CPUS=0.5`) it passed. And the nodes are
managed, so the remap test above (a handler pointed at runc) cannot be repeated there; the
per-pod check is the same code either way.

## Each claimed pod keeps the tested filesystem boundary

The actual pod must match the checked template's volume sizes, mount paths,
termination-log path, entrypoint and security context. Scheduling fields, resource
requests and Kubernetes readiness defaults do not change that comparison. Every
accepted pod must use the first accepted pod's image digest, including both startup
smoke-test claims, so changing a mutable image tag requires a restart and new proof.

Before any submitted code, the same guest command that reads the kernel identity
also reads the complete mount table. No mount may sit below a writable root, even
when a path in the image resolves through a symbolic link. Under container and vm
isolation, each root must report a tmpfs, a filesystem held in memory. Under gVisor,
Kubernetes memory volumes appear as 9p shares, a filesystem-sharing protocol that
hides their backing type; their memory declaration and limits remain bound to the
template whose write limits the startup test proved. A malformed or truncated report refuses the run without dispatch.
These checks are provider evidence, never hardware attestation.
