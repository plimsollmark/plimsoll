# plimsoll E2B template

<dfn>*E2B*</dfn> is a hosted service that runs each sandbox in a small virtual machine of
its own. A <dfn>*template*</dfn> is the machine image E2B starts each sandbox from; plimsoll
names the one it uses with `E2B_TEMPLATE` (unset, E2B's own `base`).

This folder is plimsoll's template recipe: [e2b.Dockerfile](e2b.Dockerfile), which E2B's
build reads. It gives:

- **Sessions** (one sandbox kept for many calls, [docs/sessions.md](../docs/sessions.md)).
  A session's own programs start with node's `--disable-sigusr1` option, which stops the
  session's code from opening their debugger with a signal. Node accepts it from v22.14.0
  (v23.7.0 in the 23 line, every release from 24). E2B's `base` template carried node
  v20.9.0 when plimsoll last checked it (2026-11-20), so a session there is refused at its
  open, in words that name this recipe. The recipe has node 24, util-linux's `setpriv`
  (which runs a session's code as a user no account has) and `python3` (for Python cells).
  It also copies node to `/usr/bin`: E2B's template build leaves `/usr/local`, where node's
  images put node, writable by every user in the machine (measured 2026-11-20, on `base`
  too), so a session's code could replace a node there, and plimsoll's own programs in a
  session take node only from `/usr/sbin`, `/usr/bin`, `/sbin` or `/bin`. A template of
  your own that serves sessions needs the same copy. A session's open also takes the write
  permission on `/usr/local` back from every user but each file's owner (root, as E2B
  builds it) before any of the session's code runs, since E2B's own programs that run as
  root live in `/usr/local/bin`: a session's code reads and runs what is there but cannot
  change it or install into it. A template where something under `/usr/local` stays
  writable to the session's user after that (a file the template gave the session's uid, 61000, a mount
  that ignores permissions) is refused at the open, in words that name the path. A single
  run is left as E2B builds it, `/usr/local` writable to the run's user.
- **Project steps with the TypeScript toolchain and no network.** tsc, tsx and eslint are
  baked in, as in [docker/Dockerfile](../docker/Dockerfile). plimsoll turns general internet
  access off for every E2B run (`network.denyOut: ["0.0.0.0/0"]`), so a step cannot
  `npm install` anything at run time.

**Single runs** (a snippet, or a project whose steps need only what the template has) work
on E2B's `base` with no template build: a single run starts no node program of plimsoll's
inside the machine, only the run's own `node` and `sh`. `base` has Python 3, Node.js, git
and build tools ([E2B's base image page, EXTERNAL · official docs ↗](https://docs.e2b.dev/template/base-image)),
but not the TypeScript toolchain.

## Build it

E2B's build command is `e2b template create`: it reads a Dockerfile and builds it as a
template. The command this page used to give, `e2b template build`, stopped working on
2026-08-01, when E2B retired that build system
([E2B's deprecation page, EXTERNAL · official docs ↗](https://docs.e2b.dev/migration/v1-build-deprecation)).

1. Install E2B's command-line tool, version 2.12.1 or later (the first that signs in with an
   API key alone):

   ```sh
   npm i -g @e2b/cli
   ```

2. Put your E2B API key in the environment (from the E2B dashboard; never write it to a file):

   ```sh
   export E2B_API_KEY=your_api_key_here
   ```

3. From the root of plimsoll's repository, build the template from this folder, with two
   virtual CPUs and 1024 MiB of memory:

   ```sh
   cd e2b
   e2b template create plimsoll --cpu-count 2 --memory-mb 1024
   ```

   The command finds `e2b.Dockerfile` in the folder it runs in. The template is named
   `plimsoll` (lowercase letters, digits, dashes and underscores only); running the same
   command again rebuilds it under that name.

4. Point plimsolld at it, then restart the daemon so its startup check reads the new
   template:

   ```sh
   export E2B_TEMPLATE=plimsoll
   ```

The command and its options are from E2B's command-line reference
([e2b template create, EXTERNAL · official docs ↗](https://docs.e2b.dev/sdk-reference/cli/v2.24.0/template)).

**What a build costs.** E2B's pages do not say whether a build is billed. A build runs in a
sandbox of its own ([how a build works, EXTERNAL · official docs ↗](https://docs.e2b.dev/template/how-it-works)), and E2B bills a running sandbox by the second, so a build may
be billed as one. E2B limits a build to one hour and a Hobby plan to 20 builds at once.

**Why two CPUs and 1024 MiB.** E2B sizes each sandbox's CPUs and memory per template, not per
call, so these two numbers bound every run on the template. Two CPUs keep a real
tsc/tsx/eslint build responsive within a run's time limit without handing a run that spins
the CPU more than two; 1024 MiB is room for a TypeScript compile of a medium project (tsc
peaks at a few hundred MiB) while capping a run that eats memory. Below about 512 MiB, tsc on
a project of any size runs out of memory. plimsolld refuses a template larger than its own
caps when `SANDBOX_MEMORY_MB` or `SANDBOX_CPUS` is set. Size the daemon's concurrency with
these numbers: about `SANDBOX_MAX_CONCURRENT` times them is the most it holds at once.

## Check the recipe without E2B

The recipe can be checked on the local machine, with no E2B account and nothing billed:
build it with docker under a name of your own, then run plimsoll's session tests against
that image through the stand-in for E2B that its docker tests use (a fake control plane, and
a local container per sandbox running a stand-in for E2B's agent inside the machine, on
the image with `/usr/local` opened to every user, as E2B's build leaves it).

```sh
docker build -f e2b/e2b.Dockerfile -t plimsoll-local/e2b-template:dev e2b
PLIMSOLL_E2B_TEMPLATE_IMAGE=plimsoll-local/e2b-template:dev go test -count=1 -run TestE2BTemplateRecipeOnALocalImage ./sandbox/
```

The test runs the startup check, the session open (which pins node, `sh`, `setpriv` and
`python3` and checks node's version) and a JavaScript and a Python cell in that image.

Toolchain versions are the single source of truth in
[../toolchain.versions](../toolchain.versions); both this template and
[docker/Dockerfile](../docker/Dockerfile) pin those versions, and the
`internal/toolchain` test fails if either drifts. To bump a version, edit
`toolchain.versions` and both Dockerfiles.

## Note on egress

- General internet access is off (`network.denyOut: ["0.0.0.0/0"]`) and public
  sandbox traffic is disabled. Host-API grants require `E2B_GUARD_URL`; their one
  allowed destination is the authenticated external guard, which delegates to the
  shared host-side broker. Without that setting, grants fail with `ErrUnsupported`.
