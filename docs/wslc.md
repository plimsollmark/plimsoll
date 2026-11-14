# The WSL containers provider

`SANDBOX_PROVIDER=wslc` selects the `wslc` <dfn>*provider*</dfn> (the backend that runs the code) for Windows. It
runs each snippet or project through <dfn>*WSL containers*</dfn> (WSLC), the <dfn>*container runtime*</dfn> (the
software that starts and runs containers) Microsoft ships inside WSL, the Windows Subsystem for Linux (the part of
Windows that runs Linux in a virtual machine). plimsolld runs inside a WSL distribution (a Linux system installed under
WSL) and starts `wslc.exe`, WSLC's command-line program, through <dfn>*interop*</dfn>, WSL's ability to start a Windows
program from a Linux process. Nothing is installed on Windows beyond WSL itself: no Docker Desktop and no other
virtualization software. plimsoll is an independent project, not affiliated with or endorsed by Microsoft.

WSLC groups containers in a <dfn>*WSLC session*</dfn>: one <dfn>*Hyper-V*</dfn> virtual machine (VM) running one Docker
daemon (`dockerd`) for its containers. Hyper-V is the <dfn>*hypervisor*</dfn> (the program that runs virtual machines)
built into Windows. A WSLC session is WSLC's term. It has nothing to do with a plimsoll session (one sandbox kept open
for many calls), which this provider does not offer.

The provider has two modes, chosen with `SANDBOX_WSLC_MODE`:

| | `per-run` (the default) | `shared` |
|---|---|---|
| What a run gets | A WSLC session of its own: a new VM with its own Linux kernel, `dockerd` and disk, booted from a fresh copy of a template disk and deleted after the run. | A new container in the Windows user's one default WSLC session, beside every other run. |
| Wall between two runs | Separate VMs. | <dfn>*runc*</dfn>'s (the program docker uses by default to start a container on the machine's own kernel): the runs share one kernel. |
| Wall between a run and Windows | The run's own Hyper-V VM. | The session's Hyper-V VM, one for all runs together. |
| Reported <dfn>*isolation tier*</dfn> (how strong the walls around a run are: `process`, `container`, `kernel` or `vm`) | `vm`, always with Microsoft's statement beside it ([below](#the-tier-and-why-hardened-mode-refuses-it)). | `container`. |
| Hardened mode | Refused. | Refused. |
| Runs at once | Up to `SANDBOX_WSLC_MAX_SESSIONS` (default 2), each in its own VM. | One at a time ([below](#what-each-run-does)). |
| gVisor inside | Optional, off by default ([below](#gvisor-inside-each-per-run-vm)). | Not offered. |

The code is [sandbox/wslc](../sandbox/wslc/wslc.go), and plimsolld builds it in
[cmd/plimsolld/wslc.go](../cmd/plimsolld/wslc.go).

**What it is, and what it is not.** A fresh VM per run is a strong way to keep runs apart from each other and from
Windows, and here it needs nothing beyond WSL. plimsoll still does not give it its strongest standing:
<dfn>*hardened mode*</dfn> (`PLIMSOLL_HARDENED=1`, the daemon's strict production check,
[INTERNAL · hardened mode →](hardened-mode.md)) refuses it in both modes, for four reasons
([below](#the-tier-and-why-hardened-mode-refuses-it)): Microsoft states that WSL is not a security sandbox for running
untrusted code; WSL's VMs share parts of Windows, such as the graphics card, with what runs inside them; five of the
controls plimsoll's docker provider applies are missing inside each VM; and the per-run mode relies on a `wslc.exe`
command Microsoft has not documented. Use it to run agent-written code in a fresh VM on a Windows machine with nothing
extra installed, at exactly the strength this page states. Do not treat it as a secure sandbox on Windows.

On the same machine, plimsoll's docker provider with the runtime of <dfn>*gVisor*</dfn> (Google's sandbox kernel,
which answers a container's requests to the kernel itself), run inside a WSL distribution, reports `kernel`, a tier
hardened mode accepts ([INTERNAL · gVisor setup →](gvisor.md)). The difference is where an escape lands: there, in
the WSL distribution that runs docker, usually the one that also holds plimsolld, its callers' code and its keys; here,
in an empty VM that is deleted after the run.

## How it was built and verified

The provider was written from Microsoft's open-source WSL code
([microsoft/WSL (EXTERNAL · source repo ↗)](https://github.com/microsoft/WSL)), because much of how `wslc.exe` behaves
(which flags `container run` accepts, how a session is made and ended, what a session VM holds) is stated there and not
in Microsoft's documentation. Its unit tests run against a stand-in program that answers as `wslc.exe` would. A
misreading of Microsoft's code would be shared by the provider and the stand-in, which is why the live suite exists.

**What was measured, and on what.** Every statement on this page that something was measured or seen comes from one
machine: a laptop running Windows 11 Pro (version 26H2, build 26300) with about 31 GiB of memory, WSL 3.0.5.0 (the newest stable WSL release on
the [WSL release list (EXTERNAL · source repo ↗)](https://github.com/microsoft/WSL/releases) as of 2026-11-14, released
2026-11-03), the real `wslc.exe`, and plimsoll's sandbox image. No other machine, WSL release or Windows edition has
been tried.

- **The live suite** (`make wslc-suite`, [Tests](#tests)) passed seven of seven tests, none skipped, on 2026-11-13, and
  again on 2026-11-14 on the code as released, after the cleanup rule and the run-folder lock changed ([One plimsolld to a run folder](#one-plimsolld-to-a-run-folder)). In the shared mode it covers the
  startup smoke test, no daemon variable reaching a step, bytes crossing interop unchanged in both directions, and a
  timeout. In the per-run mode it covers the smoke test's two VMs, a run's tier and result, nothing left once the
  teardowns end, and two kill tests: one kills the process holding a run's VM; the other starts a separate process
  that runs the provider (its startup checks and one snippet), kills that process with SIGKILL once its run's container
  exists, and requires a fresh provider to find no session and no run folder left.
- **gVisor's live tests** (`make wslc-gvisor-suite`) passed three of three on 2026-11-13: two snippets printed gVisor's
  kernel string from inside the sandbox, a VM whose docker settings were deliberately not rewritten was refused with
  no run started, and nothing was left behind after two runs at once and a refused one. Rerun repeatedly on
  2026-11-14, one of them failed intermittently ([Known limitation](#known-limitation-a-lost-session-with-gvisor-on));
  the three passed again that day on the code as released.

**What CI can and cannot test.** plimsoll's CI runs on GitHub's hosted Linux runners, which have no WSL, so it builds
the package and runs its unit tests against the stand-in program only. GitHub's hosted Windows Server 2025 image lists
WSL 3.0.5.0 ([Windows Server 2025 runner image (EXTERNAL · source repo ↗)](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md),
read on 2026-11-14), but a WSL containers VM there would be a VM inside the runner's own VM, and GitHub's
documentation says: "While nested virtualization is technically possible while using runners, it is not officially
supported."
([GitHub-hosted runners (EXTERNAL · official docs ↗)](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)).
plimsoll has not tried it. The live suites run by hand, on a Windows machine, from a WSL distribution. A passing CI run
says nothing about WSLC itself.

## The tier, and why hardened mode refuses it

A reported tier is configuration and provider evidence plus the startup smoke test, never runtime
<dfn>*attestation*</dfn> (cryptographic proof from the hardware of what is running). For this provider it always comes
with Microsoft's own position, from the security model page of WSL's developer documentation
([WSL security model (EXTERNAL · official docs ↗)](https://wsl.dev/technical-documentation/security/), on wsl.dev,
which Microsoft's WSL overview names as the WSL open-source documentation site). Its first paragraph:

> WSL provides a Linux environment that is deeply integrated with Windows. It is not a security sandbox for running
> untrusted code.

and its section on untrusted workloads and containers:

> To isolate untrusted code from the Windows host, use a security boundary designed for that purpose, such as a
> separately managed virtual machine outside WSL with appropriately restricted access. Containers running inside WSL
> inherit the security properties of their container runtime configuration and WSL. Running a workload in a container
> does not make WSL a security boundary from the Windows host.

The VMs this provider starts are WSL's own, not VMs managed outside WSL.

- **Per-run mode: `vm`.** The tier names the mechanism, a Hyper-V VM per run. plimsolld states it with this
  qualification, word for word:

  > Hyper-V VM per run (one WSLC session per run). Microsoft states that WSL is not a security sandbox for running
  > untrusted code; the VM wall is Hyper-V's, and the Windows components around it (network relay, shares, interop) run
  > with the user's rights.

  With gVisor on, this sentence follows it:

  > gVisor, a user-space kernel on its systrap platform, also runs inside that VM as an added wall: the VM's default
  > container runtime is read back as gVisor's before each run, a run is refused when it is not, and the VM wall's
  > qualification above is unchanged.

  What is read before each run is the VM's default runtime, after the settings are written and `dockerd` reloads. The
  runtime of a container itself is read in the startup smoke test, not at each run, so a `dockerd` that restarted
  between the read-back and `container run` would not be seen.

- **Shared mode: `container`**, never `vm` and never `kernel`. Every run shares the session VM's Linux kernel, its
  `dockerd` (which runs as root) and its storage disk, and the wall between two runs is runc's. It is weaker than
  plimsoll's docker provider under runc, because five of that provider's controls are missing ([Controls](#controls)).
  The session VM stands between all of the session's containers together and Windows, not between runs: the shared mode
  does not give each container its own VM. plimsolld states the tier with this qualification, word for word:

  > One WSLC session VM shared by every run (a container per run in the caller's default session). Microsoft states that
  > WSL is not a security sandbox for running untrusted code; the wall between two runs is runc's, and this mode is
  > weaker than plimsoll's docker provider under runc.

Neither mode is the Windows feature called Hyper-V isolated containers, which is a different product.

**Where a caller reads the qualification.** `Describe`, the call that asks a daemon what it is, carries it as the string
field `isolation_qualification` (`Info.IsolationQualification` in the Go client, `isolation_qualification` in the
Python client, `isolationQualification` in the TypeScript client, and the summary text of the MCP server's
`server_info`). It is the mode's sentence above, with gVisor's added when gVisor is on.
The startup log carries it too (`isolation_qualification`), and so do `plimsolld -h` and this
page. It is informational, like the tier: no run record (the daemon's statement of what it ran and where) and no run
request carries it, and the protocol number did not change for it, so a client shows it and does not require it. A
run's record carries the tier name alone, and with gVisor on also the policy `gvisor:proven`
([below](#gvisor-inside-each-per-run-vm)).

The four reasons hardened mode refuses the per-run mode's `vm`:

1. **Microsoft disclaims it.** Hardened mode is plimsoll's statement that every protection it advertises is in force.
   plimsoll does not make that statement for a wall whose vendor says, in the sentences above, that WSL is not one.
2. **WSL's VMs share with Windows.** Every VM `wslc.exe` creates has WSL's GPU device, `/dev/dxg`, through which Linux
   shares the computer's graphics card with Windows, and the command line has no switch to turn it off. WSL also mounts
   Windows folders into every session VM: the graphics driver folders, read-only, and the share they come through. A
   run's container has none of them: the startup smoke test records what the VM has, and refuses to serve if its
   boundary-test container has the GPU device or any Windows filesystem. They are still code on the Windows side that
   is reachable from inside the VM, and the network relay, the shares and interop run with the Windows user's rights.
3. **Five controls are missing inside each VM.** WSLC cannot give a container a read-only root filesystem, a
   <dfn>*seccomp*</dfn> profile (the kernel's filter on which requests a process may make) of plimsoll's choosing,
   no-new-privileges (a bar on gaining privileges a process did not start with), a process limit, or user
   <dfn>*namespaces*</dfn> (which map root inside a container to a powerless user outside it). In the per-run mode a
   break-out of the container lands in an empty VM that is deleted after the run, so they matter less there, but they
   are absent.
4. **The per-run mode relies on an undocumented command.** Each run's VM is held open by `wslc system session enter`,
   which is in Microsoft's code but not in its documentation, so any WSL release may change or remove it. If it does,
   runs are refused; nothing falls back to the shared mode.

Hardened mode refuses the provider with gVisor on as well.

## What the operator sets up

- **A Windows machine with WSL 3.0.5 or later.** That is the first release whose `wslc container run` can drop
  capabilities (`--cap-drop`, released 2026-11-03), and the provider refuses an older one. `wsl --update` installs it
  and restarts WSL, so run it at a quiet moment.
- **plimsolld in a WSL distribution on that machine**, running as the Windows user whose WSLC sessions will run the
  code, with interop on (WSL's default).
- **The sandbox image in that user's default WSLC session:** plimsoll's sandbox image
  ([docker/Dockerfile](../docker/Dockerfile)) or one built FROM it, since every run starts plimsoll's project runner
  (`/runner.mjs`) and its guard from it. Load it with `wslc image load`, or pull it with `wslc image pull`. The per-run
  mode copies it from there into its template, by ID.
- **In the per-run mode, two programs at fixed paths:** Windows PowerShell at
  `/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe` and `mkfs.ext4` at `/usr/sbin/mkfs.ext4` in the
  distribution. No setting changes either path; the startup check refuses to start without both.

```sh
SANDBOX_PROVIDER=wslc \
SANDBOX_WSLC_IMAGE=plimsoll/sandbox@sha256:<digest> SANDBOX_REQUIRE_PINNED_IMAGES=1 plimsolld
```

The provider's variables (`plimsolld -h` lists every variable the daemon reads):

| Variable | Default | What it does, and what fails startup |
|---|---|---|
| `SANDBOX_WSLC_MODE` | `per-run` | `per-run` or `shared`; any other value fails startup. |
| `SANDBOX_WSLC_IMAGE` | none: required | The image every run starts. Letters, digits and `. _ : / @ -` only, not starting with `-`, because it becomes an argument to `wslc.exe` ([What crosses to Windows](#what-crosses-to-windows)). |
| `SANDBOX_REQUIRE_PINNED_IMAGES` | off | `1` requires `SANDBOX_WSLC_IMAGE` in the form `name@sha256:<64 hex digits>`, and the smoke test then refuses an image whose repository digests, as `wslc image inspect` reports them, do not include that digest. |
| `SANDBOX_WSLC_PATH` | `/mnt/c/Program Files/WSL/wslc.exe` | `wslc.exe` as the distribution sees it (where the WSL package installs it); an absolute path. |
| `SANDBOX_WSLC_MAX_SESSIONS` | `2` | Per-run mode only: the most runs in VMs of their own at once, 1 to 16. A run past it is refused before anything starts, marked not dispatched with reason `capacity`; a run also waits while an ended run's VM is still being torn down. The default is 2 because each live VM held about 0.9 GB of Windows memory in a sizing check on the laptop above (one machine, a design figure, not a benchmark). Set in the shared mode, it fails startup. |
| `SANDBOX_WSLC_RUN_ROOT` | the Windows user's `%LOCALAPPDATA%\plimsoll-wslc` | Per-run mode only: the folder for the template and the run disks, given as the distribution mounts it (a clean absolute path under a Windows drive, such as `/mnt/d/plimsoll-wslc`). Its Windows path must be a drive letter, then folders named with letters, digits and `. _ -` only, so a Windows user name with a space in it needs this setting. Only names plimsolld creates there are ever deleted, and each plimsolld needs a folder of its own ([One plimsolld to a run folder](#one-plimsolld-to-a-run-folder)). Who may write to it, and to the folders above it, is checked at startup ([The run folder](#the-run-folder)). Set in the shared mode, it fails startup. |
| `SANDBOX_WSLC_NPROC` | `256` | `--ulimit nproc`: the most processes of the guest user at once in the VM, 16 to 65,536. 256 is the docker provider's default process limit. In the shared mode the count covers the session VM, which runs one run at a time; in the per-run mode, the run's own VM ([Controls](#controls)). |
| `SANDBOX_WSLC_GVISOR` | off | Per-run mode only: `1` runs every container under gVisor inside its VM ([gVisor inside each per-run VM](#gvisor-inside-each-per-run-vm)). Needs the next two. Set in the shared mode, it fails startup. |
| `SANDBOX_WSLC_RUNSC_PATH` | none | With `SANDBOX_WSLC_GVISOR=1`: gVisor's `runsc` program as the distribution sees it, an absolute path. Nothing is downloaded. |
| `SANDBOX_WSLC_RUNSC_SHA512` | none | With `SANDBOX_WSLC_GVISOR=1`: that file's SHA-512, 128 lowercase hex digits. A path without a digest, or a digest that does not match, fails startup. |
| `SANDBOX_WSLC_RUNSC_HELPERS` | none | With `SANDBOX_WSLC_GVISOR=1`: the files `runsc` needs from the `gvisor-bin` folder beside it, as `NAME=SHA512` pairs separated by commas. Each is sent and checked, and the template must then hold exactly this set. |
| `SANDBOX_MEMORY_MB` | `512` | Each container's memory (`--memory`), at least 64. |
| `SANDBOX_CPUS` | `1` | Each container's CPUs (`--cpus`), above 0 and at most 64; fractions are allowed. |
| `SANDBOX_DISK_MB` | 176 | The four in-memory scratch mounts together: `/tmp`, `/var/tmp` and `/dev/shm` get 16 MiB each and `/work` the rest, at least 16 MiB, so the smallest value is 64. Unset, `/work` gets 128 MiB. |
| `SANDBOX_PIDS` | unset | Setting it fails startup: WSLC has no per-container process limit. |

A run's own time budget defaults to 30 s and is capped at 120 s, the docker provider's values for projects.
`wslc.exe` gets 60 s on top of it to start the container, because in the per-run mode that start includes booting the
VM, and WSLC's own boot timeout is 30 s. None of the three is a setting.

## What each run does

Both modes start the container with the same command, every control WSLC has:

```text
wslc.exe [--session plimsoll-run-<16 hex digits>] container run
  --rm --interactive --name plimsoll-wslc-<24 hex digits> --pull never
  --network none --dns 127.0.0.1 --dns-search .
  --cap-drop ALL --user 61000:61000
  --memory <bytes> --cpus <n>
  --ulimit nproc=<n>:<n> --ulimit nofile=4096:4096 --ulimit core=0:0
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777
  --tmpfs /var/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777
  --tmpfs /dev/shm:rw,noexec,nosuid,nodev,size=16m,mode=1777
  --tmpfs /work:rw,noexec,nosuid,nodev,size=<n>m,mode=1777
  --workdir /work --no-healthcheck --stop-timeout 1
  --entrypoint /usr/bin/env <image ID>
  -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/
  LD_PRELOAD=/usr/local/lib/plimsoll-runner-guard.so node /runner.mjs
```

The image is the one the smoke test inspected, named by its ID and never fetched. User 61000 is the docker provider's
default: a user ID no account in the image or the VM uses, so the code owns nothing in the image. Every mount's mode is
stated because WSLC 3.0.5's `dockerd` (25.0.3) mounted a `/dev/shm` with no mode stated as writable only by root,
seen on 2026-11-11. The runner starts with an empty environment; the caller's files, its steps and the image's
environment reach it as a plan on standard input, never as arguments. The runner answers with a report authenticated
by a key made for that run. A run whose report is missing or fails that check is never marked as not dispatched: its
code may have run.

**Shared mode.** The container starts in the default WSLC session of the Windows user, and of the elevation, that
plimsolld's interop calls run as (`wslc-cli-<user>`, or `wslc-cli-admin-<user>` when elevated); the startup log names
the one the smoke test landed in. The shared mode runs one run at a time, because `--ulimit nproc` counts the guest
user's processes across the whole session VM, so with two runs at once one could start processes until the other's
`fork` failed. A run takes the provider's single place before its container starts and gives it back after the
container is removed. A second run waits for its turn, no longer than its own time budget and no longer than its
caller's context; a run whose wait ends first is refused before anything started, marked not dispatched with reason
`capacity` ([INTERNAL · run results →](run-results.md)), so a caller may retry it. The cost is throughput: concurrent
callers are served in turn. A run that does not end cleanly has its container removed by name
(`wslc container remove --force`, three tries). A removal that keeps failing is logged, and the container then ends
when its runner's own time budget does, since `--rm` removes it when it exits.

**Per-run mode**, through `wslc.exe` and `powershell.exe`:

1. Copy the template disk into a new folder under the run folder, named like the run's session, with PowerShell's
   `Copy-Item`, Windows to Windows. The folder must not exist yet, so a run never starts on an older disk.
2. Start the holder, `wslc system session enter <folder> --name plimsoll-run-<16 hex digits>`, with its input a pipe:
   the session lives while that process does.
3. Wait until the session is listed, then read its VM's boot ID (the random identifier Linux picks at each boot). That
   first command boots the VM. A boot ID seen before is refused.
4. With gVisor on, write the VM's docker settings, reload `dockerd` and read the default runtime back
   ([gVisor inside each per-run VM](#gvisor-inside-each-per-run-vm)).
5. Run the container with the command above, in that session.
6. Write `exit` to the holder's input and close it, wait until the holder has exited and the session is no longer
   listed, and delete the folder. The run's result does not wait for this teardown.

Every failure before step 5 ran no code: it is marked not dispatched (reason `environment`, or `capacity` when the
caller's deadline ran out first), and whatever was started is torn down. Once step 5 has started a container, a failure
is never marked, because the code may have run. The holder's input is a root shell inside the run's VM, so plimsoll
writes only the fixed line `exit` to it, from one function, and a test fails the build if any other code writes to it.

A VM boots for every run. In gVisor's live tests of 2026-11-13, each snippet reached its result about 3.0 s after it
started. In the shared mode a run is a container start in a VM that is already running.

## Controls

| Control | On every run | How |
|---|---|---|
| No network | yes | `--network none`; the smoke test requires loopback to be the only interface and a TCP connection out to fail. |
| No capability (one of root's powers, granted one by one) | yes | `--cap-drop ALL`; the smoke test requires every capability set, the bounding set included, to be empty. |
| Not root | yes | `--user 61000:61000`, a user that owns nothing in the image. |
| Memory and CPU | yes | `--memory`, `--cpus`; the smoke test reads `memory.max` back. |
| Bounded scratch space that cannot hold a program | yes | four <dfn>*tmpfs*</dfn> mounts (filesystems held in memory) at `/tmp`, `/var/tmp`, `/dev/shm` and `/work`, each with a size and with <dfn>*noexec*</dfn> (a file there cannot be started as a program by its path), <dfn>*nosuid*</dfn> and `nodev`. `/tmp` and `/var/tmp` are writable by everyone in the image, so both are covered. |
| No core files, bounded open files | yes | `--ulimit core=0`, `--ulimit nofile=4096` (the docker provider's value). |
| No Windows folder | yes | no `-v` or `--mount`; the smoke test refuses any 9p, virtiofs, drvfs, SMB or FUSE mount, the ways a Windows folder reaches Linux. |
| No GPU | yes | the container has no `/dev/dxg`, and the smoke test refuses one that has it, though every session VM has it. |
| No host resolver settings | partly | `--dns 127.0.0.1 --dns-search .`; the smoke test refuses a nameserver other than loopback, or a search domain. |
| The image's environment for the code only | yes | the runner starts under `/usr/bin/env -i`; the steps get the image's environment from the plan. |
| **Read-only root** | **no** | no `--read-only`. Approximated: a user with no capability in an image owned by root, and the smoke test walks the whole filesystem, making a real write at every mount point and at every folder or file the code's user looks able to write, and refuses unless only the four tmpfs mounts accepted one. The gap: a folder the code's user cannot list but could write is not entered (the count is reported in the startup log). |
| **Seccomp choice** | **no** | no `--security-opt`, so plimsoll's audited seccomp profile ([INTERNAL · seccomp →](seccomp.md)) cannot be applied. The smoke test refuses to serve unless docker's default filter is in force (`Seccomp: 2`). |
| **No-new-privileges** | **no** | no `--security-opt`; the smoke test reports the value it reads. |
| **Process limit** | **no** | no `--pids-limit`, so `SANDBOX_PIDS` fails startup. `--ulimit nproc` counts every process of the code's user in the VM: in the per-run mode only the run's own; in the shared mode every run in the session VM, which is why the shared mode runs one run at a time. |
| **User namespaces** | **no** | user ID 0 in a container would be the VM's root; no run is root. |

Two further differences from the docker provider. **Logs:** there is no log driver choice, so a run's output also goes
to `dockerd`'s log in the VM until `--rm` removes the container (in the per-run mode the VM and its disk are then
deleted). **Init:** `wslc container run` has no `--init`, so the runner is process 1 and a step's orphaned child
processes stay as zombies (ended processes whose exit nobody collected) until the run ends.

## The per-run mode in detail

### The template disk

WSLC opens a session's storage folder only if it already holds a `storage.vhdx` disk, and creates one by itself only for
the default session. So at every startup plimsolld builds the template from nothing: an empty ext4 filesystem made by
the distribution's `mkfs.ext4` in a sparse file, wrapped in a dynamic VHDX (Windows' virtual hard disk format) that
plimsoll writes itself, to Microsoft's published VHDX specification; a test reads the file back by that specification.
A session is opened on it, and the pinned image is copied in from the default session by its ID (`wslc save`, then
`wslc load`). That image is the one thing that crosses: the user's own default session store is never copied, and the
build refuses a store that then holds anything else (another image, a container or a volume). A build whose session
had to be terminated instead of ending at its `exit` line is refused, since whether the image was written to the disk
then is not known.

The template's virtual size is 8 GiB, the most one run's VM can write to its copy (the image plus `dockerd`'s own
state; the code itself writes only to its in-memory mounts), which bounds how far one run can grow its copy on the
Windows drive. The file holds only the blocks written: with gVisor's files on it, 566,231,040 bytes for plimsoll's
sandbox image in gVisor's live tests of 2026-11-13, built in 7.0 s.

### The run folder

Every run boots a copy of the template kept in the run folder, and nothing checks the template between runs, so anyone
who could write there could change what every later run boots. So the startup smoke test reads Windows access lists
(through `powershell.exe`, as security identifiers and numeric rights, so the answer does not depend on the Windows
display language) and refuses to serve, naming the account:

- **The run folder itself:** unless its owner, and every account a rule (inherited rules included) gives a right to
  create, change or delete anything there or to change its permissions or owner, is the Windows user plimsolld runs
  as, SYSTEM or the Administrators group. Read access for other users is accepted.
- **Every folder above it, up to the drive's own:** if any account outside that set (plus the Windows servicing
  account that owns a drive's root) could empty, delete, rename or take over the folder, and so put another folder
  where the run folder was. Creating a new entry in a folder above, which a drive's root lets every signed-in user do,
  replaces nothing and is accepted.
- **The built template's folder and disk file:** held to the run folder's own rule, since a right set directly on
  either is in no list above it.
- **An answer it cannot read**, such as a failed script or an empty list, is refused too.

The default, under `%LOCALAPPDATA%`, belongs to the Windows user and passed these checks on the laptop above. Each list
is one `powershell.exe` start, about five seconds more at startup in all. The checks run at startup only, not between
runs, so a `SANDBOX_WSLC_RUN_ROOT` must sit under folders only this user controls.

### Freshness

A run never starts on an older disk (its folder must not exist yet), and its VM's boot ID must be new: the smoke test
requires its two VMs' boot IDs to differ from each other, from the default session's and from the distribution's, and
every run refuses a boot ID the daemon has seen before (it remembers the last 65,536). A fresh disk per run matters as
much as a fresh VM: on 2026-11-11, two VMs booted one after the other on the same disk, and the second found the files
and the volume the first had left on it.

### Nothing left behind

When the process holding a session dies, the session does not end: the session stays listed until something terminates
it. So:

- The startup smoke test terminates every listed session named `plimsoll-run-<16 hex digits>` whose folder is under
  this plimsolld's run folder, and deletes every entry plimsolld made in that folder, before it builds the template. A
  session with such a name and no folder there is another plimsolld's and is left alone.
- A run that gives up (a holder that died, a teardown that did not finish), and a sweep the daemon runs every minute
  once the template exists, do the same for every such session no live run holds. A run counts as live from the moment
  its folder is created, so a sweep never takes a run that has only started.
- At shutdown the daemon waits for the teardowns still running in the background.
- The live suite kills a process running the provider in the middle of a run, starts a fresh provider, and requires
  that no session with the prefix is listed and no run folder is left.

Each per-run plimsolld needs a run folder of its own ([One plimsolld to a run folder](#one-plimsolld-to-a-run-folder)).
After a crash followed by a change of run folder, the old folder's sessions and disks are no longer this plimsolld's
and are never swept: end them by hand with `wslc system session list` and
`wslc --session <name> system session terminate`, then delete the old folder.

## gVisor inside each per-run VM

WSLC gives no way to choose a runtime: `wslc container run` has no option for one, and every container starts under
runc. With `SANDBOX_WSLC_GVISOR=1`, plimsoll puts gVisor inside each per-run VM itself, so a run's code talks to
gVisor's kernel (its <dfn>*Sentry*</dfn> process), and gVisor to the VM's kernel, instead of the code talking to the VM's
kernel directly. It is off by default, and refused in the shared mode, which runs in the user's own default session,
whose docker settings plimsoll never rewrites.

- **The template carries gVisor.** gVisor's runtime program, <dfn>*runsc*</dfn>, and the helper programs it needs are
  the operator's files, named with their SHA-512 digests (the variables above); plimsoll's gVisor installer
  ([INTERNAL · gVisor setup →](gvisor.md)) puts a pinned release's `runsc` in `/usr/local/bin` and its four helper
  programs in `/usr/local/bin/gvisor-bin`, the files the live tests used. At startup the template build refuses any file
  whose digest is not the configured one, streams them onto the template disk on standard input (never as an argument,
  never through a Windows folder), reads each digest back inside the VM, and refuses a template that holds another
  digest, a file nobody sent, or a `runsc` that does not print a version.
- **Each run turns it on, and proves it.** WSL rewrites the VM's docker settings (`/etc/docker/daemon.json`) at every
  boot, so a setting written into the template does not survive. Before each run's container starts, plimsoll checks
  that the settings hold exactly what WSL 3.0.5 writes there (or plimsoll's own text), writes them again (WSL's own
  entry kept, runsc registered and made the default), tells `dockerd` to reload them, reads the default runtime back,
  and refuses the run, marked not dispatched with reason `environment`, unless it is runsc. Settings it has not seen
  before are refused, not overwritten. A run never falls back to runc: the code has no branch that starts a container
  otherwise. A unit test makes the stand-in report runc after the reload and requires that no container starts, and a
  live test leaves a real VM's settings as WSL wrote them and requires the run to be refused, not dispatched.
- **Each result carries the proof.** Every run dispatched after the read-back said runsc carries the policy
  `gvisor:proven`, and the run's record names it.
- **The smoke test proves it from both sides**, in both of its VMs: from inside the boundary test (gVisor's kernel
  string answers) and from the VM's side (the container's runtime read while the container exists, a running gVisor
  Sentry and its own seccomp filter, and the container's memory limit read from its cgroup in the VM). Three of its
  readings differ under gVisor and are read from the VM's side instead: the seccomp line (gVisor applies its own filter
  to the Sentry, outside the container), the memory limit, and the kernel and boot ID (gVisor's kernel has its own).
  Three mount readings are loosened under gVisor only, each narrow: a tmpfs line may lack `nodev` (`mknod` needs a
  capability, and every capability set is required to be empty), a tmpfs size may be stated among the mount options
  instead of the filesystem's own, and a 9p mount (how gVisor serves the container's files) is accepted at `/`,
  `/etc/resolv.conf`, `/etc/hostname` and `/etc/hosts` alone, while the VM's side requires the container to have no
  bind mount or volume. Every other check runs unchanged. The boundary test's container is held for 10 s while the VM's
  side is read, in each of the two VMs, so gVisor adds at least 20 s to startup.
- **The tier stays `vm`**, with Microsoft's sentence beside it and gVisor's sentence added
  ([above](#the-tier-and-why-hardened-mode-refuses-it)). Hardened mode still refuses the provider.

What it adds: a break-out would have to defeat gVisor and then the VM, two unrelated walls. gVisor brings its own wall
around system calls, which answers most of the missing seccomp choice. It does not answer Microsoft's statement, and the
other missing controls stay listed as missing, since nothing here measured them under gVisor. gVisor runs here on its
`systrap` platform because the VM has no `/dev/kvm` (no hardware virtualization is passed into it);
[gVisor's page on platforms (EXTERNAL · official docs ↗)](https://gvisor.dev/docs/user_guide/platforms/) says what its
KVM platform needs and that systrap often performs better inside a virtual machine.

What it rests on: three behaviors Microsoft has not documented, any of which a WSL release may change: `session enter`,
running a command as root in the VM through `wslc system session run`, and `dockerd` rereading
`/etc/docker/daemon.json` when told to reload. If one changes, the read-back fails and every run is refused; no run
proceeds without gVisor.

### Known limitation: a lost session with gVisor on

With gVisor on, the second of two runs started one after the other has lost its session at the settings step:
`wslc.exe` answers "Session not found" after the same session answered the boot ID read. The run is refused, marked not
dispatched with reason `environment`, so a caller may retry it, and nothing runs under runc.

It happened three times, all on 2026-11-14 within one half hour: 3 of 11 repeats of the live test that starts two runs
back to back. It has not happened since: none of the 184 runs made afterwards that day, 140 of them in a test that
starts runs back to back on one provider, each while the run before is still being torn down. A fault at a steady 3 in 11 would
leave 184 runs clean about once in a number with 25 zeros, so the fault is not steady. Inside the same half hour, 13
tries with a short wait before the reload signal all passed, which is too few to say whether a delay hides it. What
differed in that half hour was not found.

What was tried, each on fresh VMs: `dockerd` killed outright (the session stayed, so a reload signal that killed
`dockerd` could not produce this error); the reload signal sent the instant `dockerd` existed (it survived, 8 of 8);
bursts of short commands just after a session appeared (no session lost, 12 of 12); 80 reload signals across the seconds
in which the session's holder attaches (none lost, 10 of 10); and the default `wslc` session being created while a run's
session starts (none lost, 12 of 12). The cause is not known. A failed settings step says whether the session's holder
had exited and what it printed, which is how a later occurrence will tell a holder that exited from a VM that stopped.
Expect that an occasional run in this mode may be refused; retry it.

### One plimsolld to a run folder

The orphan sweep ends a session only when its folder is under this plimsolld's own run folder, so a second plimsolld on
the same Windows machine, with a run folder of its own, is left alone. Two processes cannot share one run folder: each
takes a lock on it at startup, and the second refuses to start, naming the folder. The lock has limits: it
is a file in the distribution's temporary directory, named for the folder's Windows path as written. It is not seen by a
plimsolld in another WSL distribution, by one whose temporary directory is private to it (a service unit with
`PrivateTmp`), or when one folder is reached by two spellings (a junction, a symbolic link, a `subst` drive). In those
cases give each plimsolld its own `SANDBOX_WSLC_RUN_ROOT`: two that do share a folder would end each other's runs, which
are then refused, and delete each other's template.

## Startup smoke test and readiness

- **Preflight** (at startup and on every `/readyz`): `wslc.exe` is a regular file where `SANDBOX_WSLC_PATH` says, and
  `wslc version --format json` reports 3.0.5 or later; in the per-run mode, `powershell.exe` and `mkfs.ext4` are regular
  files at their paths, and with gVisor on, the `runsc` files are where the settings say. Microsoft's code prints the
  version without starting a session VM (read from the source, not measured).
- **Smoke test** (startup only; plimsolld serves nothing if it fails):
  1. `wslc image inspect`: exactly one image, for Linux, with an ID of the form `sha256:<64 hex digits>`; no `VOLUME`
     (writable storage outside the bounded mounts); no variable in its environment that the C library or the dynamic
     loader reads before plimsoll's `/usr/bin/env -i` clears it (any `LD_` name, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`,
     `GCONV_PATH`); and, with pinning required, the pinned digest among its repository digests. Every run then starts
     the image by this ID.
  2. In the shared mode: the session VM's kernel release, boot ID, `dockerd` version, GPU device and Windows mounts,
     read through `wslc system session run`. In the per-run mode: the sweep, the access lists and the template build
     above, then two fresh sessions opened exactly as a run's, each torn down before the next, with both teardowns
     required to finish and both folders to be gone.
  3. A boundary test through the same path as every run, refused unless: loopback is the only network interface and a
     TCP connection out fails; every capability set is empty; the code's user and group are 61000 throughout, with no
     supplementary groups; a seccomp filter is in force; `memory.max` equals the configured memory and the three ulimits
     read back; a walk of the whole filesystem finds that only the four tmpfs mounts accept a real write; those mounts
     carry `noexec`, `nosuid`, `nodev` and their sizes, and no Windows filesystem is mounted; the resolver names only
     loopback and no search domain; no variable from outside reached a step; a step cannot open the runner's memory; the
     GPU device is absent; and the boundary test's kernel and boot ID are the session VM's. With gVisor on, the seccomp,
     memory, kernel and boot ID readings and three mount readings change as
     [gVisor inside each per-run VM](#gvisor-inside-each-per-run-vm) says.

The startup log states what the smoke test read: the WSL version, the kernel, the `dockerd` version, the seccomp and
no-new-privileges values, the process limits, the controls that are missing, the runtime (runc, or runsc with its
version, digest, platform and the Sentry's filter), and in the per-run mode the two VMs' boot IDs and the template's
size, or in the shared mode the session's name and boot ID.

## What crosses to Windows

plimsolld starts `wslc.exe` (and, in the per-run mode, `powershell.exe` and `mkfs.ext4`) through one function, with
`PATH` as the whole environment. So `WSLENV`, the list of variables interop copies into a Windows program, is unset,
and no variable of the daemon's (its callers' tokens, its keys) reaches Windows. Interop joins a Windows program's
arguments into one command line that the program splits again, and two parsers can disagree on spaces, quotes,
backslashes or bytes beyond ASCII. So every argument is a fixed flag, a checked ID, a checked Windows path (a drive
letter, then folders of letters, digits and `. _ -`, none of them `.` or `..`) or a PowerShell script built from fixed
text and checked paths and passed in base64, and every argument is checked against the characters
`A-Z a-z 0-9 . _ : / = , @ + -` before anything starts. Everything a caller controls travels in the runner's plan on
standard input, and the scripts the gVisor steps run inside the VM travel on standard input too. Tests fail the build
otherwise: `TestProcessesStartOnlyThroughHostCommand`, `TestWSLCEnvironmentIsPathAlone`, `TestRunArgvIsInteropSafe`,
`TestPerRunArgvIsInteropSafe` and `TestGVisorScriptsHoldOnlyCheckedNames`.

## What it does not do

- **Host-API grants** (a run's permission to call listed routes of one API through plimsoll's broker): refused before
  anything starts, marked not dispatched with reason `unsupported`, since a container with no network has no path to
  the broker.
- **plimsoll sessions**: not offered.
- **Module runs** (a compiled simulator run once per row of a parameter table): refused with reason `unsupported`.
- **Serve under hardened mode**, in either mode, with or without gVisor.
- **A per-container process limit**: `SANDBOX_PIDS` fails startup ([Controls](#controls)).
- **Name the platform image a run used.** `Describe` names the image by the ID the smoke test read
  (`wslc-image:sha256:...`), but WSLC does not report which platform manifest a run used, so a request that carries a
  software rule is refused before anything starts.
- **Languages beyond JavaScript**: a project's steps are stated to run `node`; the provider states no other language.
- **Prove that a run started.** There is no start marker, so a run that ends without an authenticated report is reported
  as one that may have run, never as not dispatched.
- **Clean up shared-mode containers a dead daemon left.** The shared mode has no sweep; the removal by name above runs
  only while the daemon lives.
- **Run two per-run daemons on one run folder** ([One plimsolld to a run folder](#one-plimsolld-to-a-run-folder)).
- **Keep your own containers apart in the shared mode.** The shared mode runs in your default WSLC session, the one
  plain `wslc` commands use: your own containers, images and volumes there sit in the same VM as the code plimsolld
  runs. Use the per-run mode, or keep nothing else in that session.
- **Run without writing to the Windows drive.** Each per-run run copies the template disk into the run folder, about
  0.5 GB on the laptop above, and deletes it afterwards.
- **Judge three readings.** The CPU limit (`--cpus`) is passed and never read back; the session VM's Windows mounts are
  recorded as evidence and a writable one is not refused; and with gVisor on, the process limit is read from
  `/proc/self/limits` and not tested by exceeding it.
- **State what network the per-run VM itself has.** The run's container has none (`--network none`, tested); the VM
  around it was not examined.

## Tests

- `go test ./sandbox/wslc` runs against a stand-in `wslc.exe` (the test program under that name) that records each
  call's arguments, environment and standard input and answers with fixed JSON. It runs anywhere, CI included, and it
  shares any misreading of Microsoft's code.
- `make wslc-docker-check`, which `make audit DOCKER=1` runs, sends the shared mode's run path, plimsoll's runner and
  the smoke test's boundary test through a second stand-in, a script that answers with the local docker
  ([sandbox/wslc/testdata/docker-standin.sh](../sandbox/wslc/testdata/docker-standin.sh)). It checks plimsoll's side of
  the path against a real container and is never evidence about WSLC. CI does not run it.
- `make wslc-suite` is the live suite: by hand, on a Windows machine with WSL 3.0.5 or later, from a WSL distribution,
  with `SANDBOX_WSLC_IMAGE` set (and `SANDBOX_WSLC_PATH` when `wslc.exe` is elsewhere). It sets `WSLC_LIVE=1`, fails
  rather than skips when its configuration is missing, and is never part of the ordinary gate. It costs nothing: WSLC
  runs on the machine itself. It covers both modes, the per-run mode with at most two VMs at once.
- `make wslc-gvisor-suite` is gVisor's live suite, run the same way with the three `SANDBOX_WSLC_RUNSC_*` settings as
  well: a run printing gVisor's kernel string, a VM whose settings were not rewritten refused with no run started, and
  nothing left behind. Find the binary with `command -v runsc`, its digest with `sha512sum`, and each helper's with
  `sha512sum "$(dirname "$(readlink -f "$(command -v runsc)")")"/gvisor-bin/*`.
