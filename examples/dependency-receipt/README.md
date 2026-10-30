# What a package did when you installed it

Installing an npm package runs its install script, and importing it runs its code. This
example watches that from outside a gVisor sandbox and says what the package's code tried
to do: the programs it started, the files it wrote (and where they really landed), the
files it renamed and removed, and the network calls it made, with their destinations.

The observer is gVisor's own syscall log. gVisor answers every system call the code makes,
and with `--strace` it writes each one to a file on the host, where the code inside cannot
reach it. That is the approach [OpenSSF package-analysis](https://github.com/ossf/package-analysis)
(EXTERNAL · source repo ↗) uses too.

Here are the reader, its test fixtures, and the signed receipt built on them.

## The signed receipt

`receipt.Build` turns one log into the receipt's claim; `receipt.Sign` signs it as an
[EXTERNAL · in-toto Statement specification ↗](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
of type `https://plimsollmark.github.io/plimsoll/dependency-behavior/v1`, in the same
envelope as plimsoll's run records. The command does both, and checks:

```sh
go run ./examples/dependency-receipt -log LOG -key harness.key -out receipt.intoto.json \
    [-bundle BUNDLE -line N]
go run ./examples/dependency-receipt -check receipt.intoto.json -pub harness.pub -log LOG \
    [-bundle BUNDLE -line N]
```

`LOG` is runsc's boot log as runsc wrote it, or gzip-compressed; the receipt names the
uncompressed bytes by their SHA-256. A key pair comes from `plimsoll-attest keygen`.

**What it states.** The sandbox the log observed; runsc's release and a digest of its
configuration (every setting it logged at boot, less the two that name per-run paths); the
processes and the programs gVisor loaded into them; every file written, named where the write
landed; and every open for writing, change and network call, on one of three sides:

- `effected`: the call returned success.
- `attempted`: the call returned an error (refused, or failed).
- `undetermined`: the log does not show the outcome. A non-blocking `connect` answers
  "in progress" (EINPROGRESS) and the connection may complete later, out of the log's sight;
  a call that never returned is here too. The network fixture's connection to
  203.0.113.7:443 is on this side. Never read `attempted` or `undetermined` as "did not
  happen".

It also lists the entries the reader could not read as one event, and signs a fixed list of
what it cannot see (the section below), so the claim's limits travel with it. A program's
arguments are kept, as the package passed them; its environment is not.

**Which run it was.** runsc logs each container's spec at boot, before any program inside
runs, and the spec names the pod's UID. A plimsoll run record (version 4 on) names the
instance that ran it, for the agent-sandbox provider `k8s-pod-uid:` and that UID. With
`-bundle` and `-line`, the run record on that line is verified, must name the log's pod, and
becomes the receipt's second subject. One pod's log covers the pod's whole life: the
agent-sandbox provider claims a pod per run and has no sessions yet, so that is one run.

**What it refuses.** No receipt is made from a log the reader refuses (above); from runsc
started without `--debug`, `--strace` or the JSON format, or with `--iouring`; from a
`--strace-syscalls` list missing a call the reader follows (the receipt would say "no
connection" where connections were not logged; an empty list, meaning every call, has not
been checked yet and is refused too); from a log with no container spec, a spec that names no
pod, or specs naming two pods; or with a run record that names another sandbox.

**How it is checked.** `-check` opens the receipt under the signer's key, rebuilds the claim
from the log (and the run record it names) and requires the two to be identical. A signer
who leaves out a connection fails, though the signature is good; so does a log changed by one
byte after signing. What the check cannot establish: that the log is the one runsc wrote for
that pod. Whoever runs the node holds the log, so that is the signer's word. The check needs
no network: on 2026-10-28 it passed on the network fixture's receipt inside a Linux network
namespace (a separate copy of the kernel's network stack) whose only interface was down (`unshare -rn`), and failed against another fixture's
log there.

## Live, through plimsoll

`go run ./examples/dependency-receipt/live` does all of it on runs plimsoll itself dispatched,
and writes the page that shows them:
[INTERNAL · the receipt, live →](https://plimsollmark.github.io/plimsoll/examples/dependency-receipt/index.html)
(source: `docs/examples/dependency-receipt/`). On a kind cluster with agent-sandbox and the
`gvisor-receipt` runtime class (`fixtures/capture.sh -install` puts its handler in the node), it
makes a namespace of its own with a warm pool under that class (`live/cluster.yaml`), starts
`plimsolld` with `SANDBOX_PROVIDER=agentsandbox` and `SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS=runsc-receipt`
in a container on kind's network, and installs and imports the `quiet`, `network` and `canary`
packages, one run each, sent as project files, with every run's record signed into one bundle.
Then it reads each run's pod log from the node, signs each receipt with `-bundle` and `-line`,
checks it, and requires three inputs to be refused: the network receipt with its connection
deleted and signed again, its log with one byte changed, and its log joined to the quiet
run's record. It deletes the namespace and the node's logs of its pods when it ends.

```sh
go run ./examples/dependency-receipt/live            # everything, fresh; needs the cluster
go run ./examples/dependency-receipt/live -verify    # the published files, offline
go run ./examples/dependency-receipt/live -render    # index.html from evidence.json
```

`-verify` starts nothing and needs no network: it verifies the bundle, checks every receipt
against its log and record, requires the three refusals, and requires the page to be what
`evidence.json` renders. The published receipts are gzip-compressed (about 380 KB each as
written, most of it npm's own work: node's compile cache, which npm turns on, is most of the
files written); gunzip one before `-check`, which reads a receipt only as written.

## The reader: `runsclog`

`runsclog.Read` takes one runsc boot log and returns a `Trace`. It refuses a log whole
when the log is not in runsc's JSON format, ends inside an entry, lacks runsc's closing
line, carries anything between entries (gVisor writes its lost-lines marker there),
names a runsc release the reader has not been checked against (`runsclog.Supported`), or is
larger than the reader takes: 256 MiB uncompressed, or an entry over 1 MiB
(`runsclog.MaxLogBytes`, `runsclog.MaxEntryBytes`). Whoever checks a receipt reads the log
its signer hands over, and before those limits a 204 KB gzip file holding one 200 MiB entry
took the checker to 685 MB of memory; it is now refused at 15 MB. The longest entry in the
fixtures is 8,316 bytes (runsc's dump of a container's spec), over 100 times under the entry
limit; the log limit is five times the 50 MB an install of express and esbuild logged with
every call traced (below).

The package under observation chooses some of the text in the log: its file names, its
process names, the paths it passes. The reader checks framing and reports ambiguous
arguments rather than guessing. Its current fixtures do not prove complete observation:

- **Only the JSON form is read.** The text form prints paths raw, so a newline in a file
  name writes what looks like a whole log line of its own. Measured: a fake connection
  broke out that way from a file name, a symlink target, a directory name and a rename.
- **Every way to split an entry into its arguments is tried.** An entry is used only when
  exactly one split fits gVisor's layout for that call; otherwise it is listed in
  `Trace.Unclear`, never guessed.
- **A program counts as loaded only when gVisor's loader logs a new stack for it.** An
  `execve` exit line reads 0 even when the file does not exist, so the failed tries along
  the search path would otherwise count as programs. The loader logs the stack before it
  maps it, so a start that fails at that point (under a tiny memory limit the program sets
  on itself) still shows; no start that succeeded is missing.
- **Files written are named where each write landed.** gVisor names the descriptor on every
  write line, so a write through `/tmp/innocent`, a symlink to `/etc/target`, is reported as
  written to `/etc/target`, per process.
- **Opens for writing keep the path as the program passed it,** joined to its directory and
  never cleaned (`d/../x` after a symlink `d` leaves another directory than its text says).
  An open is tied to the file it reached only when a later entry of the same thread names
  the descriptor and no thread in the sandbox freed that descriptor number in between, so a
  thread that closes and reuses the number cannot hand another file's name to the open.
- **What a call was given is read from its entry line** where gVisor reads the argument again
  for the exit line (a `sendmsg` header), so another thread cannot erase a send by changing
  the header during the call.
- **The environment of a started program is dropped,** also from entries the reader could
  not read (their text is withheld). runsc logs it in full, and it can hold secrets. The
  program's arguments are kept.

A child is linked to its parent after the whole log is read, since its first entry can come
before its parent's fork returns.

## What the log cannot show

- Writes through shared memory mappings (`mmap`), `sendfile`, `splice`,
  `copy_file_range` and `fallocate` are outside the current captured syscall set.
  A write-intent open can appear without any later write being observed.
- An exec attempt invalidates earlier descriptor-to-open associations for that
  process: `O_CLOEXEC` may close descriptors silently. This deliberately leaves
  an unresolved name rather than attaching a new file's name to an earlier open.

- Names looked up in DNS: a lookup shows as a datagram to port 53, not the name.
- The destination of a datagram sent with `sendmsg`, which node's UDP sockets use.
- Behavior the package keeps for later: one install and one import is one run, and code
  that waits, or checks whether it is watched, shows nothing.
- Paths of calls that take no descriptor (`mkdir`, `rename`, `unlink`, `open`) are copied
  from the program's memory before the call reads them, so a second thread can change them
  in between, and a symlink in a folder of the path can make the call land elsewhere. Files
  written are named from descriptors and are not affected. An open that only truncates a
  file through a symlink, with no write after it, is named as passed.
- io_uring, which runsc leaves off unless started with `--iouring`: its file and network work
  would not be in this log, so a successful `io_uring_setup` is listed as unclear.
- Anything outside gVisor: the Kata and microVM providers have no such log.

## The fixtures

`fixtures/packages` holds five packages, each with an install script that does one kind
of thing: `quiet` (no script), `builds` (writes inside its own directory), `canary` (writes
to `/root`, writes through a symlink into `/etc`, renames and removes a file, and has a
write refused), `network` (a TCP connection, a DNS lookup, a UDP datagram) and `child`
(starts `sh`, `id` and `uname`). `fixtures/capture.sh` installs each one offline in a
pod on a kind cluster under the `gvisor-receipt` runtime class and writes its log to
`runsclog/testdata`; `-install` first puts the handler in `fixtures/handler.toml` and the
runsc options in `fixtures/runsc-receipt.toml` into the node.

```sh
go test ./examples/dependency-receipt/...
examples/dependency-receipt/fixtures/capture.sh -install   # needs a kind cluster with gVisor
```

On an offline install of express and esbuild, the log made the install 1.6 times slower
(2.1 s to 3.5 s) and took about 50 MB before compression with every call logged; the
receipt's options log only the calls the reader follows and 16 bytes of written data,
which brings a fixture's log to about 1.8 MB.
