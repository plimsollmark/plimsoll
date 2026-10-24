# What a package did when you installed it

Installing an npm package runs its install script, and importing it runs its code. This
example watches that from outside a gVisor sandbox and says what the package's code tried
to do: the programs it started, the files it wrote (and where they really landed), the
files it renamed and removed, and the network calls it made, with their destinations.

The observer is gVisor's own syscall log. gVisor answers every system call the code makes,
and with `--strace` it writes each one to a file on the host, where the code inside cannot
reach it. That is the approach [OpenSSF package-analysis](https://github.com/ossf/package-analysis)
(EXTERNAL · source repo ↗) uses too.

This is the reader and its test fixtures. The signed receipt built on it is next.

## The reader: `runsclog`

`runsclog.Read` takes one runsc boot log and returns a `Trace`. It refuses a log whole
when the log is not in runsc's JSON format, ends inside an entry, lacks runsc's closing
line, carries anything between entries (gVisor writes its lost-lines marker there), or
names a runsc release the reader has not been checked against (`runsclog.Supported`).

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
- Behaviour the package keeps for later: one install and one import is one run, and code
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
