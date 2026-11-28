# Session files: the native helper's file commands

plimsoll's native helper, the one program every project image of plimsoll's carries at
`/usr/local/libexec/plimsoll-helper` (it is also the project runner, [guest-dependencies.md](guest-dependencies.md)),
has a second mode: `plimsoll-helper files SCOPE COMMAND ARG...`, one interface to a sandbox's
files. It is the in-sandbox half of the daemon's file calls for a
[session](trainers/glossary.html#session) (one sandbox kept for many calls): the daemon starts a
command as the guest, writes its input, and reads its answer by the contract on this page. No
client sees this wire; the daemon parses it strictly and answers in its own terms. This page is
that contract, version 8 (`nativehelper.FilesVersion`); the implementation is
[sandbox/internal/nativehelper/program/src/files.rs](../sandbox/internal/nativehelper/program/src/files.rs).

## Where the commands run, and what they can reach

- **On an image whose helper the startup check verified.** The docker, OpenShell,
  agent-sandbox and WSL containers providers check the file at that path before they serve
  anything. Each starts it with its `identity` command, which prints `inputs` and the SHA-256 of
  the build's inputs (the pin's lines for its sources, compiled in by `build.sh`), and requires
  the pinned build's line. Docker, agent-sandbox and WSL containers also read the file as root
  and check its SHA-256; OpenShell runs every command as the guest, who cannot read it (next
  point but one), so there the check is of its type, owner, mode, size and that line. The line
  tells this build from another of plimsoll's builds, a stale image's or another release's, of
  the same size (two builds a release apart were both 586,400 bytes); a program built to lie
  could print any line, so it proves nothing against an image made to deceive, and the image is
  the operator's. So wherever they serve, these commands are the version this plimsolld
  carries. E2B's templates do not carry the helper, so an E2B session's open puts the build
  this plimsolld carries at `/usr/lib/plimsoll/plimsoll-helper`, before any of the session's
  code: in a folder of the root's that the guest cannot write, never through or over
  anything it did not put there (a link, a folder or a file that is not the root's alone at
  the path refuses the session), published by a hard link, which refuses a name already
  there, mode 0711, and checked after by type, owner, mode and the SHA-256 of the bytes read
  back as root. A
  template that holds this very build there keeps it; one that holds other bytes refuses the
  session. Each file call then starts it as root and drops to the guest with `setpriv`
  (every uid and gid the guest's, no supplementary group, no-new-privs).
- **As the guest's own user.** A command is an ordinary program started as the guest. It reads
  no plan, key, report or descriptor of the project runner, and shares no code with the runner's
  report or its signing. Every open it makes is the kernel's check of the guest's own
  permissions, so code in the sandbox that starts the helper itself gets nothing its own shell
  does not have, and a race another process of the guest's wins reaches only what that process
  could reach by itself.
- **Non-dumpable from its exec.** It is *non-dumpable* (no other process of the same user may
  open its descriptors or read its memory) from before its first instruction, so a process the
  guest keeps running beside it, such as a session's interpreter, cannot change an answer while
  it is made. The helper is installed mode 0711, root's: the guest may run it and not read it,
  and the kernel makes a process that runs a program its user cannot read non-dumpable at the
  exec. Its first act makes it non-dumpable as well, which alone left a moment, from the exec to
  that call, in which another process of the guest's could open `/proc/<pid>/mem`. Measured
  2026-11-27 under runc and gVisor, on docker and on the E2B stand-in: a process of the guest's
  that starts the helper, blocked before any call of its own, is refused its memory, where the
  same opening of a program the guest may read succeeds (`TestDockerHelperIsNonDumpableFromItsExec`,
  `TestE2BSessionDockerInstallsTheHelper`).
- **Nothing but a regular file is opened for its content.** A name is first *pinned* with
  `O_PATH` (an open that opens nothing: a FIFO, a socket or a device is not opened by it) and
  classified by `fstat` on that descriptor. Only a regular file is then opened, for reading or
  writing, through `/proc/self/fd/N`: the very object classified, never a name looked up again.
  A FIFO or a device planted at a path therefore answers 85 at once and is never opened. Where
  `/proc` is not mounted, no file is opened for its content at all: a `read`, a `readmany` item, a
  `replace` of a file that is there and an `append` fail (exit 1, `ENOENT` on `/proc/self/fd`),
  and the name is never looked up again, since by then it could hold a FIFO, which an open would
  open before any check saw it.
- **Names, not inodes.** The work scope confines the names a command acts on. A hard link the
  guest made in the work folder to a file elsewhere reads as that file, and only when the guest may
  read it: the command has the guest's permissions and nothing more, and Linux refuses a hard link
  to a file the guest does not own while `fs.protected_hardlinks` is 1 (its default).

## Scopes

The first argument is the scope, which says how a path resolves.

- **`work`**: a path relative to the working folder (the daemon starts the command in the
  session's work folder), its parts separated by `/`, none empty, `.` or `..`, at most 4096 bytes;
  `.` alone names the work folder where a folder is meant.
  - **The work folder must be a mount of its own**, or every work-scope command exits 1 with
    `EXDEV` first on stderr. Why: a folder the helper has opened stays open however another
    process moves it, so without a boundary a guest process could move a folder out of the
    work folder while a call holds it, and the call's write would land where it went. A rename
    out of a mount is refused by the kernel (`EXDEV`), so on its own mount no folder can leave.
    The helper compares the mount id statx states for the work folder and for its parent.
    Docker sessions mount `/work` as a tmpfs of its own; an E2B session's open bind-mounts its
    `/work` on itself; a provider whose work folder is
    a plain folder gets no work scope until it mounts one, and an OpenShell session's is one
    ([sessions.md](sessions.md#files)), so OpenShell sessions take file calls in the
    sandbox scope alone and state so (`file_scopes`); the daemon refuses a work-scope call to
    one before it starts the helper.
  - **The work scope never crosses a mount.** A mount below the work folder (a template that
    bind-mounts another folder at `/work/shared`, or a file at `/work/config`) is another file
    system's, or another part of one, and a rename within it crosses no edge of the work mount:
    a guest process could move a folder a call holds there out of the work folder, and the call's
    write would land outside. So a path across such a mount, at any part and the last included,
    answers 86 (permission denied) for every command, a link inside that leads into it too; a
    recursive `list` lists the mount's folder as `u`, a folder it could not enter, and goes on; a
    flat `list` names it `d` (the folder it covers is the work folder's), or `o` for a file; and
    nothing is read, written, made, moved or removed through it. The sandbox scope reaches it.
    The resolution refuses it (`RESOLVE_NO_XDEV`, below), and every folder on the way, every name
    a command pins and every folder a listing enters is held to the work folder's mount, by the
    mount id `statx` states. Measured 2026-11-27 under
    runc (Linux 6.18) and gVisor, as the guest, from `/dev` (a mount of its own, with
    `/dev/shm`, `/dev/pts` and `/dev/mqueue` below it): each is 86, and `u` in a recursive listing.
  - **A path is resolved by one `openat2` call with `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`
    and `RESOLVE_NO_XDEV`** from the work folder: the kernel resolves every part, links
    included, and refuses (as 80) any step that would leave the work folder: a link to an absolute
    path, a `..` past the top, a `/proc` magic link; and (as 86) any part that is a mount. Both
    refusals are the same error (`EXDEV`), so the helper resolves the path once more without
    `RESOLVE_NO_XDEV`, opening nothing: the same error again is the leaving (80), an object on
    another mount is the mount (86), and anything else (a path another process changed meanwhile)
    is tried again, up to 16 times, after which the answer is 86. A link that stays inside (a
    virtual environment's `bin/python`, `node_modules/.bin/x`) is followed. The check is the
    kernel's own resolution, not a test before it, and a resolution a concurrent rename disturbed
    is tried again. Measured 2026-11-26 in the project images, as the guest, non-dumpable:
    `openat2` behaves so under runc (Linux 6.18) and under gVisor (runsc); the docker suite checks
    it under both (`TestDockerSessionHelperFileCommands`).
  - **The work scope needs Linux 5.8 or later, or gVisor**: a kernel with `openat2` (5.6) whose
    `statx` states mount ids (5.8). Nothing else keeps a call from crossing a mount below the work
    folder: a file system's device does not tell a second mount of the work folder's own file
    system apart, and a resolution part by part has no `RESOLVE_NO_XDEV` (review finding
    session-files-23). On a kernel without either, every work-scope command exits 1 with `ENOSYS`
    first on stderr and the cause named (`statx` or `openat2`), before any path is resolved and
    before the work folder's own mount is checked; the sandbox scope answers there as anywhere.
    Exit 1, not 86 or 2: the cause is the machine's, not a path's or the command's. Measured
    2026-11-27: runc on Linux 6.18 and gVisor (runsc) both state a mount id for `/`, a tmpfs
    `/work` and a folder under it. A docker provider's startup check starts the work scope once
    as a session's file call does, and where it answers this refusal the provider's sessions
    state the sandbox scope alone (`file_scopes`).
- **`sandbox`**: an absolute path, `/` alone the root, the same rules for its parts, resolved by
  the kernel as the guest's own shell resolves it, links followed. The sandbox's walls are the
  boundary there.

In both scopes the root is a starting point, never a folder read: the helper opens it with
`O_PATH`, as it opens every folder on the way, so a sandbox that forbids reading `/` (or the work
folder) itself but allows what lies beneath it answers every call beneath it, and a stat of the
root itself. Only a `list` of the root reads it, and there such a policy answers 86. OpenShell's
Landlock policy is one: it grants no reading of `/`'s entries (measured on OpenShell v0.1.2,
2026-11-27).

A listing never follows a link, in either scope. A listing is not isolated from changes made
while it runs, between its pages or during one: an entry made or removed meanwhile may or may not
appear, and a folder moved within the work folder during a call is acted on where it went.

## Links, per operation

What each command does with a symbolic link, by where the link is. "Followed" in the work scope
means followed when it stays inside the work folder; a link that leaves is 80 wherever it is.
The sandbox scope follows as the kernel does. The root is the work folder (`.`) or `/`.

| Command | A link before the last part | A link at the last part | A dangling link at the last part | The root |
|---|---|---|---|---|
| `stat` | followed | not followed: `k` is `l` | `l` | the folder |
| `read` | followed | followed | 81 | 2 (a file path) |
| `write replace` | followed | replaced by the new file, its target untouched | replaced by the new file | 2 |
| `write create-only` | followed | 84 | 84 | 2 |
| `write append` | followed | followed (its target is appended to) | 81, never made through | 2 |
| `mkdir` | followed | a link to a folder is a folder already there (done); to anything else 84 | 84 | 2 |
| `remove` | followed | the link itself is removed (FOLDER `1`: 83) | the link itself is removed | 2 |
| `rename` | followed | the link itself is moved, or replaced at TO | the same | 2 |
| `list` | followed (to DIR) | DIR followed; entries that are links are listed `l`, never entered | 81 | the folder |
| `readmany` | followed | followed | 81 for that item | 2 for the whole call |

Both scopes keep this table, but a link that leaves the work folder is 80 in the work scope
only.

## The words on stdin: `files SCOPE -`

A command's words can come on stdin instead of in its arguments: `plimsoll-helper files SCOPE -`
reads, from the start of stdin, the count of words in decimal (1 to 6, no sign, no leading zero),
`:`, then each word ended by a NUL (each at most 4096 bytes), the first the command; the rest of
stdin is the command's own input, as below. `files work -` with stdin `2:stat\0notes\0` is
`files work stat notes`. Anything else is 2.

The daemon always sends this form. An exec's arguments reach a sandbox as text: `docker exec`
sends them to the docker daemon as JSON strings, and JSON's encoder replaces a byte that is not
UTF-8 with U+FFFD (measured 2026-11-26: an argument `a\xffb` arrived as `a\xef\xbf\xbdb`), and a
proto3 `string` field, which a gateway's exec may take its arguments in, must be UTF-8. A name may hold any byte but `/` and NUL, so a name
that is not UTF-8 can be named only through stdin, which carries every byte. Version 1 of this
contract had the argument form alone, and its `readmany` stated no size at open.

## The commands

Numbers are plain decimal (no sign, no leading zero). Each answer is framed (next section).

| Command | Input on stdin | Answer: the frames of its entry, or of each entry |
|---|---|---|
| `stat PATH` | nothing | `k` the kind (`f` a regular file, `d` a folder, `l` a link, `o` anything else), `s` the size, `m` the permission bits (`st_mode & 07777`, in decimal), `t` the modification time in whole seconds since 1970 (0 for one before) |
| `read PATH OFFSET LENGTH` | nothing | `s` size_at_open, the file's size as its open saw it, `b` up to LENGTH bytes from OFFSET (fewer at its end, none past it); LENGTH is 1 to 8,388,608. The bytes are read to LENGTH or the end whatever size_at_open says: a file of the kernel's (`/proc`, `/sys`) states size 0 and has content, which `read` answers as `readmany` does. size_at_open promises nothing about the bytes read, since the file can change while it is read: a reader of many pieces checks each piece against its own answer, and `stat` gives the current length |
| `write PATH MODE PARENTS` | the content, at most 4,194,304 bytes (87 past it) | `n` the bytes written. MODE `replace` and `create-only` stage the content in a file of the helper's own and publish it whole (next section): the file at the name is all of the new content or as it was. `replace` keeps a regular file's permission bits and refuses one the guest may not write (86). `append` adds to the end in place. PARENTS `1` makes the folders on the way |
| `mkdir PATH PARENTS` | nothing | nothing; a folder already there is done, anything else there is 84; PARENTS `1` makes the folders on the way |
| `remove PATH FOLDER` | nothing | nothing; FOLDER `0` removes anything but a folder (82), `1` an empty folder (83 for anything else, 88 when it is not empty) |
| `rename FROM TO REPLACE` | nothing | nothing; REPLACE `0` refuses a TO already there (84), atomically (`renameat2` with `RENAME_NOREPLACE`) |
| `list DIR RECURSIVE BUDGET [MATCH]` | nothing, or a cursor | `p` the path from DIR, `k` the kind (`f`, `d`, `l`, `o`, and in a recursive listing `u`: a folder it could not enter), `s` the size (a regular file's; 0 for the rest). RECURSIVE `1` goes depth first into every folder below DIR; each folder's entries are sorted by their bytes. With MATCH, only the entries whose path matches the glob below (the walk still goes everywhere). DIR itself must be a folder the guest may read and search (86 otherwise) |
| `readmany MAX BUDGET` | at most 16,384 paths, each ended by a NUL | in the order asked, `p` the path, `s` size_at_open (the file's size as its open saw it, as `read` states it), then `b` its bytes; or `p` the path, `s` 0, then `e` the exit code below that says why it was not read (87 for a file past MAX bytes, MAX at most 8,388,608, or for the first item of an answer whose bytes would not fit the budget even alone) |

A file's bytes are always what was read, never a size measured beforehand: a file that changes
while it is read is read as it is then, and no frame can run into the next file's bytes.

## Writes: how they publish, what a success proves, what a failure leaves

**Staging (`replace`, `create-only`).** The content is written into a file made with
`O_TMPFILE`, a file with no name, so no other process can open it while it is written and
`fsync`ed. `create-only` then links it at the name with `linkat` (through `/proc/self/fd`), which
refuses a name already there (84): no staging name exists at any moment. `replace` links it at a
staging name in the same folder (`.plimsoll-write-`, the helper's process id in hex, `-`, 16 hex
digits) and renames that over the name. Where the file system has no `O_TMPFILE` (gVisor's tmpfs
answers `EOPNOTSUPP`, measured 2026-11-26 in the project images under runsc; runc's tmpfs has it)
the file is made under the staging name from the start, with `O_EXCL`, and published by the
rename (`create-only` with `RENAME_NOREPLACE`). Names starting `.plimsoll-write-` belong to the
helper.

**What a successful write proves.** The helper wrote these bytes through a descriptor of its own,
synced them, published that file at the name, and found right after the publish that the name
holds that very file (the same device and inode). It does not prove that the file still holds
them later: the guest owns the file and may change it at any time, between calls or during one.
In particular a guest process can, in the moment between the link and the rename (and, where the
file system has no `O_TMPFILE`, for the whole write), open the staging name and write into the
file the helper is about to publish; a guest process that swaps the staging name for a file of
its own is caught by the check, and the answer is then 92, never a count. A write's run record
states what the helper was sent and what it answered, as every record does
([run-records.md](run-records.md)).

**What a failed or unanswered call may have left.** No client of plimsoll's retries a call that
may have changed something (`write`, `mkdir`, `remove`, `rename`) after it gave no answer: a
request ID makes an answer trustworthy, not a call repeatable.

| Command | An answered error (an exit of the table below) | 92, or no answer (a deadline, a killed helper) |
|---|---|---|
| `write replace`, `create-only` | the file at the name as it was; no staging name (the helper removes its own); folders PARENTS made stay | the name may hold the new file, or (92) another process's file; a staging name a killed helper left is removed by the next `replace` or `create-only` write into that folder (its process gone), among the first 65,536 entries; folders PARENTS made stay |
| `write append` | nothing added: the write failed before its first byte; folders PARENTS made stay | any part may have been added, and stays (92: cut short after a part was added). It is never cut back: the length the file had says nothing of whose bytes follow it, since another process of the guest's may append between the part and any cut, which a cut would take too |
| `mkdir` | folders PARENTS made before the error stay | the folder and those on the way may have been made |
| `remove`, `rename` | nothing changed | the change may have been made |
| `stat`, `read`, `list`, `readmany` | nothing changed | nothing changed |

## Framing

Every answer is frames one after another. A frame is one tag byte, the payload's length in
decimal (no sign, no leading zero), a colon, then exactly that many bytes. The last frame, and
only the last, is `.` (the answer is whole) or `+` (it stopped at its budget), and its payload is
the decimal count of entries before it. A reader checks that the count times the frames per entry
is the number of frames it read, and that each entry's tags are the command's, and refuses
anything else. A name may hold any byte but `/` and NUL, a newline included, so no answer is a
line format.

Frames per entry: `stat` 4 (one entry), `read` 2 (one entry), `write` 1 (one entry), `list` 3,
`readmany` 3. `mkdir`, `remove` and `rename` answer nothing on success.

Example: `list . 1 8192` over a folder `x` holding a file `f` of 5 bytes answers
`p1:xk1:ds1:0p3:x/fk1:fs1:5.1:2`.

## Paging

`list` and `readmany` take a BUDGET, from 8,192 to 8,388,608 bytes: the most their whole answer
may take, its last frame included. An entry that would pass it is left out whole and the answer
ends with `+`. The least budget holds the largest entry a listing can answer (a path of 4,096
bytes, its kind and a 20-digit size: 4,130 bytes of frames) and the last frame, so **an answer
that ends with `+` always holds at least one entry**, and asking again always makes progress.

- **`list`:** ask again with the last path of the answer on stdin; the walk starts after it, in
  the same order (a flat listing's cursor is one name). Every path a listing answers is at most
  4,096 bytes, so every one is accepted back as a cursor. A tree of any size lists one budget at
  a time. The walk is depth first with an explicit stack, holding one folder's entries per level
  and never the whole tree, and each bound is checked while it is spent, never after: one call
  reads at most 1,000,000 entries from the folders it walks, holds at most 64 MiB of names at
  once (a folder is never read whole into memory: its reading stops at the bound), goes at most
  512 folders below DIR (each level holds a descriptor), and answers no path longer than 4,096
  bytes. Past any of them it ends with 91, never a cut answer; list a folder further down.
  Why these sizes (measured 2026-11-27 with plimsoll's sandbox image): a walk of 999,999 entries
  of a tmpfs, matching none, took 1.5 s under runc and 13 to 13.5 s under gVisor, and one past
  1,000,000 ended with 91 in the same time, so a call that meets the entry bound is answered
  inside the 30 s a docker file call gets by default instead of running out of time with no
  answer. 64 MiB of names (each entry counted with its own bookkeeping) fits beside a full
  128 MiB work tmpfs inside the docker provider's default 256 MiB memory cap, which both are
  charged to. 512 levels hold 512 descriptors, half of the 1,024 open files a process gets
  where nothing raises the limit (Linux's default, measured in a container with no `--ulimit`
  under runc; the docker provider's runs set 4,096). A
  folder below DIR the walk may not enter (the guest may not read it or may not search it) is
  answered with kind `u`, unreadable, and the walk goes on past it, so an answer never leaves
  out a subtree without naming it, and a recursive listing of the sandbox's `/`, which meets
  such folders at once (`/root` among them), is not ended by them. The kind is known before the
  entry is framed: the walk opens each folder it will enter for reading first. Only a
  recursive listing answers `u`; a flat one enters nothing, so it names every folder `d`. One
  gone or no longer a folder by the time the walk opens it is a change made while the listing
  ran, and lists nothing.
- **`readmany`:** the count says how many of the paths asked were answered; ask again for the
  rest. The first item of an answer whose bytes would not fit the budget even alone is answered
  as `e` 87, so `+` never comes with a count of 0: read that file with `read`, in pieces if need
  be.

## Glob

`list`'s MATCH is matched in the helper against each entry's path from DIR, part by part:
within a part, `*` is any run of bytes, `?` one byte, `[...]` one byte of a set (ranges such as
`a-z`, `!` or `^` first to negate it, `]` first to include it), and `\` makes the next byte plain;
a part that is exactly `**` is zero or more whole parts. A leading dot is not special. A pattern
that is empty, holds an empty part, a `**` inside a part, an unclosed `[` or a trailing `\` is a
malformed command. The vectors every reader of this rule checks itself against are
[sandbox/internal/nativehelper/testdata/glob-vectors.json](../sandbox/internal/nativehelper/testdata/glob-vectors.json).

A match costs at most the pattern's parts times the path's parts part matches, each at most the
two parts' lengths multiplied: every position the pattern could be at is advanced together, one
path part at a time, so a pattern of many `**` is never tried one way of splitting the path at a
time (40 `**` against a path of 61 parts ends at once; tried that way it would not end).

## Exit codes

Nothing is written to stdout unless the exit is 0.

| Exit | Meaning | Error it maps to |
|---|---|---|
| 0 | done | |
| 80 | a symbolic link the scope does not follow: in the work scope, one that leaves the work folder | `ELOOP` |
| 81 | nothing there | `ENOENT` |
| 82 | a folder where a file is meant | `EISDIR` |
| 83 | not a folder where one is meant: a part before the last, or the last for `remove PATH 1` and `list` | `ENOTDIR` |
| 84 | something is there already | `EEXIST` |
| 85 | neither a regular file nor a folder (a FIFO, a socket, a device) | none of its own |
| 86 | permission denied; in the work scope also a path across a mount below the work folder | `EACCES`, `EPERM` |
| 87 | past a size cap: one of the helper's own, or the kernel's file size limit | `EFBIG` |
| 88 | a folder that is not empty | `ENOTEMPTY` |
| 89 | no space left | `ENOSPC`, `EDQUOT` |
| 90 | a read-only file system | `EROFS` |
| 91 | a `list` call past one of its bounds (entries read, names held, depth, a path's length) | none of its own |
| 92 | a write that failed after a change it could not undo, so what the file holds is unknown; the daemon reads it as a call that gave no answer | none of its own |
| 2 | a malformed command (a path out of its scope, a bad number, flag, mode or glob); stderr says what | `EINVAL` |
| 1 | any other failure; stderr is `CODE: description, call 'path'` (a work folder that is not a mount of its own: `EXDEV`; in the work scope, a kernel that states no mount id or has no `openat2`, before Linux 5.8: `ENOSYS`) | the errno named first on stderr |

stderr names the path, so the daemon keeps it to itself: it is the guest's text.

## Versions

Version 8 (2026-11-27) needs a kernel that states mount ids and has `openat2` (Linux 5.8 or
later, or gVisor) for the work scope, and refuses every work-scope command on any other (exit 1,
`ENOSYS`), where version 7 held a path to the work folder's mount by its device on a kernel that
states no mount id, and resolved a path part by part, every link refused, on a kernel without
`openat2` (review finding session-files-23). It also answers a write past the kernel's file size limit
(`EFBIG`) as 87, where version 7 answered it as 1.

Version 7 (2026-11-27) never crosses a mount below the work folder in the work scope: a path
across one is 86, and a recursive listing lists its folder as `u`, where version 6 resolved
through it (review finding session-files-19). An append that fails after a part was added is 92
and the part stays, where version 6 cut it back and answered the write's error (session-files-22).
Where `/proc` is not mounted a file's content is not opened, where version 6 opened its name again
(session-files-21).

Version 6 (2026-11-27) reads a `read`'s bytes whatever the size its open saw: a file of the
kernel's that states size 0 (`/proc/self/status`) answers its content, where version 5 answered
no bytes from it while `readmany` answered them.

Version 5 (2026-11-27) opens the root of either scope with `O_PATH`, where version 4 opened it
for reading: where `/` or the work folder may not be read but what lies beneath it may, a call
beneath it now answers where version 4 answered 86, and only a `list` of the root itself is 86.
It also raises `readmany`'s paths from 1,024 to 16,384 a call (its budget, at most 8 MiB, still
bounds each answer), so a search of a large tree takes few calls.

Version 4 (2026-11-27) answers a folder a recursive listing may not enter as an entry of kind
`u` and goes on, where version 3 ended the whole listing with 86.

Version 3 (2026-11-26) follows links that stay inside the work folder (version 2 refused every
link in the work scope), requires the work folder to be a mount of its own, acts on a last-part
link itself in `stat`, `remove`, `rename` and a replace, raised the least budget from 64 bytes to
8,192, added exit 92 and the bounds 91 now covers, and answers a `readmany` first item too large
for its budget as 87. Version 2 added the words on stdin and `readmany`'s size at open.

## Tests

The helper's own suite ([program/tests/files.rs](../sandbox/internal/nativehelper/program/tests/files.rs),
`make rust-helper-suite`) runs each command in a scratch folder: every exit code, both scopes,
names holding any byte, paging with nothing missed or repeated and progress on every page, a tree
of 60,000 names, a walk past each of its bounds, a folder far larger than a bound never read whole,
an adversarial glob, the glob against the shared vectors, a FIFO never opened (inotify sees no
open), the helper non-dumpable while it runs, a replace that is whole or nothing and leaves no
temporary file, a staging name swapped before the rename (92), a killed replace's staging name
removed by the next write, an append out of space answering 92 with its part kept (and 89, nothing
added, when not a byte fits), every command refused across a mount below the work folder (a folder
and a file bind-mounted there, through `openat2`; listed `u` and never
entered), every work-scope command refused on a kernel that states no mount id or has no `openat2`
(exit 1, `ENOSYS`), no file opened by its name where `/proc` is not mounted, a hard link that reads only what
the guest can read, the link table, a folder swapped for a link in a loop while a file under it is
read, calls in both scopes beneath a root the guest may not read (confined by a Landlock
ruleset of the test's own, the kernel's access control OpenShell uses), and an ancestor moved out of the work folder while a call holds it (refused: the scratch
folder is not a mount; on a tmpfs of its own, in a user namespace, the move itself is refused).
The races are driven through pause points, the mount rule is lifted, and a kernel without mount ids
or `openat2` is answered as one, through test hooks compiled into a debug build alone; the pinned helper holds none (`TestPinnedHelperHoldsNoTestHooks`).
[sandbox/docker_files_test.go](../sandbox/docker_files_test.go) drives every command in a real
docker session as the guest, under runc and under gVisor (`SANDBOX_DOCKER_RUNTIME=runsc`), and the
conformance suite ([sandbox/sessiontest/files.go](../sandbox/sessiontest/files.go)) drives the
daemon's file calls.
