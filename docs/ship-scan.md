# The ship scan

How plimsolld checks every call for material its operator has declared must never enter a sandbox (a test harness's source, hidden answers, held-out seeds) before the call runs, and what it tells the caller and the operator when it finds some.

Part of the [plimsoll README](../README.md). To see it work first, the example page runs five calls against a daemon with a withheld set and shows what the caller and the operator each saw: [INTERNAL · the ship scan, five calls →](https://plimsollmark.github.io/plimsoll/examples/ship-scan/index.html).

## Why

When agent-written code is graded, the grader's inputs must stay out of the agent's
reach. The usual leak is not an escape from the sandbox but a mistake in what is put
into it: the harness (the program that builds each run and grades it) ships its own
simulator source as a helper file, and the agent rebuilds the hidden cases from it; or a
held-out <dfn>*seed*</dfn> (the number that generates a hidden test case) is left in an
example URL in a file the agent can read. UC Berkeley's audit of 13 widely used AI
benchmarks found that "the most common pattern we exploited was submissions running in the
same process, container, or filesystem as the evaluator"
([EXTERNAL · article ↗](https://rdi.berkeley.edu/blog/trustworthy-benchmarks/)). The
ship scan checks the payload of every call against a list the operator writes, so that
mistake is caught on the call that makes it.

Both mistakes happened in the did-it-learn hackathon entry
([EXTERNAL · source repo ↗](https://github.com/carrollco/did-it-learn), 2026-10-25). The second
is checked on the entry's real files: an example link in the replay viewer,
`tasks/drone/view.mjs`, named one of the 16 practice seeds until 12:55, and the viewer was one of
the 13 files the harness put into every rebuild's sandbox; the harness's own check had looked
for the first practice seed in the task file alone. `examples/squeeze/argon-scan.sh` rebuilds
those 13 files from the public repository at 12:44 and at 12:55 and scans both offline against
the 16 seeds: at 12:44 the scan flags the viewer for `seeds.txt:2`, the second seed, and at 12:55
all 13 files are clean. Its transcript is `examples/squeeze/argon-scan.txt`. It is an offline scan
of rebuilt files, not a replay of the hackathon's sandboxes. The squeeze example's page tells it
with the entry's other mistakes, beside the squeeze test and the canary run (which is not part
of the open-source release):
[INTERNAL · three checks for an AI score, the ship scan →](https://plimsollmark.github.io/plimsoll/examples/squeeze/index.html#ship-scan).

## The withheld set

The operator declares a <dfn>*withheld set*</dfn>: a JSON file of SHA-256 digests,
named by `PLIMSOLL_WITHHELD_FILE`. plimsolld loads it at startup and refuses to start if
the file is malformed (an unknown field, a bad digest, an unknown mode), since a set that
loads with a typo scans for less than its author believes. The set holds digests, not
values: the daemon keeps no withheld value, and its log lines and refusals name an entry by
its label, never by what it holds. It does read each call's content, to compare it, and an
audit-mode find leaves the run unchanged, so code that prints a value it was given returns
that value. A set of files and long values can be committed or published as a statement of
exactly what was scanned for.

```json
{
  "version": 2,
  "mode": "refuse",
  "exempt_callers": ["judge"],
  "entries": [
    {"kind": "file",  "sha256": "<64 hex>", "label": "harness/sim.py"},
    {"kind": "value", "sha256": "<64 hex>", "length": 6, "label": "seeds.txt:3", "mode": "audit"}
  ]
}
```

Build it with `plimsoll-withheld`, which reads the files and values, writes only their
digests, and refuses a value the scan could never find. Each file is labeled by its path
from the named directory's parent (`-file /srv/harness` labels `/srv/harness/sim.py` as
`harness/sim.py`), so a label never shows a caller where the operator keeps the harness;
each value by its file's name and line. Symbolic links are skipped, and said so, and so
is an empty file (or one of blank lines), whose entry would match every empty file a
caller ships, such as an `__init__.py`; the daemon refuses a set holding one:

```sh
plimsoll-withheld build -mode refuse -values-mode audit -exempt judge \
  -file harness/ -source harness/ -values seeds.txt -values answers.txt > withheld.json
plimsoll-withheld scan -set withheld.json task/   # the same scan, offline; exit 1 on a find
```

There are three kinds of entry.

- A **file** entry is the SHA-256 of a whole file after <dfn>*normalization*</dfn>: the
  spaces, tabs and carriage returns at the end of each line, and the newlines at the end
  of the file, are dropped first. A copy with Windows line endings or trailing
  whitespace still matches. It is found as any file of a call, under any name, and as a
  snippet's or cell's code.
- A **value** entry is the SHA-256 of a short string (a seed, an answer, a key) with its
  ASCII letters lowercased, and its length in bytes. It is found in any letter case
  (`KESTREL-42`, `Kestrel-42`, `kEsTrEl-42`), and in the encodings described under
  "Encoded values" below, where it occupies whole runs of ASCII letters and digits:
  its first byte starts such a run and its last byte ends one. So the seed `731904` is
  found in `viewer.html?seed=731904&case=2` and in `seed_731904`, and not inside
  `1731904` or `731904a`, which are other numbers or names. A value must begin and end
  with a letter or digit, span at most 8 such runs (a date is 3, a UUID 5), and be 4 to
  256 bytes long; the builder's default floor is 6 bytes, because a random 6-digit number
  turns up as a whole run of digits in about one unrelated number in 900,000, and a
  4-digit one in one in 9,000.
- A **source** entry is the SHA-256 of each distinctive line of a file, and how many of
  them a shipped file must hold to be a find. It finds the copies a file entry misses:
  the harness file shipped edited, reformatted, or bundled into a larger file. "Source
  entries" below says how lines are compared and what it costs.

**Digests do not keep a short value secret.** A 6-digit seed is recovered from its
SHA-256 by trying all million candidates. Treat a set of short values as being as
sensitive as the values themselves. Lowercasing before hashing makes a mixed-case value
cheaper to guess, too: a random 10-character token of letters and digits has about 60
bits of guessing work before and about 52 after.

## Encoded values

A harness rarely ships a withheld value exactly as the operator listed it. In one
hackathon entry, a practice seed sat in an example link in a viewer file; put that link into
another link's parameter and it becomes `next=viewer.html%3Fseed%3D731904`, where the
escaped `=` (`%3D`) leaves the seed glued to the letters `3D`. A seeds file embedded in a
JSON string is `"100001\n731904\n"`, where the second seed follows the letter of the `\n`
escape. A fixture inlined into a page as a `data:` URI is base64, in which the seed is a
few characters inside a long run of letters and digits. In each of these the value is
not on run boundaries as written, so the scan reads each part in three views, and finds
a value in any of them by the same rule:

- **As written.**
- **With its escapes decoded once**, when it holds any:
  <dfn>*percent escapes*</dfn>
  ([EXTERNAL · official docs ↗](https://www.rfc-editor.org/rfc/rfc3986#section-2.1)),
  the `%HH` form URLs use for characters they cannot hold as they are, and the backslash
  escapes of JSON, JavaScript and Python strings (`\n`, `\"`, `\/`, `\xHH`, `\uHHHH` and
  the rest). So `%3D731904` reads `=731904`, `\n731904` reads a line break and then the
  seed, and a value with characters an encoder escaped (`12:30:45` as `12%3A30%3A45`,
  `café-42` as `caf\u00e9-42`) is found whichever characters the encoder chose to escape
  and in either hex case. The view as written still counts, so a literal backslash
  (`C:\temp\run7`) does not hide `run7`.
- **Base64 decoded.** <dfn>*Base64*</dfn>
  ([EXTERNAL · official docs ↗](https://www.rfc-editor.org/rfc/rfc4648#section-4))
  writes bytes as letters, digits, `+` and `/` (`-` and `_` in its URL-safe form), four
  characters for every three bytes, so the same value encodes three different ways
  depending on where it falls in a group of three: its three alignments. Every run of at
  least 6 such characters (6 hold 4 bytes, the shortest value) is decoded from its first
  character, in each alphabet, and the decoded bytes are scanned, which finds the value
  at any alignment. Inside a run, `%2B` and `%2F` (base64 inside a URL) and `\/` (inside a
  JSON string) count as `+` and `/`, and a line break after a whole number of 4-character
  groups, with any indentation after it, continues the run, so base64 wrapped at 76
  columns (the `base64` command's default) or 64 (PEM) is one blob. A file entry is also
  checked against each decoded blob, so a harness file inlined as a `data:` URI is found.

Form encoding writes a space as `+`, which the scan does not read as a space (in code it
is a plus), so the builder withholds a value holding a space twice, as written and with
`+` for each space, under one label. Entries of one label and one mode are one entry to
the scan: a refusal or an audit line names the label once.

Not decoded, and so not found: an encoding inside another (base64 inside base64, a
backslash escape inside base64, a URL encoded twice as in `%253D`), a base64 blob glued
to a letter or digit before it (it is decoded from the wrong character), and hex. Nor
can any scan of this kind find a value an agent hides on purpose (split in two,
reversed, XORed); the scan catches what a harness ships by mistake and what an agent
copies.

How often the views find something by chance: over this module's own source and
documents (4.0 MB), 1,885 random values of the usual shapes (6-digit seeds, 8-digit hex
keys, UUIDs, 10-character tokens, word-number answers) were found by the decoded views
alone 0 times (`TestViewsAddNoFindsOnOrdinaryText`). Base64-decoded ordinary text is
close to random bytes, so a 6-byte value turns up in it by chance at a given place about
once in 2^48 (256 to the sixth power), or once in 2^42 for six letters, since a letter matches
in either case; the escape view is ordinary text again, at the rate of the view as written.

## Source entries

A file entry matches only an exact copy, so a harness file shipped with a function
renamed, reindented by a formatter, pasted into a larger file or kept as a notebook's
cells is not found by it. A source entry is found by the file's lines instead:

- **A line is compared** with every space, tab and line ending removed (so reindented
  and respaced copies match), then with the quotes, comma and `\n` escape that wrap a
  line of code quoted as a string trimmed from its ends (as a notebook's JSON and a
  list of lines hold it). A <dfn>*distinctive*</dfn> line is 24 bytes or longer after that, and
  is not a comment (it does not start with `#`, `//`, `/*`, `*`, `--` or `;`): shorter
  lines (`return x`, a closing brace) and comments (a license header, a generated
  banner) are what unrelated files share.
- **The entry** holds the digest of each distinctive line of the file, each once, and
  `min_lines`, the number a shipped file must hold. The builder (`-source PATH`) sets it
  to a third of the entry's lines, and never fewer than 8, and skips a file with fewer
  than 8 distinctive lines. A third, because an edited copy keeps most of a file's lines
  and a bundled one all of them, while files of one codebase share more than one might
  expect: across this module's own code, the closest pair (two session providers
  written to one pattern) shared 83 of one's 362 lines, 69 percent of what a third needs
  and 91 percent of what a quarter would.
- **The scan** reads the distinctive lines of every whole file a call carries (a file's
  content, a snippet's or cell's code, a base64 blob, a decompressed stream, an archive
  member), as written and with its escapes decoded (a file kept in a string), and finds
  the entry when that file holds at least `min_lines` of the entry's lines. It costs one
  pass over each file and one SHA-256 per distinctive line: the most a call carries, of
  ordinary source, took 0.1 s against 20 entries (`BenchmarkScanSource`, 2026-10-28).

A source entry misses a copy of a few lines (a single function from a long file is under
a third of it) and code rewritten line by line, and a line's digest is only as secret as
the line: a line common enough to guess (an import, a standard call) can be confirmed
from the set by hashing it.

**The builder puts source entries in `audit` mode** unless `-source-mode refuse` says
otherwise. In `refuse` mode a refusal tells the caller that its file holds enough of the
harness's lines, so an agent that already holds one fewer than `min_lines` of them can
add one guessed line at a time and learn from each refusal whether the guess is in the
harness. Refuse mode suits calls whose content only the harness's developer writes.

## Archives

A harness often ships files packed: a `.tar.gz` of fixtures, a zip of a package, one
file gzipped. A call's file content must be valid UTF-8, so a compressed archive reaches
a sandbox as base64 (a step then runs `base64 -d`) or as the escapes of a byte string in
generated code (`b"\x1f\x8b..."`), and a tar of text files can ship as it is. The scan
reads inside each of them.

- **Found by its content.** An archive is recognized by the bytes it starts or ends
  with, never by a file name (the name is the caller's choice, and an archive inside a
  base64 blob has none), at any place in any view of a part: as written, with its
  escapes decoded, or in a base64 blob decoded. So an archive in the middle of a file,
  after a few bytes of something else, or inside another archive is found too.
- **The formats read**, each with Go's standard library: gzip
  ([EXTERNAL · official docs ↗](https://www.rfc-editor.org/rfc/rfc1952)), where members
  written one after another are one stream, as `gunzip` reads them; bzip2
  ([EXTERNAL · official docs ↗](https://sourceware.org/bzip2/)); zip
  ([EXTERNAL · official docs ↗](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)),
  read through its <dfn>*central directory*</dfn> (the index at a zip's end that lists
  every member and where it sits), as `unzip` reads it: stored, deflate and bzip2
  members, and zip64. A member no directory lists (a zip cut short before its directory,
  one whose directory is broken, or a member its directory leaves out) is read from the
  <dfn>*local header*</dfn> written just before its data, as `bsdtar` and Java's
  `ZipInputStream` read a zip one member after another; a stored member whose sizes
  follow its data ends where `bsdtar` ends it, at the first data descriptor (the record
  of sizes and CRC-32 written after such a member) whose CRC-32 holds, or, with CRCs
  ignored, at the first descriptor signature, and both are checked. And tar
  ([EXTERNAL · official docs ↗](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html)),
  in the POSIX, GNU and PAX forms: every 512-byte header carrying the `ustar` magic (the
  five letters a tar header holds at a fixed place) and a checksum that holds is a
  member, its size in octal or in the base-256 form GNU tar writes, and a tar written
  as a byte string's escapes is read with them decoded. And zlib
  ([EXTERNAL · official docs ↗](https://www.rfc-editor.org/rfc/rfc1950)), what Python's
  `zlib.compress` and most languages' default compressors write: a two-byte header,
  deflate data, and the Adler-32 checksum of what it inflates to.
- **A zlib stream is believed only once it has been read.** Its header is two bytes, and
  ordinary text holds valid ones now and then (`x^`, `(S`, `HK`, `hC`, `XG`, `8O`), so
  each header (the deflate method, a window of at most 32 KiB, its check bits, and no
  preset dictionary, which a reader without it cannot inflate) is tried: inflated, and
  believed only when the deflate data ends and the Adler-32 after it holds, which bytes
  that are not a stream do about once in four billion tries (2^32). A try that fails is
  a <dfn>*false start*</dfn>, neither read nor stated. Over this module's own text and
  source (1,524 files, 40.1 MB, each scanned as a call of its own), 7,569 headers were
  tried and none was believed but the one a test holds as a fixture
  (`TestZlibFalseStarts`, 2026-10-28). What the tries cost is in the bounds below. The
  false starts wrote 13.5 KB in all, at most 2 KB in one file; before PNG pixel data was
  skipped (next item) they wrote 0.8 MB, nearly all from one SVG holding a PNG image,
  whose pixels are a zlib stream cut into chunks that inflates almost to its end before
  it fails.
- **A PNG image's pixels are not read.** A PNG, found by its signature at any offset of
  any view (a data URI's base64 included), holds its pixels as one zlib stream cut
  across IDAT chunks (fdAT chunks for an animated PNG's frames), and the scan tries no
  zlib stream inside a pixel chunk whose CRC-32 holds. Most encoders write the pixels in
  chunks (all 35 images this repository publishes, in chunks of 4 KB, one of 32 KB),
  which the scan cannot read as one stream in any case. It could read an image written
  as one chunk, as some image generators write them, and there a large image (3,000 by
  3,000 pixels, 9 MB of pixel data) reached the bound on bytes decompressed, so a set
  with `refuse` entries refused a call that carried nothing withheld. What the scan is for, an answer key shipped by mistake, is
  text, not pixels. The image's other chunks are read as before: a text chunk as
  written, a compressed one (zTXt, iTXt) inflated. A pixel chunk whose CRC-32 does not
  hold, or that runs past the end of what holds it, skips nothing
  (`TestPNGPixelsAreNotRead`, 2026-10-28).
- **What is checked.** A <dfn>*decompressed stream*</dfn> (a gzip, bzip2 or zlib stream,
  a compressed zip member) is new text, so it is scanned as a whole file: against file
  entries, for values in its three views, and for archives inside it. A
  <dfn>*stored member*</dfn> (a tar member, a zip member kept uncompressed) is already
  read byte for byte in the view that holds its archive, so a value in it, or in its
  name, which the archive keeps as written, is found there; the member adds the checks
  against file and source entries, which need its bytes apart from the archive's: read
  inside the whole archive, a member's first line runs on from its header. So the harness's `sim.py` is found inside `deps.tar.gz` under any
  member name, and the seed `731904` inside a JSON file in it.

Every archive is work the request did not pay for in bytes: a gzip of 10 KB can
decompress to 10 MB (deflate's limit is about 1,032 to 1), and a gzip of gzips to far
more. So the scan reads archives within four bounds per call, shared by all its parts:

| Bound, per call | Value | Why this number |
|---|---|---|
| Bytes decompressed, in all | 8 MiB | Twice the 4 MiB of files a call may carry. Each such byte gets the full scan, so this bound sets the scan's worst cost (below). The bytes a zlib false start reads count too: input that inflates slowly costs about what scanning does. |
| Bytes of stored members checked against file and source entries, in all | 64 MiB | A member costs its line endings normalized and one SHA-256 pass, about 3 ms a megabyte, and with source entries a pass over its lines, about 2 ms a megabyte against 20 entries (measured 2026-10-30), so 64 MiB is at most 0.35 s; the bound stops headers that claim overlapping contents from making the work grow with the square of the call. The CRC-32 computed to find where a stored zip member ends counts against it too, and so do the bytes a zlib false start writes, which are inflated and never scanned: output past what a try read comes from deflate's back-references, which inflate at about 2 GB/s. |
| Archives and members, in all | 65,536 | Each costs a header's parse, and a zlib try a reader's reset and a few bytes inflated. A real archive within the byte bound holds fewer (8 MiB of tar is at most 16,384 headers), so a call that reaches this one is a call of little but headers. |
| Decompressions nested | 4 | A `.tar.gz` is one, since the tar is read in place; a `.tar.gz` of `.tar.gz` files inside a zip is three, and four leaves one level to spare. |

A bzip2 stream counts its block size (100 to 900 KB) against the 8 MiB when it starts,
since Go's reader sets aside four times that much memory for any stream, however little
it holds.

A call whose archives reach a bound, or that carries an archive the scan recognizes and
cannot read (below), is <dfn>*incomplete*</dfn>: what the scan read is still scanned,
and its finds count, but the rest was not read. A set with any `refuse` entry refuses an
incomplete call (`PermissionDenied`, reason `permission`), naming the part and why
(`files[2].content: the call's archives decompress past the scan's 8 MiB`, or
`files[0].content: a zip member is encrypted, which the scan cannot read`; the first
eight such parts, while the audit line names every one), because a `refuse` entry
promises that a call carrying it does not run, and the unread part could carry one. The
refusal tells the caller nothing about the set: whether a part is incomplete depends on
the call alone. A set of `audit` entries only lets the call run and states `incomplete`
on the operator's audit line.

The incomplete rule covers what the scan recognizes. What it cannot recognize at all
(raw deflate, a zlib stream whose checksum does not hold; "Not recognized" below) is
neither read nor stated, so `refuse` mode stops material a harness ships by mistake and
the packed shapes the scan can see, not material packed on purpose to pass it: two lines
of Python that strip a zlib stream's header and checksum before shipping it, and invert
that in a step, defeat it.

The bounds are bytes and counts, never time, so a call is scanned the same way on a busy
machine as on an idle one. A signature inside a stream that decoded cleanly is part of
it and is not read again; one after a stream that failed is read, so a broken stream
cannot hide the next one.

Recognized and not read, so the call is incomplete (refused by a set with `refuse`
entries, run and stated `incomplete` under one without), each wherever the scan looks
for archives, inside other archives included:

| What | How it is recognized | Stated as |
|---|---|---|
| An encrypted zip member | the encryption flag in its directory entry (in its local header, for a member no directory lists) | `archive_zip_encrypted` |
| A zip member compressed any way but stored, deflate or bzip2 (LZMA, zstd, xz, PPMd, deflate64 and the rest) | its method, when it holds any bytes | `archive_zip_method` |
| An xz stream | its signature and the CRC-32 of its stream flags | `archive_xz` |
| A zstd frame | its signature, a frame header with its reserved bit clear, and a first block of a valid type and at most 128 KiB (the current format; the legacy frames of zstd before 0.8, which a build may enable and has off by default since 1.6.0, are not recognized) | `archive_zstd` |
| A 7z archive | its signature, major version 0, and its start header's CRC-32 (or that header all zero, as an unfinished archive leaves it) | `archive_7z` |
| A rar archive | the RAR 4 or RAR 5 signature and the main archive header after it | `archive_rar` |
| A GNU sparse tar member | its type, `S` | `archive_tar_sparse` |
| A tar member whose size or sparse layout a PAX header sets | a `size` or `GNU.sparse.` record in the PAX header before it | `archive_tar_pax` |

Go's standard library has no package for xz, zstd, 7z or rar that a program can import
(the toolchain's own zstd decoder is internal to it), and the scan takes no dependency
outside the library, so it states them rather than reading them. Each check past a
signature asks for bytes that a program spelling the signature in a string does not
write after it (a zero byte, a CRC-32 that holds, a size within the format's limits),
so a file-type sniffer's table is not taken for an archive, with its escapes decoded or
as written.

Not recognized, and so neither found nor stated: raw deflate (deflate data with no
header or checksum, as Python's `zlib.compress(data, wbits=-15)` writes it), which Go's
library reads but no scan can find, since nothing marks where it starts; a zlib stream
whose Adler-32 does not hold, cut short or altered, since a two-byte header with no
checksum behind it is text as often as it is a stream; a format that has no signature
(the old `.lzma` form, brotli), and any other format the table does not name (lz4, lzip,
Unix `compress`); a tar in the format from before POSIX, which has no `ustar` magic; an
archive encoded twice (base64 of base64) or in hex; and bytes the shipped code itself
enciphers or rearranges. Recognized and not read, by design: a PNG image's pixel data
(above).

## What a find does

Each entry has a <dfn>*mode*</dfn>, the set's unless the entry states its own:

| Mode | The call | The caller is told | The operator's audit line |
|---|---|---|---|
| `refuse` | refused, not dispatched (`PermissionDenied`, reason `permission`) | the entries' labels and where they sit | a `withheld material refused` line naming every entry found |
| `audit` | runs | nothing | a `withheld material found` line when the find is made, and the run's line names every entry found |

Two modes, because a refusal is an answer. When the content was built by the harness,
its developer should be told, and `refuse` stops the mistake on the spot. When the
content was written by the agent being graded, telling the caller that a string is
withheld answers a question the agent should not be able to ask: an agent that guesses
an answer, sees the call refused and so learns the guess was right has found the answer
key. Use `audit` for hidden answers and held-out seeds: a find then means the answer
reached the agent, the operator voids the score, and the agent learns nothing.

A refusal names each entry by its label and its place in the request (`files[2].content`,
`files[2].path`, `steps[0]`, `artifacts[1]`, `code`), never the caller's path or content.
A label in `refuse` mode is shown to the caller, so it should say which entry, not what
it holds: `seeds.txt:3`, never `seed-731904`.

## What it reads, and when

The scan reads everything a call carries into its sandbox: a snippet's code; a project's
file paths, file contents, steps and artifact paths; a session cell's code, file paths
and contents; and the archives any of them hold ("Archives" above). Session calls are
scanned one by one like runs, and a refused one is not chained into the session's
records.

A module run carries parameter rows into a compiled simulator and no file; its scan is
stated as `not_scanned`, not as clean. A caller listed in `exempt_callers` (by its ID in
`PLIMSOLL_CLIENTS_FILE`) is not scanned, and its calls state `exempt`: that is the judge,
which ships the hidden cases into runs of its own. An unauthenticated caller is never
exempt, and neither is a caller holding the `*` scope unless it is listed.

The scan is the last check before admission, after the request's validation, its grant,
its isolation floor and its software rule. A call it reads takes its rate token
(`SANDBOX_RATE_PER_MIN`) first, because the scan is work the daemon does whatever
happens next: with the token taken at admission instead, a call the scan refused never
paid one, and a caller whose rate was spent could still have every call scanned, so the
rate would bound none of the scan's work. A caller whose rate is spent is refused before
the scan, at constant cost (`ResourceExhausted`, reason `capacity`). A call the scan
refuses has spent its token and taken nothing else: no slot, no session turn and no paid
time. Admission takes no second token, so a call that runs costs one, as without a set.
Its work is bounded by the request and the archive bounds, not by the set:
one SHA-256 per file and per decoded base64 blob, and for values at most 8 per run of
letters and digits in each view. A part of L bytes has at most L/2 runs as written and L/2 with its escapes decoded, and
its base64 blobs in both alphabets decode to at most 1.5 L bytes, so 0.75 L runs: about
14 hashes per byte at the very most, against 4 before the decoded views. The most a call
carries (about 4.4 MiB: a project's files, steps and artifact paths at their limits),
built to make one view as costly as it can be and scanned against a set declaring every
value length, took at most 1.6 s of one core (`BenchmarkScanViews`: the decoded view of
`a.a%2E` repeated, 4.3 hashes per byte; the view as written alone took 1.0 s) on a
24-core laptop with a dozen other jobs sharing it (load average 6 to 9, 2026-10-27).
Ordinary source against a set of the usual size (200 values) took 0.18 s for the same
4.4 MiB, against 0.06 s before the decoded views (`BenchmarkScanOrdinary`), since a span
is hashed only when its length is one the set declares. At most half the
daemon's cores scan at once, and any one caller at most a quarter of those, so such
requests cannot take every core, and one caller's stream of them does not make every
other caller's calls wait behind it.

A call waiting for a scan holds its decoded request, up to about 4.4 MiB, and nothing
before admission frees it, so the calls that may wait are bounded too: beyond those
scanning, as many as admission runs at once, `SANDBOX_MAX_CONCURRENT` in all and
`SANDBOX_PER_KEY_CONCURRENT` of one caller's. A call past that is refused at once, not
dispatched (`ResourceExhausted`, reason `capacity`), as admission would refuse it. The
numbers are admission's so that a caller within what the daemon would run is never
refused for having to wait, and they keep the waiting requests to half of what the
daemon may be decoding at once (twice `SANDBOX_MAX_CONCURRENT`): at the default of 8,
the scan holds at most 8 waiting requests, about 35 MiB, plus one for each scan
running.

Archives add work the request's size does not bound, so their bounds do. Against the
same set, each case built to make the scan as slow as it can (`BenchmarkScanArchives`,
load average 4, 2026-10-28): a gzip of 12 KB that decompresses to the whole 8 MiB of
`a.a%2E` repeated took 2.5 s of one core; 8 MiB of ordinary source in a `.tar.gz`, 1.8 s;
3 MiB of deflate data in blocks of one byte each, whose tables are rebuilt for every
block, 0.5 s; 65,535 zip members, 0.55 s; 65,536 gzip headers over nothing, 0.02 s. The
same day the costliest parts without an archive took 1.4 s, so the costliest call the
daemon accepts, those parts and such an archive together, is about 4 s of one core.
Reading members no directory lists, and finding where a stored member ends, added two
cases, measured the same day after that change: 65,535 zip members with no directory,
0.27 s, and a stored member with a descriptor signature every four bytes, 0.37 s; the
gzip case was then 2.6 s, so the costliest archive is unchanged. Reading zlib added four
more, measured the same day after that change (load average 2 to 4): a zlib stream that
decompresses to the whole 8 MiB of `a.a%2E`, 2.6 s, as for gzip; and false starts: the
65,536 tries the entry bound allows, 0.05 s; the deflate blocks of one byte each behind
a zlib header with no checksum, 0.53 s; 64 MiB written by tries whose checksum fails,
0.03 s. The costliest call is unchanged.

Since each scanned call spends a rate token, one caller's scans cost at most about 4 s of
a core per token: at the default `SANDBOX_RATE_PER_MIN` of 30, two cores' worth over a
minute, while its share of the scan slots bounds how many cores it holds at any moment.

## What it states

Every scanned call's audit line carries `withheld_scan` (`scanned`, `exempt`,
`not_scanned` or `incomplete`), `withheld_set` (the SHA-256 of the set file as loaded),
when anything was found `withheld_found` (labels, whatever their mode), and when the scan
was incomplete `withheld_incomplete` (each part and the bound it reached or what it
could not read, such as `files[2].content: archive_bytes` or
`files[0].content: archive_zip_encrypted`). A find, or an incomplete scan, also gets a line of its
own the moment the scan ends (`withheld material refused`, `withheld material found` or
`withheld scan incomplete`, with `withheld_refused`, the caller, the request's sizes, its
`trace_id` and, for a session call, the session), so a find in a call that admission
then refuses (the caller's concurrency, no free slot) is still written down. A daemon without a
set states nothing.

## Limits

- Neither the response nor the run record states the scan yet: a signed record shows
  what ran, not that it was scanned. Until it does, the audit line is the operator's
  evidence, and a caller learns of a find only through a refusal.
- The provider's image is not scanned: a harness file baked into the image reaches the
  sandbox without passing through a request.
- What a run fetches through a [INTERNAL · capability grant →](capability-grants.md) is not
  scanned, nor is the client a grant places in the sandbox.
- Archives are read within the bounds of "Archives": a call past one, or carrying an
  archive the scan recognizes and cannot read (an encrypted or LZMA zip member, xz,
  zstd, 7z, rar, a GNU sparse or PAX-sized tar member), is refused by a set with
  `refuse` entries and runs, stated `incomplete`, under one without. A format the scan
  does not recognize at all (raw deflate, a zlib stream whose checksum does not hold,
  lz4, a tar from before POSIX, an archive encoded twice) is neither read nor stated, so
  material packed in one on purpose passes even a `refuse` entry.
- A PNG image's pixels are not read ("Archives"): a value drawn into an image, or packed
  into its pixel data, passes even a `refuse` entry, and the call is not stated
  `incomplete`.
- A file entry matches the whole file: an edited copy, or the harness's code pasted into
  a larger file, is not found by it. A source entry finds those when a third of the
  file's distinctive lines are there; it misses a few copied lines and code rewritten
  line by line. A distinctive value withheld from the code (a constant table, an unusual
  name) catches some of those.
- A value is found only as whole runs of letters and digits, in the three views of
  "Encoded values": one level of decoding, no hex, and nothing hidden on purpose.
