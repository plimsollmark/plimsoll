# plimsoll MCP server

An [MCP](https://modelcontextprotocol.io) server for `plimsolld`. MCP (the Model Context
Protocol) is how an AI agent such as Claude Code, Codex or Claude Desktop calls an outside
tool. With this server the agent can run Python or JavaScript in a plimsoll sandbox and get
back, beside the output, the isolation tier the code ran behind and the digest of a **run
record**: digests of the request as sent and the result as returned, with the provider,
image identity and policy the daemon stated, which the client recomputed before accepting
the answer ([run-records.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/run-records.md)).
`get_record` returns the record itself.

It is a Go program over plimsoll's checked Go client, in a module of its own so the MCP SDK
never enters the daemon's. It runs on your machine over stdio, or in an optional
[INTERNAL · single-owner HTTPS mode →](REMOTE.md), and talks to a `plimsolld` you
can reach. It serves MCP 2026-07-28 and the 2025 revisions (the official Go SDK, v1.8.0).

## Tools

| Tool | What it does |
|------|--------------|
| `run_code` | Runs `code` (`language` `"python"` or `"javascript"`, optional text `files` written first). Without `sandbox` the call is fresh and nothing is kept. With `sandbox`, a handle from `open_sandbox`, it runs where that handle's earlier calls ran, so files and interpreter state remain. An optional `trace` (1 to 64 letters, digits or `. _ : -`) ties the run to a log of the caller's, such as a coding session's ID, and is signed into its receipt; [the agent-session example](../../examples/agent-session/README.md) sets it from a hook. A program that fails is a result with its exit code. |
| `open_sandbox` | Opens a sandbox that keeps state and answers once the daemon has opened it, with its handle, languages, tier and when it ends. At most `PLIMSOLL_MAX_SANDBOXES` are open; past that the open is refused (`capacity`) and names the idle sandboxes in `idleSandboxes`. Nothing is ever closed for room: deleting a sandbox's state takes a `close_sandbox` naming it, so `open_sandbox` is not marked destructive. |
| `close_sandbox` | Closes a handle's sandbox; `deleted` says whether the daemon confirmed it. |
| `get_record` | The run record of a call, by the `recordSha256` its result or failure gave. The last 256 are kept in memory until the server restarts. |
| `server_info` | This server's version, its tools with a digest of their names, descriptions, schemas and annotations, and what the daemon states. If the tools listed differ from those the agent can call, the host's tool list is out of date. |

MCP's 2026-07-28 revision has no protocol sessions, so state is a handle the model passes
back. A handle is random and is never the daemon's session ID. A sandbox the daemon ended
(its lifetime, a disk limit, its memory) is replaced on the handle's next call, which says
`freshSandbox` and, in `sandboxReplaced`, why the earlier one ended; a call whose sandbox ended
as it answered says so in `sandboxEnded`.

Each successful result is one JSON value, sent both as `structuredContent` and as the text
of its one content block, because hosts differ in which they give the model. Its `summary`
states in a sentence the facts the model may need to quote; it is a field, not a separate
block, because a host that passes on only the structured value would drop the block.

A failure is a tool error whose text is JSON: `summary`, and `ran`, which is `"no"` when the
daemon or this server refused before any code was sent (with the daemon's `refusal` reason
when it gave one) and `"maybe"` when the code may have run without an answer that checked.
A `"maybe"` is never retried: running the code again could repeat what it did. A session call
that may have run still has a checked record, whose `recordSha256` the failure carries.

## Receipts

With `PLIMSOLL_SIGNING_KEY_FILE` and `PLIMSOLL_RECEIPTS_DIR` set, every checked exchange is
signed with plimsoll's attest harness into the directory, and each result's `receipt` says
where: `status` (`stored`, written and synced; or `failed`, with `reason`), `file`, `line`,
`lineSha256`, `keyId`, and `session`: `none` for a fresh run, `open` for a sandbox call until
its sandbox's close is signed, then `closed`, or `incomplete` when the server let the sandbox
go without a signed close (the daemon was gone, the host killed the server) or a call of the
sandbox could not be stored (its file then never becomes whole). A close is signed only when
the daemon's checked count is the calls the file holds. A call that may have run keeps its
failure and its record digest whatever its receipt did. `close_sandbox` reports `deleted` and, separately, `receipts`: `closed` when the signed close
is stored, or `incomplete` with `receiptsReason`. `get_record` returns the same receipt.
Receipts are refused on Windows for now: the access-control lists that would keep the key and
the receipts private there are neither set nor checked.

Each server process writes only files it created: run segments (`runs-<process>-<n>.jsonl`,
whole after every run, a new one every 500 runs or after a write that failed) and one file
per sandbox session (`session-<fingerprint>-<process>.jsonl`, whole once its close is signed).
One writer per file needs no lock on any platform. To check them, with the public key you
generated (not one found beside the files):

```sh
plimsoll-attest verify-entry -pub harness.pub -line 3 receipts/runs-....jsonl   # one line, any time
plimsoll-attest verify -pub harness.pub receipts/session-....jsonl              # a whole file
```

A receipt proves that this harness checked the exchange against its record and signed it
with your key. It is not an independent audit, and it does not make what the guest printed
true; an unanswered call's receipt proves only that the call may have run. The entries hold
the checked messages as protobuf, not the HTTP bytes. A failed receipt never turns a checked
result into a failure: the code ran, and its result is returned. An embedder can hand the
client its own recorder through `server.Config.Recorder` instead.

A sandbox runs one call at a time and holds at most four, running and waiting; the server
holds at most sixteen `run_code` calls. An open reserves its place first, so opens at once
cannot pass `PLIMSOLL_MAX_SANDBOXES`. A sandbox the server drops (closed, replaced, or left by
a call whose answer could not be checked) is closed on the daemon in the background. On a
signal the server cancels calls in progress and closes its sandboxes at once.

## Configuration

All from the environment. A value left as an unfilled placeholder such as
`${user_config.token}` is refused at startup rather than sent.

| Variable | Default | Meaning |
|----------|---------|---------|
| `PLIMSOLL_URL` | required | The daemon, such as `http://127.0.0.1:8080`. Cleartext HTTP is accepted only to loopback. |
| `PLIMSOLL_TOKEN` | none | A caller token with the `code:run` scope ([callers.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/callers.md)). Omit only for an open development daemon. |
| `PLIMSOLL_MIN_ISOLATION` | `kernel` | The weakest tier a run or sandbox accepts: `vm`, `kernel`, `container` or `process`. `kernel` is a verified gVisor runtime, the weakest fit for code you did not write. A plain docker daemon is `container`, which you must ask for. |
| `PLIMSOLL_SOFTWARE_IDENTITY` | none | Image identities allowed to run code, comma-separated, such as `oci-manifest:linux/amd64@sha256:...`. One is an exact pin, several an approved set. Checked by the daemon before each run and by the client on each answer. |
| `PLIMSOLL_TIMEOUT_MS` | `50000` | Each run's budget in the sandbox. |
| `PLIMSOLL_CALL_TIMEOUT_MS` | `80000` | A whole tool call: the daemon's Describe, opening a sandbox, waiting for its turn and the run. At least 10 s over the run budget, and under the host's own tool timeout. |
| `PLIMSOLL_SANDBOX_LIFETIME_MS` | `1800000` | Asked of the daemon for each sandbox. A host may kill the server before it closes its sandboxes (Claude Code allows half a second), so this bounds how long an orphaned sandbox holds the daemon. |
| `PLIMSOLL_LANGUAGES` | `python,javascript` | The languages `run_code` offers, the first the default; a sandbox offers those its image states. |
| `PLIMSOLL_MAX_SANDBOXES` | `3` | Handles open at once, 1 to 16. Over the remote transport one approved app holds at most one fewer, and at least 2 is required. The daemon's own caps apply too. |
| `PLIMSOLL_MAX_OUTPUT_BYTES` | `16000` | Bytes of stdout and of stderr returned to the model. |
| `PLIMSOLL_SIGNING_KEY_FILE` | none | An Ed25519 key (`plimsoll-attest keygen -out harness` writes `harness.key` and `harness.pub`). With `PLIMSOLL_RECEIPTS_DIR`, turns on signed receipts. Refused if other users can read it. |
| `PLIMSOLL_RECEIPTS_DIR` | none | Where receipts are written: created owner-only (with any missing parents), its name synced to disk before any receipt in it is called stored, and refused if other users can read it, if it is a symbolic link, or if a parent is one this user may write but not open (an entry there could not be synced). |
| `PLIMSOLL_RECEIPTS_MAX_MB` | `1024` | The directory's limit, checked when each call is admitted, and for a sandbox call again once it has its turn: past it, the call is refused before anything runs. This server's own receipts count as they are written. The directory itself (another server's files sharing it, and what you move away) is measured again once the last measurement is 30 s old, counted from when its walk began, and at every check at or past the limit, so moving receipts away lets work in at once; checks that arrive during a walk share it. A file another server wrote more than 30 s before a check is always counted; one written since may not be, and a time bound sets no bound on how many bytes another server writes in that time. A walk costs about 1.4 µs a file (143 ms at 100,000 files on ext4 with a warm cache), so a full measurement at every call would grow with every receipt ever kept. A threshold, not a reservation: a call admitted under it may take the directory past it. Nothing is deleted for you. |
| `PLIMSOLL_INSECURE_HTTP` | unset | `1` allows cleartext HTTP to a host other than loopback. Development only: the token would cross the network in clear. |

## Setup

Run a daemon first. [Getting started](https://github.com/plimsollmark/plimsoll/blob/main/docs/getting-started.md)
starts `plimsolld` and creates a caller token. Use the docker provider and set
`SANDBOX_MAX_SESSIONS` (say 8) so `open_sandbox` works; set `PLIMSOLL_MIN_ISOLATION=container`
here unless docker runs gVisor (`SANDBOX_DOCKER_RUNTIME=runsc`), which is `kernel`.

Build the server from this directory (Go 1.26):

```sh
go build -o plimsoll-mcp ./cmd/plimsoll-mcp
```

Claude Code (`-e` writes the token into `~/.claude.json` as given; the plugin below keeps it
in the system's credential store instead):

```sh
claude mcp add plimsoll -e PLIMSOLL_URL=http://127.0.0.1:8080 -e PLIMSOLL_TOKEN="$PLIMSOLL_TOKEN" -- /path/to/plimsoll-mcp
```

Codex (`~/.codex/config.toml`; `env_vars` forwards the token from the environment Codex runs
in rather than writing it into the file, and the tool timeout sits above the server's 80 s
call deadline):

```toml
[mcp_servers.plimsoll]
command = "/path/to/plimsoll-mcp"
env = { PLIMSOLL_URL = "http://127.0.0.1:8080" }
env_vars = ["PLIMSOLL_TOKEN"]
startup_timeout_sec = 30
tool_timeout_sec = 90
```

Mirror 0.1.1 (`~/.mirror/mcp/plimsoll.json`, then `/connect plimsoll`):

```json
{
  "command": "/absolute/path/to/plimsoll-mcp",
  "env": {
    "PLIMSOLL_URL": "PLIMSOLL_URL",
    "PLIMSOLL_TOKEN": "PLIMSOLL_TOKEN"
  },
  "startupTimeoutSeconds": 30,
  "toolTimeoutSeconds": 90
}
```

Mirror treats each `env` value as the **name of an environment variable**, not
its literal value. Supply `PLIMSOLL_URL` and the caller token to the process
that launches Mirror, using your credential manager. For an open development
daemon, remove the `PLIMSOLL_TOKEN` entry. To sign receipts, also forward
`PLIMSOLL_SIGNING_KEY_FILE` and `PLIMSOLL_RECEIPTS_DIR` by name. Keep keys out of
the connection file. Mirror's 90 s deadline sits above this server's default
80 s deadline.

Mirror exposes connected tools through `mcp_search`, `mcp_describe`, and
`mcp_call`. Ask it to find Plimsoll's `run_code`, inspect its schema, and run
code there. The underlying tool names include `mcp__plimsoll__run_code` and
`mcp__plimsoll__get_record`. Select Beam with `/model reflection`, or use
another model that supports tool calls. Model access and charges belong to
that model provider. Connecting this server does not isolate Mirror's other
shell or file tools. Keep approval enabled for normal use. See
[EXTERNAL · Mirror MCP documentation ↗](https://developers.reflection.ai/mirror-mcp)
and [EXTERNAL · Mirror 0.1.1 source ↗](https://github.com/reflection-oss/mirror/tree/80a9fa83c22e6ac2cc630ef907b427c295ffcc84/mirror-cli).

The Claude Code plugin in `marketplace/`, the npm launcher in `npm/` (which picks the
binary for its platform from a package npm installs for it) and the Claude Desktop bundles are
for the published release; until then, use the binary. The plugin installs the pinned package
into its own data directory and starts it from there (`marketplace/plimsoll/launch.mjs`).
Do not start the server as `npx -y @plimsollmark/mcp@<version>` from a project directory you
did not write: npx takes a package of that name and version from the directory's
`node_modules` before fetching one, and reads its `.npmrc`, so the project could run its own
program in the server's place. Install the package (`npm install -g`) and give your host the
installed command's absolute path, as the plugin does. The plugin needs Claude Code v2.1.271 or later, which its isolation setting's
list of choices requires.

## Building a release

`scripts/release.sh` builds, into `dist/`, a static binary for darwin arm64 and x64, linux
arm64 and x64, and windows x64 (`-trimpath`, no build ID: a rebuild with the same Go is
byte-identical), the npm launcher and one npm package per platform as packed tarballs, one
Claude Desktop bundle per desktop platform, and `SHA256SUMS`. A second build gives the same
`SHA256SUMS`: npm packs its tarballs with fixed times, and the bundles' entry times are set to
1980-01-01, since the bundle CLI stamps the time it ran. The bundle CLI is installed with
`npm ci` from `scripts/tools/package-lock.json`, which records a content hash for each of its
packages. It publishes nothing.
`scripts/release-check.sh` then checks `SHA256SUMS` and runs the stdio tests against what a
user gets: `@plimsollmark/mcp` installed by name from a local registry serving only these
tarballs (npm picks the platform package itself, and nothing comes from the public registry),
into a path with spaces; and on WSL the Windows bundle's binary through interop. Claude
Desktop's own install and launch of a bundle, and both macOS builds, are not exercised.

## What it does not do

- It proves what the daemon stated and the client checked, not more: a tier is the daemon's
  configuration and provider evidence plus its startup smoke tests, never hardware
  attestation.
- `get_record` keeps the last 256 records in memory; receipts on disk are kept until you
  delete them.
- No CycloneDX bill of materials yet: the mapping covers answered single project runs only,
  and is not yet a library.
- No grant profile reaches the code, and the sandbox has no network.
- No file comes back out of the sandbox except as stdout and stderr.
- Stdio is the default. Hosted clients can use the optional
  [INTERNAL · remote HTTP mode →](REMOTE.md), with passkey sign-in and explicit consent.
  Direct native-client OAuth callbacks are not supported.
