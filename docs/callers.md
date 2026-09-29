# Caller credentials

A **caller** is a program that is allowed to talk to `plimsolld`: for example, an
<dfn>*MCP*</dfn> gateway (a server that offers tools to AI models over the Model
Context Protocol), a program that hosts an AI agent, or a test <dfn>*harness*</dfn> (a
program that drives runs and checks their results). Each caller has an id, a bearer
token (the secret it sends in its `Authorization` header), and a list of scopes, the
permissions it holds. The daemon reads the whole set once, at startup, from the JSON
file named by `PLIMSOLL_CLIENTS_FILE`, and that file holds the **SHA-256
<dfn>*fingerprint*</dfn>** (the hash) of each token rather than the token itself.
Possessing the file does not give anyone a way in.

`plimsoll-clients` is the command that edits that file. It is an offline tool: it
never contacts a daemon, it never writes a token anywhere but the stdout you
explicitly ask for, and it stores only fingerprints. The daemon and the command
validate the file with the same code, so a file the command accepts is a file the
daemon loads.

## Create the first caller

From a clone, with Go 1.26.6 or newer:

```sh
TOKEN="$(go run ./cmd/plimsoll-clients create \
  -file clients.json -id mcp-gateway -token-stdout)"
```

`create` refuses to run without `-token-stdout`, because the generated token is the
only copy that will ever exist: stdout carries exactly that token and one newline,
and nothing else. Capture it straight into your secret manager. The shell variable
above is the local try-out form. Everything else the command says goes to stderr:

```
create saved for caller "mcp-gateway" in clients.json.
Not active in running daemons. Deploy this file and restart EVERY daemon using it; old credentials remain accepted until those daemons stop.
Editing this file does not cancel already admitted work.
```

The file now reads:

```json
{
  "clients": [
    {
      "id": "mcp-gateway",
      "token_sha256": "238a56a2c5dd9e2145e071fbeeb4573d90dac7e1df349fd724d1624a43eed911",
      "scopes": [
        "code:run"
      ]
    }
  ]
}
```

A new file is created with mode `0600`; an existing file keeps its mode. The token is
32 random bytes, hex encoded (256 bits of entropy). `code:run` is the default scope
and the one every RPC that runs code requires; pass `-scope` once per additional
scope.

## Start the daemon with it

```sh
SANDBOX_PROVIDER=wasm \
PLIMSOLL_ADDR=127.0.0.1:8746 \
PLIMSOLL_CLIENTS_FILE=clients.json \
go run ./cmd/plimsolld
```

Two log lines say auth is on:

```
msg="multi-client auth enabled" clients=1
msg="plimsolld listening" addr=127.0.0.1:8746 provider=wasm isolation=process auth=true ...
```

`wasm` is the <dfn>*provider*</dfn> (the backend that runs the code) that runs it inside
the daemon's own process, so it gives the weakest <dfn>*isolation tier*</dfn> (how
strong the wall around a run is), `process`: right for trying the auth path on a
laptop, wrong for hostile code (see [docs/isolation-tiers.md](isolation-tiers.md)).
Nothing about the caller setup changes when you switch to `docker` or `e2b`.

## Call it as that caller

With the Go client, the token goes in one option:

```go
remote, err := client.New("http://127.0.0.1:8746", client.WithToken(token))
```

Plain HTTP to a loopback address (reachable from this machine only) is accepted as
is; plain HTTP to any other address needs the explicit, development-only
`client.WithInsecureHTTP()`. With curl, it is the standard bearer header on a
<dfn>*Connect*</dfn> request. Connect is the RPC framework plimsolld uses, and a call
is an ordinary HTTP POST, here with a JSON body:

```sh
curl -sS -X POST http://127.0.0.1:8746/plimsoll.v1.SandboxService/Describe \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}'
```

```
{"sandbox":"wasm", "isolation":"process", "supportsJavascriptGrants":true, "protocol":2, "javascriptEnvironment":{"identity":"quickjs-wasm:sha256:f9258d318b05404d49f635191d2056c30d24ad75f2cb7f1190fdb98a76cd679e", "maxTimeoutMs":30000}, "projectEnvironment":{}, "moduleEnvironment":{}, "resources":{}}
```

The environment fields say what runs each kind of request (`javascript`, `project`,
`module`): an identity only when it is <dfn>*content-addressed*</dfn>, that is, named
by a hash of its own content (here, the hash of the embedded interpreter; empty `{}`
for kinds `wasm` does not run), and the longest a run of that kind may take.
`resources` is the set of per-run limits the operator chose, such as memory and CPU;
an empty one means every limit is the provider's default. All of it is informational:
evidence from configuration and from the provider, not <dfn>*attestation*</dfn>
(cryptographic proof, usually rooted in the hardware, of what software is running).

A wrong token and a missing token are both refused before the body is decoded, with
HTTP 401 and a Connect error body:

```
{"code":"unauthenticated","message":"invalid or expired token"}
{"code":"unauthenticated","message":"missing bearer token"}
```

A recognised token whose scopes omit `code:run` gets `permission_denied` on the
RPCs that run code instead. Every run's audit line carries the caller id
(`caller=mcp-gateway`) and never the token.

## The id is what the rest of the system sees

The caller id is the <dfn>*principal*</dfn>, the authenticated identity a request is
attributed to. A run reaches one of your APIs only through a <dfn>*grant*</dfn>,
permission attached to that run to call listed routes of one API. Over RPC a caller
selects a grant by name, from a <dfn>*grant profile*</dfn> stored on the server, and
each profile's `allowed_callers` list names the caller ids that may select it. So
the `code:run` scope alone never reaches one of your APIs. The id is also what a `jwt` profile stamps
as the `sub` (subject) claim of the <dfn>*minted*</dfn> token, the credential plimsoll
creates for one run, when a run is granted one. Pick ids you are happy to see in an
audit log and in a downstream API's logs. `*` is reserved and refused.
See [credential minting](architecture/credential-minting.md) for where the caller's
token stops and the per-run downstream credential begins.

## List, rotate, revoke

```sh
go run ./cmd/plimsoll-clients list   -file clients.json            # ids and scopes; add -json for machines
go run ./cmd/plimsoll-clients rotate -file clients.json -id mcp-gateway -token-stdout
go run ./cmd/plimsoll-clients revoke -file clients.json -id mcp-gateway
```

`list` shows ids and scopes only: no fingerprints, and nothing about a running
daemon, since the command does not talk to one. `rotate` replaces the token and keeps
the id and scopes, so `allowed_callers` lists and audit history stay valid. `revoke`
removes the entry.

**Every change is a file edit, and a running daemon holds a snapshot.** The file is
read at startup and never re-read. Until you deploy the new file and restart every
daemon that loads it, the old token keeps working and the new one does not. A run
the daemon has already accepted is never cancelled by editing the file. The command
prints this after every change because it is the step people forget.

**Rotation is a cutover, not an overlap.** One id has one fingerprint, so there is no
window in which both the old and new token are accepted. Plan a rotation as: deploy
the file, switch the caller to the new token, restart the daemon, in that order and
close together. If you need two valid tokens at once, that is two callers, and they
will appear as two identities downstream.

**Revoking the last caller leaves an empty file, which the daemon refuses to load.**
The command says so. A daemon already running keeps accepting the revoked token
until it is stopped, so stop it; do not just restart it, because it will refuse to
start until a caller is added.

## Import a token you already have

When the token is created elsewhere (a secret manager that generates secrets, a
token you are migrating), feed it on stdin; it is never accepted as an argument, so it
never lands in shell history or a process listing:

```sh
printf %s "$EXISTING_TOKEN" | go run ./cmd/plimsoll-clients import -file clients.json -id ci-runner
```

One trailing line ending is tolerated. Two separate rules apply to the token. It must
be one non-empty run of visible ASCII characters, with no spaces or control
characters, because it has to travel as one HTTP bearer value. And it may be at most
4096 bytes long: that is a bound plimsoll chose on how much input the command reads,
so that a wrong file piped in by mistake is refused instead of stored, not a limit
HTTP imposes. Neither rule checks entropy: a token you import is as strong as you
made it. `rotate -token-stdin` takes the same input to replace an existing
caller's token with one created elsewhere.

## What the file enforces

The format is [clients.example.json](clients.example.json): a `clients` array of
`{id, token_sha256, scopes}` and nothing else. Both the command and the daemon
reject unknown fields, trailing data, a missing or duplicate id, a `token_sha256`
that is not 64 hex characters, two callers sharing a fingerprint, and a scope that
is empty, repeated, or contains whitespace. Ids and fingerprints are trimmed and
fingerprints lower-cased on load, so a hand-edited file is normalised the same way
the daemon normalises it.

The command edits safely. It refuses a path that is a symlink or anything but a
regular file, takes an exclusive lock by creating `clients.json.lock` next to the
file, writes a temporary file, syncs it, and renames it over the original, so a
failure at any point leaves the previous file byte for byte intact. The lock is a
directory; if a command is killed mid-edit it stays behind, and the next run says
so. Remove it only after confirming no other edit is running. Editors that do not
use this command do not take the lock, so do not run them concurrently with it.

## Where this sits among the auth options

The daemon picks how it checks tokens in this order: `PLIMSOLL_CLIENTS_FILE` (this
file, one principal per caller), then `PLIMSOLL_TOKEN` (one shared bearer token for
every caller, with no per-caller identity), then open development mode (no token
checked), which a real provider refuses unless `PLIMSOLL_INSECURE=1` acknowledges it.
<dfn>*Hardened mode*</dfn> (`PLIMSOLL_HARDENED=1`), under which the daemon refuses to
start unless every production safeguard is configured, accepts only the clients file.
Per-caller identity is what makes the `allowed_callers` lists and per-run token
minting mean anything, so treat the shared token as a step on the way to the clients
file.
