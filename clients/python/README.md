# plimsoll-client for Python

A Python client for `plimsolld`, the plimsoll sandbox daemon. It runs JavaScript
snippets, multi-file projects and compiled simulators (module runs) on a daemon, opens
sessions, and makes every check the Go client in [client/](https://github.com/plimsollmark/plimsoll/tree/main/client/) makes on
what comes back. It uses the Python standard library only and needs Python 3.10 or
later.

It speaks Connect's JSON protocol over HTTP/1.1: each call is one HTTP `POST` of a
JSON message
([Connect protocol reference (EXTERNAL · official docs ↗)](https://connectrpc.com/docs/protocol/)),
with the message in protobuf's JSON form
([ProtoJSON format (EXTERNAL · official docs ↗)](https://protobuf.dev/programming-guides/json/)).
The messages are defined in [proto/plimsoll/v1/sandbox.proto](https://github.com/plimsollmark/plimsoll/blob/main/proto/plimsoll/v1/sandbox.proto).

## Install

From PyPI ([plimsoll-client (EXTERNAL · package index ↗)](https://pypi.org/project/plimsoll-client/)):

```sh
pip install plimsoll-client
```

Or from a checkout of this repository: `pip install ./clients/python`.

The distribution is `plimsoll-client`; the import package is `plimsoll_client`.

## Use

```python
from plimsoll_client import Client

c = Client("http://127.0.0.1:8746", token="...")  # the token needs the code:run scope
info = c.describe()
print(info.provider, info.isolation)

r = c.run_javascript("console.log(6*7)", timeout=10.0, minimum_isolation="process")
print(r.exit_code, r.stdout_text, r.record.sha256)

p = c.run_project(
    files={"main.js": "console.log(require('./lib.js'))", "lib.js": "module.exports = 42"},
    steps=["node main.js"],
    artifacts=[],
    minimum_isolation="container",
)
print(p.outcome, [s.stdout_text for s in p.steps])

with c.open_session(minimum_isolation="container") as s:
    s.run_javascript("require('fs').writeFileSync('/tmp/a', '1')")
    s.run_javascript("console.log(require('fs').readFileSync('/tmp/a', 'utf8'))")
    # Cells run in an interpreter the session keeps alive, so state survives calls.
    s.run_cell("import csv\nrows = list(csv.reader(open('data.csv')))", files={"data.csv": "a,b\n1,2\n"})
    print(s.run_cell("len(rows)").stdout_text)  # 2: the last expression is printed
summary = s.close()  # the call count and the last record's digest; closing again is harmless
```

`run_cell(code, language="python", files=...)` runs `code` in the session's interpreter
for `"python"` or `"javascript"`. `files` are written into the session's work directory,
the interpreter's working directory, before the code runs: the way to hand a cell data
from somewhere else, such as another tool's output. The result's `exit_code` is 0 when
the code ran, 1 when it raised (the error is on `stderr`) and 124 at the deadline;
`interpreter_started` says this call began with a fresh interpreter, so nothing defined
earlier exists. Python cells need `python3` in the daemon's image: `describe()` lists the
languages its startup checks proved on `project_environment.languages`.

`AsyncClient` and `AsyncSession` in the same package take the same arguments and run
each call in a worker thread (`asyncio.to_thread`), for async agent frameworks.
Cancelling an awaiting task stops the wait, not the request: the HTTP exchange goes on
in its thread until it ends or reaches the client's `request_timeout`, so a run it
carried may still execute. A session `open_session` opens after its await was cancelled
is closed, not left holding a place on the daemon until it expires.

Terms used below:

- An *isolation tier* is how strong the walls around a run are: `process`, `container`,
  `kernel` or `vm`, weakest first. A tier is the daemon's configuration and provider
  evidence, never runtime attestation (cryptographic proof of what a machine runs).
- A *floor* (`minimum_isolation`) is the weakest tier a request accepts.
- *Dispatch* is the moment the daemon hands the code over to start running.
- A *run record* is the daemon's statement of one run: SHA-256 digests of the request as
  sent and the result as returned, the evidence the run executed under, and when
  ([docs/run-records.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/run-records.md)).
- A *session* is one sandbox kept open for many calls: files persist between calls, and
  no process does except the interpreter the session keeps for its cells
  ([docs/sessions.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md)).
  Code an earlier call ran can change what later calls see, and a call that names a
  `grant_profile` needs a profile that allows sessions
  ([what a session gives up](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#what-a-session-gives-up)).
  A session is one trust domain: plimsoll ties it to the credential that opened it, not
  to the users behind that credential, so a service running many users' code through one
  credential must give each user (and each conversation or job) a session of their own,
  chosen by identities it verified
  ([who may share a session](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#who-may-share-a-session)).

Results are frozen dataclasses. Guest output (`stdout`, `stderr`, artifact contents) is
`bytes`, because a guest can print any byte sequence and the record covers the exact
bytes; `stdout_text` and `stderr_text` decode it as UTF-8 with invalid sequences
replaced. A non-zero `exit_code` is a normal result (the guest's code failed), not an
error. Durations that come back are whole milliseconds (`duration_ms`); durations you
pass in (`timeout`, `request_timeout`, a session's `lifetime`) are seconds.

## What the client checks

- **The base URL.** It must be an absolute `http` or `https` URL with no user name,
  password, query or fragment. Cleartext `http` is refused for any host that is not
  loopback (`localhost`, `127.0.0.0/8`, `::1`) unless you pass `insecure_http=True`: the
  bearer token and your code would otherwise cross the network unencrypted.
- **The request, before it is sent**, with the daemon's own limits: code size, step
  count and length, file count, project size, safe relative paths (no `..`, no leading
  `/`, no empty segment, no backslash, no control character), module table shape and
  result budget, a floor that is a real tier, and a software rule that is well formed.
  The trace ID (an opaque correlation ID the daemon writes on the run's audit line) must
  be 1 to 64 characters of `[A-Za-z0-9._:-]`: the daemon drops any other value without
  telling the caller, so the client refuses it instead.
- **The protocol number.** Every request states the number this client speaks
  (`PROTOCOL`); a daemon on another number refuses it before reading the payload.
  `describe()` compares the daemon's number with it and raises `ProtocolMismatchError`
  (with the description attached as `info`) when they differ.
- **Every run record.** The client recomputes the request digest from the JSON it sent
  and the result digest from the JSON it received, and checks the record's version, its
  provider, tier, environment and selected software against the answer, its software
  rule against the request, and its own digest. A single run's record must carry no
  session fields.
- **The isolation evidence.** The floor is sent with the request, so the daemon refuses
  before dispatch when its tier is below it; the tier the answer states is then checked
  against the floor again.
- **A session's chain.** Each call's record must name the session's fingerprint (the
  SHA-256 of the session ID), the next call number and the previous record's digest. At
  close, the daemon's count of executed calls and its last record must match what the
  client saw. A gap means someone else holding the session ID made a call. A call that may
  have run but ended in an error comes with its record (`PlimsollError.unanswered`, a
  version 3 record); the session checks it (its tier against the call's floor, and its
  provider, tier and software against what the session stated at open), hands it back as
  `PlimsollError.record`, keeps it in its chain and goes on. A call whose answer never
  arrived carries none, and neither does one cut short any other way (an answer this
  client cannot read, a `KeyboardInterrupt`), so the session refuses every later call
  before sending it, marked not dispatched: open a new one. Leaving a `with` block on an
  exception closes the session without hiding that exception behind the close's.
- **The response size and the time.** An answer over 32 MiB is refused, and
  `request_timeout` (default 360 seconds, above the daemon's five-minute ceiling on a run)
  bounds the whole HTTP exchange, not each socket read. Redirects are never followed and
  proxy settings in the environment are not used.

## What each error means

Every error is a `PlimsollError`. The question that decides a retry is whether
anything ran:

- `err.not_dispatched` is set (to `request`, `permission`, `protocol`, `unsupported`,
  `isolation`, `environment`, `capacity` or `unknown`) only when the daemon stated that
  nothing ran, or when the client refused the request before sending it. Sending the
  same request again, here or to another daemon, cannot run it twice.
- `err.not_dispatched is None` means the run may have executed, whatever the class or
  code. It is never a safe automatic retry of a request that is not idempotent.

Refusals. The class comes from the status code and the reason; the daemon marks these
refusals, but read `not_dispatched` rather than the class, since a daemon that predates
a procedure (sessions, for one) answers it `unimplemented` without the mark:

| Class | Meaning |
|---|---|
| `InvalidBaseURLError`, `InsecureHTTPError` | The base URL failed the check above (it must also be ASCII). Raised by the constructor. |
| `InvalidOptionError` | A token that is not visible ASCII, or a `request_timeout` that is not a positive finite number. Raised by the constructor; the message never repeats the token. |
| `InvalidRequestError` | The request is malformed or out of bounds; the client or the daemon refused it. |
| `InsufficientIsolationError` | The daemon's tier is below the floor. |
| `SoftwareMismatchError` | The software the daemon would run is outside the request's software rule. |
| `UnsupportedError`, `DisabledError` | The daemon's provider cannot do this, or runs nothing. |
| `ProtocolMismatchError` | The daemon serves another protocol number. |
| `AtCapacityError` | Shed by the daemon's admission or rate limit; retry later or elsewhere. |
| `SessionEndedError` | The session has ended; `reason` says why (`closed`, `expired`, `disk_exceeded`, `main_process_ended`, `boundary_failed`, `sandbox_changed`, `shutdown`). |

A plain `PlimsollError` carries any other Connect status in `code` (for example
`unauthenticated`), marked or not as the daemon sent it.

Answered, but the answer does not check (`DataLossError`, never marked; the run may
have executed, and `err.result` holds what came back):

| Class | Meaning |
|---|---|
| `RecordMismatchError` | The record does not match the request sent or the result received. The attached result has `record=None`. |
| `NoRecordError` | The answer carries no record. |
| `RecordVersionError` | The record uses an encoding version this client does not know. |
| `ChainError` | A session's chain is broken: a call this client did not make ran in the session. |
| `IsolationEvidenceMismatchError` | The tier the answer states is below the floor. |
| `SoftwareEvidenceMismatchError` | A session opened on software outside the requested rule (the client closes it). |
| `ResultKindMismatchError` | The answer holds a result of another kind than the request. |

No usable answer (`TransportError`, never marked): the connection failed,
`RequestTimeoutError` (the exchange outlived `request_timeout`),
`ResponseTooLargeError` (over 32 MiB), or `MalformedResponseError` (not a well-formed
message of the expected type).

## Limits

- **NaN in module outputs.** JSON writes every NaN (the floating-point "not a number"
  value) as the string `"NaN"`, which loses the bits a NaN can carry. The daemon sends
  every NaN of a module output as the quiet NaN with no sign or payload, the one
  `float("nan")` encodes to, so the record checks whichever NaN the simulator produced; a
  NaN's sign and payload do not reach the client.
- **Text files only.** A project file's content is a protobuf `string`, so it must be
  text (`str`); captured artifacts come back as `bytes`.
- **No signing.** The Go module's `attest` package signs checked records outside the
  daemon; this client checks records and does not sign or store them.

## Tests

`go test ./clients/python` serves the real daemon handler (the wasm provider for single
runs, an in-memory session provider for sessions, and test handlers that tamper with or
misstate answers) and runs the whole Python suite against it, with a fixture of digests
the Go `record` package computed. It needs `python3` 3.10 or later and no network. The
unit tests alone:

```sh
cd clients/python
PYTHONPATH=src python3 -m unittest discover -s tests -t .
```
