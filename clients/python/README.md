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

An app that serves many users on one token passes `open_session(owner=user_id)`. A daemon
with `SANDBOX_MAX_SESSIONS_PER_OWNER` then holds each user to that many open sessions across
every process of the app, closing the user's least recently used idle session to open a new
one; a call on the closed session raises `SessionEndedError` with `reason == "replaced"`,
marked not dispatched, so it is safe to run again in a new session. The ID never leaves the
process: the daemon gets an HMAC-SHA256 of it (a keyed hash that cannot be reversed)
under a key derived from the client's token, so a daemon, which stores only each token's
SHA-256, cannot test a guessed ID.

For a framework that needs a bounded code call without a persistent interpreter,
`plimsoll_client.execution.CodeExecutor` runs Python or JavaScript in a fresh project:

```python
from plimsoll_client import Client
from plimsoll_client.execution import CodeExecutor

executor = CodeExecutor(Client("http://127.0.0.1:8746"))
result = executor.execute_code("print(sum([1, 2, 3]))", language="python")
print(result.steps[0].stdout_text)
```

The project image must contain the selected interpreter and its dependencies.
The default isolation floor is `kernel` (verified gVisor or a stronger VM boundary).
The default 30-second run budget bounds interactive calculations below the daemon's
five-minute ceiling; both are explicit constructor options. `files` supplies text
files, and `artifacts` names output files to capture. `.plimsoll/` is reserved for the
helper's script. The helper returns the checked `ProjectResult` unchanged, keeps
typed errors and never retries or installs packages. Each call starts fresh.

`AsyncClient` and `AsyncSession` in the same package take the same arguments and run
each call in a worker thread (`asyncio.to_thread`), for async agent frameworks.
Cancelling an awaiting task cancels its request too:

- **Not sent yet** (a session call waiting for the one before it, say): it is never
  sent, and the call ends in `RequestCanceledError` marked not dispatched (reason
  `request`).
- **In flight** (connecting, in the TLS handshake, sent or waiting for its answer):
  the connection is shut down, so the worker thread returns at once instead of waiting
  out `request_timeout`. The error is unmarked: the daemon may have received the
  request and run it. A session whose call was cut sends nothing more, since it can no
  longer follow the daemon's chain of records: open a new one.

Two calls run to their end instead. `open_session`: cutting it after the daemon had
answered would leave a session nobody holds the ID of, holding its place until it
expired, so the open finishes in its thread and a session it opens after the cancel is
closed. And `AsyncSession.close`, which is what releases the session.

The synchronous client takes the same control explicitly: pass a `CancelHandle` as
`cancel=` to `describe`, `run_javascript`, `run_project`, `run_module` or a session's
calls, and call `handle.cancel()` from any thread. One handle can cover several
requests; once cancelled it refuses every later one, with nothing sent. Name
resolution is not interrupted. Whether the daemon stops code it already started
depends on its provider: the daemon's handler passes the provider a context that ends
when the connection closes, and a provider that honors it stops the run.

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

## Google ADK executor

`plimsoll_client.adk.PlimsollCodeExecutor` implements Google ADK's Python code-block
interface over the shared fresh-execution helper. Install it with its extra,
`pip install 'plimsoll-client[adk]'` (0.20.0 and later; 0.19.0 has no extras), or from a
checkout with `pip install './clients/python[adk]'`.

```python
from plimsoll_client import Client
from plimsoll_client.adk import PlimsollCodeExecutor

executor = PlimsollCodeExecutor(client=Client(PLIMSOLL_URL, token=TOKEN))
# Supply executor as your ADK Agent's code_executor.
```

Each block gets a fresh Python sandbox. The default floor is kernel; stateful mode
is refused. Encoded text inputs and raw byte-valued output artifacts follow ADK's
file conventions. ADK consumes its native text result; `result.execution` retains
the complete checked ProjectResult. Infrastructure errors propagate without replay.
See [Google ADK guide (EXTERNAL · official docs ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/google-adk.md) for
the CSV optimization limitation, bounded error handling and a no-spend local example.

## Agno and CrewAI tools

Two optional modules give an agent one code tool over `CodeExecutor` (`plimsoll_run_code` in both):
`plimsoll_client.agno.PlimsollTools`, an Agno toolkit
([Agno toolkits (EXTERNAL · official docs ↗)](https://docs.agno.com/tools/creating-tools/toolkits)),
and `plimsoll_client.crewai.PlimsollCodeTool`, a CrewAI tool
([CrewAI custom tools (EXTERNAL · official docs ↗)](https://docs.crewai.com/en/learn/create-custom-tools)).
Each is imported only when used, so the client keeps no dependencies; install the
framework with the extra of the same name:

The `crewai` extra installs CrewAI, which installs ChromaDB for its own memory and
knowledge features. Every ChromaDB release up to 1.5.9, the latest on 2026-10-08, is
affected by advisories against a running Chroma server's HTTP API, with no fixed release
(GHSA-f4j7-r4q5-qw2c and three others). Installing the library starts no server, and
this tool configures no CrewAI memory, knowledge or embedder, so nothing here runs
ChromaDB; if your own crew enables those features, read those advisories first.

```sh
pip install 'plimsoll-client[agno]'     # or 'plimsoll-client[crewai]'; 0.20.0 and later
```

```python
from plimsoll_client import Client
from plimsoll_client.execution import CodeExecutor

executor = CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN))

# Agno
from agno.agent import Agent
from plimsoll_client.agno import PlimsollTools
agent = Agent(model=..., tools=[PlimsollTools(executor)])

# CrewAI
from crewai import Agent
from plimsoll_client.crewai import PlimsollCodeTool
agent = Agent(role=..., goal=..., backstory=..., tools=[PlimsollCodeTool(executor)])
```

Recorded calls through each tool, from a CSV sum to an answer lost after the code may have
run, replay on its integration page:
[Agno: see a run, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/integrations/agno/index.html) and
[CrewAI: see a run, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/integrations/crewai/index.html).

The model calls the tool with `code`, `language` (`"python"` or `"javascript"`, the
first of the tool's `languages` by default) and `input_files`, a list of `{path, content}`
text files written into the working directory first. Agno reserves a tool parameter named
`files` for the media it passes in and leaves it out of the schema, which is why the
parameter is `input_files` in both tools. The tool answers with JSON:

- `ran: true`: the code ran; `exit_code`, `timed_out`, `stdout`, `stderr` and `truncated`
  are the guest's, with a non-zero exit as an ordinary result. `isolation` is the tier it
  ran behind and `record_sha256` the digest of the run record the client checked.
- `ran: false`: plimsoll refused before anything ran, and `refused` says why (`request`
  or `unsupported` for something the model can change; `isolation`, `environment`,
  `capacity`, `permission` or `protocol` for the operator, which the tool also logs to the
  `plimsoll_client` logger).
- `ran: "unknown"`: an error after which the code may have run. The tool does not retry
  it, since a second run could repeat what the first did.

What the operator sets, and what the tools do not do:

- **The daemon.** It must run projects, with `python3` (and `node`, to offer JavaScript)
  in its project image, such as `plimsoll/sandbox-python` from `make docker-images`. Offer
  only the languages the image runs (`languages=("python",)`). The sandbox has no network
  and nothing is installed at run time: the libraries a model may import are the ones
  built into the image ([docs/guest-dependencies.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/guest-dependencies.md)).
- **Isolation.** `CodeExecutor`'s floor defaults to `kernel`: a daemon on docker under
  runc (container tier) refuses every call until it runs gVisor or the executor is built
  with `minimum_isolation="container"`, which is for development on your own code only.
- **Nothing persists.** Every call is a fresh sandbox: a variable, import or file from an
  earlier call is gone, and the tool's description tells the model so.
- **Cancellation.** The async paths (`agent.arun`, a CrewAI tool's `arun`) run the call in
  a worker thread with a `CancelHandle` that is cancelled with the await. Cancelled
  before Run is sent (the daemon's Describe still answering, say), the call never sends
  it. Cancelled with Run in flight, the connection is cut and the worker thread ends at
  once rather than at the executor's `timeout`; the code may have run, and the daemon
  stops it only if its provider honors the closed connection (above, under
  `AsyncClient`).
- **CrewAI's tool cache.** A crew that opts into CrewAI's tool cache (`Crew(cache=True)`; off by
  default) looks a call up in that cache by tool name and arguments before calling the tool,
  whatever the tool's `cache_function` says, so another tool of the same name could answer for
  this one with nothing run. The tool never writes to the cache, and constructing one makes every
  read of CrewAI's `CacheHandler` miss for its name
  (one process-wide wrapper of `CacheHandler.read`, which changes nothing for other tools), so CrewAI
  always calls it. A cache handler of your own that overrides `read` is not covered: turn caching
  off for such a crew (`cache=False`).
- **JavaScript is an ES module.** A JavaScript call runs as an ES module: `import`, not `require`.
- **CrewAI has no interpreter of its own any more.** Since April 2026 an agent's
  `allow_code_execution` only warns and points to hosted sandboxes (checked in CrewAI 1.15.23);
  this tool is the self-hosted option.

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
- `err.answer_not_bound` is true when the answer did not carry this request's
  `Plimsoll-Request-Id` back: an intermediary served another request's answer, or the
  daemon is older than protocol 3. Nothing it said is believed, so it has no
  `not_dispatched`; a success answer of that kind raises `AnswerNotBoundError`, a
  `DataLossError`.

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
| `SessionEndedError` | The session has ended; `reason` says why (`closed`, `expired`, `disk_exceeded`, `main_process_ended`, `boundary_failed`, `sandbox_changed`, `shutdown`; `replaced`: the daemon closed it to open a newer session for the same `owner`, at its `SANDBOX_MAX_SESSIONS_PER_OWNER`; `not_found`: the daemon has no such session, after a restart, say; `unclaimed`: no request named it before its first idle timeout, so the daemon closed it, as it does a session whose open answer was lost; or `unknown`: an end a newer daemon has). Nothing of the refused call ran: open a new session. |

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

Stopped by a `CancelHandle` (`RequestCanceledError`, code `canceled`; not asyncio's
`CancelledError`): marked not dispatched, reason `request`, when no byte of the request
had been sent; unmarked once it may have been, since the daemon may have run it.

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

The framework tools have a suite each in `frameworks/<name>/`, run by
`go test ./clients/python -run TestPythonFrameworks` in a virtual environment per
framework, at the version `frameworks/<name>/requirements.txt` pins: `make py-frameworks`
builds them under `tmp/py-frameworks/` (the first build downloads the frameworks;
nothing calls a model or a paid service). The suites call each tool through its
framework's own tool-call path (Agno's `FunctionCall`, CrewAI's `run` and `arun`), with
no model and no agent loop, against the real daemon handler; `make clients-suite` runs
them with every other client suite. The cancellation cases hold the daemon's Describe
or a Run until released, cancel the await, and count the Run requests that reach the
handler.
