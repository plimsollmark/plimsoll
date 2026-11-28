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

The session part of this example needs a daemon started with sessions on (`SANDBOX_MAX_SESSIONS`, for example
`SANDBOX_MAX_SESSIONS=4`; they are off by default), and its Python cells need `python3` in the project image (on
docker, `SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python:latest`).

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
languages a session's cells run in on `session_environment.languages`.

A call that keeps nothing for a later one is a cell the daemon runs by itself:
`c.run_cell(code, language="python", files=..., prefer_warm=True)`. With `prefer_warm` a
daemon that keeps a warm pool (`describe()` states `session_pool`) runs it in a waiting
sandbox that has run only plimsoll's own programs, claimed for this call and deleted after
it, so it answers without a sandbox being made; with no pool or none waiting it runs in a
sandbox made for it, and a miss is never an error. `result.warm` says which ran. What it
costs: a pool sandbox runs the cell in the session's image (on docker the project image,
which a fresh cell uses too); the run record is a single run's either way and does not
cover `warm` ([docs/sessions.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md), "A cell for one call").
`AsyncClient.run_cell` is the same in a worker thread. `CodeExecutor` does not use it: its
fresh run is a script, not a cell.

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
- **In flight**: the connection is shut down, so the worker thread returns at once
  instead of waiting out `request_timeout`. A cancel while connecting or in the TLS
  handshake, before the first byte went out, is still marked not dispatched (reason
  `request`); one after the request was sent, or while waiting for its answer, is
  unmarked: the daemon may have received the request and run it. A session whose call was cut sends nothing more, since it can no
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

## Carrying a session on from another process

A session can be taken over by another process of your application, a workflow step
retried on another machine, say, with the same token. Give the client a short name for
the daemon (`daemon_name`, never a URL) and a *checkpoint store*: an object with
`load(key)` and an atomic `compare_and_set(key, expected, replacement)`, kept where only
your application can write. Every call of a session opened with a store passes through
it: before the call its record is marked pending, after a checked answer it is ready at the
new head.

```python
from plimsoll_client import Client, MemoryCheckpointStore

store = MemoryCheckpointStore()  # for tests only: use storage only your app can write
key = f"{user_id}/{thread_id}"   # from identities your app verified, never model or user text
c = Client(url, token, daemon_name="prod")
s = c.open_session(checkpoint_store=store, checkpoint_key=key)
s.run_cell("x = 1")
# In another process, with the same token, store and daemon name:
t = Client(url, token, daemon_name="prod").attach_session(key, store=store)
t.run_cell("x")  # the same interpreter
```

What a takeover guarantees, and what it raises:

- The daemon raises the session's ownership generation by one; every later call or close
  of the first process is refused before it runs (`StaleOwnerError`, marked not
  dispatched). If it shares the store, it is stopped there first
  (`CheckpointConflictError`, nothing sent).
- A process that died mid-call leaves its record pending, with the call's request digest.
  The next `attach_session` sends that checkpoint and names the call. If the daemon never
  dispatched the call, the heads match and the takeover is plain. If it dispatched it and
  its answer was lost, the daemon takes the session over across that one call (the
  *explained gap*) and returns its record, and its answer when the daemon still keeps it
  (the last answer, in memory, until the next call starts or the session suspends or ends;
  `open_session(keep_no_answer=True)` keeps none), both checked by the client. The record
  says whether the daemon answered it: a result digest when the daemon answered, which does
  not show that the call ran to its end (a step stopped at its time limit and a setup that
  failed are answers too), an `unanswered` code when it ended without an answer, so that it
  may have done none, part or all of its work. The new session is then recovering:
  `session.lost_call` holds the lost call (its `request_sha256`, `record` and `answer`), and
  every call is refused with nothing sent (`RecoveringError`) until you have read it and
  called `session.resolve_lost_call()`; a call you send after that runs, the lost one
  again included, by your decision. A checkpoint saved while recovering carries the state
  (`recovering_request_sha256`), so a process that takes over from it is recovering too,
  knowing the lost call by its digest alone; resolving writes the store's record without
  it. Any other gap is `CheckpointMismatchError`, and nothing moves.
- Every call states the head it expects (the generation, the count of calls and the last
  record digest). A call whose head is not the daemon's is refused before it runs
  (`HeadMismatchError`, with the daemon's head in `.head`): something else ran a call on
  the session between this process's calls, so the session stops here, sending nothing more.
- A missing record is `LookupError`, never a fresh session. With `fingerprint=`, the
  session you mean, a record naming another session is `LookupError` too, with nothing
  sent: the check is made on the record the attach sends, so a store that changed since
  you read it never moves another session to this process. An attach answer that does not
  repeat the checkpoint is `ChainError`, and the session is not closed. A failed or
  canceled attach is never retried.
- `CheckpointStoreError` (its subclass `CheckpointConflictError` when the compare-and-set
  refused) says whether the call was sent (`sent`) and carries its result or error when it
  ran; the session then sends nothing more. No timeout ever clears a pending record. An
  attach whose store write finds a record a stale worker wrote after the attach read the
  store (the same session, at no later generation) writes over it, since the daemon now
  holds the session for this process; a record at a later generation is another
  process's, and the attached session is dropped with `CheckpointConflictError`.
- `session.checkpoint()` returns the checkpoint for an application that keeps it itself;
  `SessionCheckpoint.to_json` and `from_json` are the form the Go and TypeScript clients read
  too. It holds no secret: not the session ID, not the token.

Anyone who holds the token and a session's run records can take the session over: key the
store by identities your application verified. Open development mode refuses every
takeover. The rules in full:
[carrying a session on from another worker](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#carrying-a-session-on-from-another-worker).

## Google ADK executor and environment

`plimsoll_client.adk` gives Google ADK two ways in: `PlimsollCodeExecutor`, ADK's code
executor, which runs each Python block the model writes in a new sandbox; and
`PlimsollEnvironment`, ADK's environment, a kept sandbox with a shell and files. Install
them with the extra, `pip install 'plimsoll-client[adk]'` (0.20.0 and later; 0.19.0 has no
extras; the environment from 0.28.0; the extra installs exactly the ADK version it is tested with:
2.14.1 in 0.28.0 and 0.29.0, 2.15.0 from the next release), or from a
checkout with `pip install './clients/python[adk]'`.

The environment is one plimsoll session behind ADK's own `EnvironmentToolset`, so the agent
gets ADK's `Execute`, `ReadFile`, `EditFile` and `WriteFile` tools, and every command and
every file read or write is one call of that session:

```python
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.tools.environment import EnvironmentToolset
from plimsoll_client import Client
from plimsoll_client.adk import PlimsollEnvironment, PlimsollEnvironmentGuard

environment = PlimsollEnvironment(Client(PLIMSOLL_URL, token=TOKEN))  # kernel floor by default
agent = Agent(name="worker", model=your_model, tools=[EnvironmentToolset(environment=environment)])
runner = Runner(agent=agent, app_name="app", session_service=your_session_service,
                plugins=[PlimsollEnvironmentGuard()])  # first; runner.close() closes the session
```

Files stay from one command to the next; each command starts a new shell in the work
directory (`/work` on docker), as in ADK's own environments, so a `cd` or an `export` does
not carry over. What plimsoll stated about each call (whether it was dispatched, the
outcome, the tier with its sentence, the checked run record) is in `environment.calls`.
The guard ties each call to its ADK tool call, puts those labels on ADK's trace, stops the
agent after a call that may have run without an answer (ADK hands such an error to the
model, which would run the command again), and keeps one sandbox to one ADK user. What it
cannot do (a process kept between commands, parallel commands at once, network, bash) is
in [the Google ADK guide (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/google-adk.md#a-kept-sandbox-with-a-shell-and-files).

The code executor:

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

For CrewAI there is also a package of its own, `crewai-plimsoll`, named the way CrewAI's
tool-publishing guide asks so a PyPI search finds it: `pip install crewai-plimsoll` installs
CrewAI and this client at the same release, and `from crewai_plimsoll import Client,
CodeExecutor, PlimsollCodeTool` gives the same classes
([its source (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/crewai-plimsoll)).

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
  only the languages the image runs (`languages=("python",)`). The sandbox has no network (but a grant, below)
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

### A grant: the tool's code calls one web API

Every tool over `CodeExecutor` (Agno's, CrewAI's, LangChain's, Agent Framework's and
PydanticAI's `plimsoll_code_tool`) can carry a grant, so one program the model writes can call
an API's routes many times from inside the sandbox. Your application chooses it, never the
model: the name of a grant profile the operator configured on the daemon, and the description
`plimsoll-specgen -only allow.json -emit description api.json` wrote for that profile
([capability-grants.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/capability-grants.md#from-an-agent-kits-code-tool)).

```python
executor = CodeExecutor(client, grant_profile="lights", api_description=open("description.txt").read())
tool = PlimsollCodeTool(executor)   # CrewAI; every other tool over CodeExecutor takes it the same way
```

- **When it is built**, the executor reads the daemon's Describe and states in
  `executor.grant.languages` which languages can call the API there: JavaScript on every
  provider that gives a project run a grant (docker, openshell, e2b with a guard URL,
  dockercloud), Python too on docker and openshell, through `plimsoll_host`, a
  standard-library module the executor writes into the run (`plimsoll_host.get(path)`,
  `post(path, body)`, `put`, `patch`, `delete`, `call(method, path, body)`; `HostAPIError`
  has `.status` and `.body`). A daemon that cannot carry a grant raises `UnsupportedError`,
  marked not dispatched, here.
- **The tool offers only those languages**, and its description tells the model the API's
  routes and how to call them in each, so the model learns it from the description, not by
  failing. A tool left with no language raises `ValueError` when it is built; a call in
  another language is refused, `unsupported`, with what to write instead. With a grant,
  CrewAI's and LangChain's tools take no `description` of yours.
- **Every run carries the profile**; the tool's arguments never name one. An unknown profile,
  or one this caller is not on, is refused `permission` and logged as the operator's to fix.
  A call that may have run says the API may have been called too.
- **What it does not protect.** The broker, outside the sandbox, holds the key and adds it;
  the code can still do whatever an allowed route permits and read whatever it returns.
  The run record does not list the calls.

Runnable examples, one per tool, each against a stand-in lights API whose profile is `lights`:
`examples/crewai_grant.py` (CrewAI) and `examples/agno_grant.py` (Agno) here,
`examples/langchain_grant.py`, `examples/agent_framework_grant.py` and
`examples/pydantic_ai_grant.py` in their kits' sections below, and `examples/mcp_grant.py`,
plimsoll's MCP server installed with the grant and called over stdio by the MCP Python SDK. The
kits' examples each run one JavaScript program and one Python program the model might write (the
programs are in `examples/_granted.py`; the MCP one runs the JavaScript program and a one-line Python call,
then one call in a sandbox from `open_sandbox`, which never carries the grant): a GET and a POST through the grant, a second POST past the route's cap of
one call a run, and a route the profile does not list, refused before it leaves. Run one with
`PLIMSOLL_URL`, `PLIMSOLL_TOKEN` and `PLIMSOLL_GRANT_DESCRIPTION_FILE` (the description
`plimsoll-specgen` wrote for the profile) set, against a daemon whose `PLIMSOLL_GRANTS_FILE` names
the profile; each file's header has the command.

## LangChain tool and Deep Agents backend

`plimsoll_client.langchain.PlimsollCodeTool` is the same tool as a LangChain tool (a grant included:
[a grant](#a-grant-the-tools-code-calls-one-web-api)), so LangGraph's
`ToolNode`, `create_agent` and any graph call it; `plimsoll_client.deepagents.PlimsollSandbox` is a
Deep Agents sandbox backend over one session, which gives a Deep Agents agent its `execute` and file
tools in a sandbox kept for its whole run
([Deep Agents sandboxes (EXTERNAL · official docs ↗)](https://docs.langchain.com/oss/python/deepagents/sandboxes)).
Both are also in a package of their own, `langchain-plimsoll`, named as LangChain's integration guide
asks
([its README (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/langchain-plimsoll)).

```sh
pip install 'plimsoll-client[langchain]'    # the tool: langchain-core
pip install 'plimsoll-client[deepagents]'   # the backend: deepagents
```

```python
from langchain.agents import create_agent
from plimsoll_client.langchain import PlimsollCodeTool

agent = create_agent(model, tools=[PlimsollCodeTool(executor)])

from deepagents import create_deep_agent
from plimsoll_client import Client
from plimsoll_client.deepagents import PlimsollSandbox

with PlimsollSandbox.open(Client(URL, token=TOKEN)) as backend:   # the kernel floor by default
    agent = create_deep_agent(model=model, backend=backend, system_prompt=f"Work in {backend.root}.")
```

Recorded calls through the tool, from a CSV sum to an answer lost after the code may have run,
replay on its integration page:
[LangChain: see a run, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/integrations/langchain/index.html).

What the backend needs and does: the sandbox must have `python3`, which Deep Agents' file tools run
(`open` refuses a daemon whose session environment does not state Python; on docker that is the
`plimsoll/sandbox-python` image); a refusal, or a call that may have run without an answer, raises
rather than reaching the model as command output, since Deep Agents reads that output as data; on a
sandbox whose `grep` is BusyBox's (plimsoll's Alpine images) every search goes through Deep Agents'
own `python3` search, because its grep route would read BusyBox's refusal of GNU options as no
matches; a file past one call's 8 MiB artifact budget is downloaded in pieces and checked against its
size, and a file past 64 MiB is that path's error (see `read_whole` below); the session lives in the process that opened it, and when it ends every later call raises.

**Retries.** LangGraph and LangChain retry nothing unless you ask: retries are off by default in both.
Once you add a `RetryPolicy` to a node or `ToolRetryMiddleware` to an agent, both frameworks' default
rules retry a `PlimsollError`, including an unmarked one, after which the code may already have run.
`plimsoll_client.retry_on` is the rule to give them instead: it is true only for an error whose
`not_dispatched` is `capacity` or `environment` (nothing ran, and another try may pass) and false for
everything else, every exception that is not a `PlimsollError` included (`RETRY_REASONS` holds the two
reasons, and its docstring says why each other reason is out).

```python
from langgraph.types import RetryPolicy
from langchain.agents.middleware import ToolRetryMiddleware
from plimsoll_client import retry_on

builder.add_node("run", node, retry_policy=RetryPolicy(retry_on=retry_on))
agent = create_deep_agent(model=model, backend=backend, middleware=[ToolRetryMiddleware(retry_on=retry_on)])
```

The rule matters where plimsoll raises: the Deep Agents backend, and `Client` or `CodeExecutor` called
from a node of your own. The code tool never raises for a refusal or a lost answer (it answers with
them), so no retry sees one. A node with several policies gets the first whose rule says yes, so a
second policy with LangGraph's default rule would still retry plimsoll's errors: decide both in one
rule, `retry_on(e) if isinstance(e, PlimsollError) else your_rule(e)`.

**Tracing.** Each call of the code tool sends the LangChain run ID of the tool call as the run's
`trace_id` (a UUID; an ID of your own outside the daemon's 1 to 64 characters of `[A-Za-z0-9._:-]`
is not sent at all), so the daemon's audit line joins to the trace. When the call is traced in
LangSmith, the tool adds metadata to the tool call's own run: `plimsoll_record_sha256`,
`plimsoll_isolation`, `plimsoll_isolation_qualification` (when the provider states one),
`plimsoll_dispatched` (`yes`, `no` or `unknown`), `plimsoll_refused` (the reason, when it was not
dispatched) and `plimsoll_outcome`. Each is checked against the values plimsoll can state, so nothing
the guest printed reaches them. With tracing off nothing is added, and the tool imports no part of
LangSmith that is not already loaded.
LangChain's own tracing still sends the tool's inputs and outputs, the code and what it printed;
LangSmith's `hide_inputs` and `hide_outputs` settings turn that off
([LangSmith tracing (EXTERNAL · official docs ↗)](https://docs.langchain.com/langsmith/mask-inputs-outputs)).

**Examples.** `examples/langchain_tool.py` hands the tool to a `create_agent` agent driven by a
scripted stand-in for the model and runs one piece of code. `examples/langchain_grant.py` calls the
granted tool through LangChain's own tool-call path (a `ToolCall` answered with a `ToolMessage`),
once with a JavaScript program and once with a Python one, each calling a stand-in API through the
grant ([a grant](#a-grant-the-tools-code-calls-one-web-api) says how to run it).
`examples/langchain_retry_guard.py` shows both rules above with nothing but the local daemon: a
LangGraph node under `RetryPolicy(retry_on=retry_on)` is retried after a capacity refusal and runs
on its second try, is not retried after an answer lost once the request was sent (LangGraph's
default rule would retry it) or after the daemon's isolation refusal; then a tool call traced by
LangChain's LangSmith tracer, its uploads kept in memory so nothing reaches LangSmith, prints the
labels on its run. The capacity refusal and the lost answer are raised by the node itself, as the
client would raise them, since a real one needs a daemon at its limit or a broken connection. Run
it as `langchain_tool.py` runs: `PLIMSOLL_URL=http://127.0.0.1:8746 python langchain_retry_guard.py`
with the daemon's `PLIMSOLL_TOKEN` exported (it needs `langgraph` installed too).

## Microsoft Agent Framework shell tool and code tool

`plimsoll_client.agent_framework.PlimsollShellTool` is Microsoft Agent Framework's shell executor
over one plimsoll session, so `create_harness_agent(client, shell_executor=shell)` gives the model
its `run_shell` tool, and the files, directory and exported variables persist from one command to
the next. `plimsoll_code_tool(executor)` is the stateless code tool as an Agent Framework tool, and takes a
grant through its executor ([a grant](#a-grant-the-tools-code-calls-one-web-api)); the shell's session takes none. Both
are in the package `agent-framework-plimsoll`, which pins the framework's shell tools
(`agent-framework-tools`, a beta released about weekly) exactly; `pip install agent-framework-plimsoll`, from 0.28.0
([its README (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/agent-framework-plimsoll)).

```python
from agent_framework import create_harness_agent
from plimsoll_client import Client
from plimsoll_client.agent_framework import PlimsollShellTool

async with PlimsollShellTool(Client(URL, token=TOKEN), minimum_isolation="kernel") as shell:
    agent = create_harness_agent(chat_client, shell_executor=shell)
    print(await agent.run("Count the lines in every .py file here.", session=agent.create_session()))
```

What the shell tool needs and does: `minimum_isolation` has no default, and the session's tier is
checked against it before any command; the shell is BusyBox `sh` on plimsoll's docker images; a
refusal and a command on an ended session raise (the model is shown the framework's error result),
a command that may have run without an answer ends the agent's run (Agent Framework's
`MiddlewareFailure`, with plimsoll's error as its cause), and an ended session is never replaced; a
process left in the background is stopped when its command ends; approval is off by default
(`approval_mode="never_require"`, where Microsoft's own shell tools default to `always_require`;
pass `approval_mode="always_require"` to keep a person in the loop). The framework's
`ShellEnvironmentProvider` describes the agent's own machine to the model (Python's
`platform.platform()` in the agent's process), not the sandbox; its `instructions_formatter`
replaces that text.

**Files on the same session.** `PlimsollFileStore(shell)` is the harness's other slot, Agent
Framework's `AgentFileStore`, over the shell tool's session, so the model's `file_access_*` tools and
its shell see one tree; `create_harness_agent(chat_client, **harness_options(shell))` fills both slots
and gives the file tools the shell tool's approval mode (`file_approval="always_require"` or
`"never_require"` sets theirs alone). The harness's file memory is best kept in Agent Framework's
`InMemoryAgentFileStore` (`file_memory_store=InMemoryAgentFileStore()`), not in the sandbox, where
every run after the session ends would raise. The store refuses, with `ValueError`, a path
that is absolute, climbs with `..`, names the workspace's state, or passes through a symbolic link
anywhere along it (each part is looked at before the operation, and plimsoll's helper refuses a link
that leaves the work directory inside the operation's own file call), and with `OSError` (`EFBIG`) a
file past `max_file_bytes`, 1 MiB by default and at most 8 MiB, one file call's read. Every
operation is a file call of the session (`Session.run_files`), so it needs a provider whose sessions
take them (docker, E2B and OpenShell; on OpenShell, in the sandbox scope, the helper's refusal of a
link that leaves is not there, so a link swapped in after the store's look is followed); text only,
as the framework's store is ([its README (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/agent-framework-plimsoll#give-the-harness-files-too)).

**What reaches the application.** `await shell.run(command)` returns a `PlimsollShellResult`, the
framework's `ShellResult` with `isolation`, `isolation_qualification`, `outcome`, `record_sha256` and
the checked `result`. Through an agent, each command's function result keeps the model's text, and
its text item's `additional_properties` carry Microsoft's five shell fields and plimsoll's labels
(`plimsoll_dispatched`, `plimsoll_refused`, `plimsoll_outcome`, `plimsoll_isolation`,
`plimsoll_isolation_qualification`, `plimsoll_record_sha256`), each checked against the values
plimsoll can state; the code tool's result carries the same labels. A raised refusal reaches a
function middleware as the exception, and `call_labels(exception)` gives its labels. When the
framework's OpenTelemetry tool span is recording, both tools add the labels to it as
`plimsoll.<label>` attributes, never the command or its output.

**Retries.** Agent Framework does not run a failed tool call again by itself (a tool's exception is
one error result, and three in a row end the request); after a refusal the model may ask again, and
after a command that may have run the run has stopped. A retry of your own should ask
`plimsoll_client.retry_on` first. Not supported: an interactive terminal, reattaching a
session from another process, and a CodeAct provider.

**Examples.** `examples/agent_framework_shell.py` runs two shell commands through an agent, the
second reading the file the first wrote. `examples/agent_framework_grant.py` invokes the granted
code tool as the framework does (`FunctionTool.invoke`), with a JavaScript program and a Python one
that call a stand-in API, and prints the labels each result carries beside the model's text; run it
as [a grant](#a-grant-the-tools-code-calls-one-web-api) says.

## smolagents executor

A smolagents `CodeAgent` acts by writing Python. `plimsoll_client.smolagents.PlimsollExecutor`
is its Python executor over one plimsoll session: each step of the agent is one cell in the
session's Python interpreter, so what one step defines is there in the next, and
`code_agent(executor, tools=..., model=...)` builds the `CodeAgent` around it. Both are in the
package `smolagents-plimsoll` (tested with, and installs with, exactly smolagents 1.26.0); `pip install smolagents-plimsoll`, from
0.28.0 ([its README (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/smolagents-plimsoll)).
The daemon's project image needs Python, as `plimsoll/sandbox-python` has.

```python
from smolagents import AgentLogger, LogLevel
from plimsoll_client import Client
from plimsoll_client.smolagents import PlimsollExecutor, code_agent

executor = PlimsollExecutor([], AgentLogger(LogLevel.INFO), client=Client(URL, token=TOKEN), minimum_isolation="kernel")
with code_agent(executor, tools=[], model=model) as agent:   # closes the session after
    print(agent.run("What is the 20th Fibonacci number?"))
```

What the executor needs and does: `minimum_isolation` has no default, and the session's tier is
checked against it before any of the agent's code is sent. smolagents shows the model every error
an executor raises and goes on, so the executor keeps the first error after which the run cannot
go on (a refusal, a cell that may have run without an answer, an ended session, a restarted
interpreter) as `executor.fatal_error` and sends nothing more, and the agent `code_agent` builds
stops at that step and raises it from `run`; a plain `CodeAgent` would go on asking its model and
return the model's own answer. The code's own exceptions reach the model as smolagents'
`AgentError`. Each step has a 120-second budget unless you set `timeout`; a step past it ends the
interpreter, and the next step ends the run.

**What reaches the application.** `executor.records` holds a `PlimsollCellRecord` for each cell
the client checked, in order (the executor's setup cell first, then one per call smolagents made):
`isolation`, `isolation_qualification`, `outcome` (`completed` or `timed_out`), `record_sha256`,
the `record` and the checked `result`. They are the session's chain, so the last one's
`record_sha256` is `executor.session.last_record_sha256`; a call that raised adds none.

**Limits.** No pickle: `allow_pickle=True` raises, since unpickling a final answer from the sandbox
runs code the sandbox chose in your process. A final answer that is an image, a NumPy array or a
NumPy number is refused (the model is told, and can answer with a plain value). Nothing is
installed: smolagents asks the executor to install each package a tool's code imports from outside
the standard library, and the executor refuses, so such a tool fails when the run starts even when
the image has the package; the agent's own steps import what the image has. Tools run in the
sandbox, and a cell carries no grant, so no tool reaches the network. The agent's own code runs in
the same interpreter as the executor's helper and can forge what the executor reads back as its
step's result, which forges only its own answer; each cell's run record is plimsoll's, checked,
chained and in `executor.records`. Text from the sandbox that smolagents prints on the terminal (a step's output, its error,
a text value, the final answer) arrives with each control character but tab, newline and carriage
return written as a visible escape, so the sandbox cannot send the terminal escape sequences. The
package README lists every limit.

## PydanticAI workspace

`plimsoll_client.pydantic_ai.PlimsollWorkspace` is a PydanticAI capability that supplies one
plimsoll session as an agent run's workspace, so PydanticAI's own `FileSystem` tools read, write,
edit, list and search in the sandbox, and it adds `plimsoll_shell`, a shell tool over the same
session. `plimsoll_code_tool(executor)` is the stateless code tool as a PydanticAI tool, and takes a
grant through its executor ([a grant](#a-grant-the-tools-code-calls-one-web-api)); the workspace takes none. All are in
the package `pydantic-ai-plimsoll`, which pins `pydantic-ai-slim` exactly (PydanticAI adds rules for
workspace backends in minor releases): `pip install pydantic-ai-plimsoll`
([its README (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/pydantic-ai-plimsoll)).

```python
from pydantic_ai import Agent
from pydantic_ai_harness import FileSystem
from plimsoll_client import Client
from plimsoll_client.pydantic_ai import PlimsollWorkspace

workspace = PlimsollWorkspace(client=Client(URL, token=TOKEN), minimum_isolation="kernel")
agent = Agent(model, capabilities=[workspace, FileSystem()])
print((await agent.run("Write a script that counts the words in notes.txt, then run it.")).output)
```

**PydanticAI's `Coder` and `Shell` add no shell tool here, and say nothing about it:** an agent
given either has no `shell` or `run_command` tool, with no error to tell you or the model why. Use
`plimsoll_shell`, which the capability adds, for commands instead.

What it needs and does: `minimum_isolation` has no default, and the session's tier is checked
against it before anything runs. **Files only:** the backend implements PydanticAI's
`SupportsFilesystem` and `SupportsRealpath` and not `SupportsCommands`, because PydanticAI's command
contract says a backend must never stop a process a command detached into its own session, and a
plimsoll session kills every process a call leaves behind. So PydanticAI's `Coder` and `Shell`
capabilities do not work on it (with no command support their shell tools are left out of the
model's tools), and commands go through `plimsoll_shell`, whose description tells the model that a
process left in the background stops when its command returns. A later run of the same
conversation reaches the same session by the `WorkspaceRef` in its message history, in the process
that opened it only; anywhere else the ref raises `PlimsollWorkspaceGoneError`, and a fresh sandbox
is never opened in its place. The ref is `<daemon>/<fingerprint>`, never the session ID. Durable
execution (Temporal, DBOS, Prefect) is refused with a `UserError` that says why. A run never closes
the session: its lifetime ends it, or `workspace.destroy(ref)`.

**Errors.** A call that may have run raises `PlimsollOutcomeUnknownError`, a
`WorkspaceUnavailableError`, which no durable engine retries; a session that ended, or that this
process cannot reach, raises `PlimsollWorkspaceGoneError`; a refusal another try may pass (capacity,
after the backend's own retries of up to about 30 seconds, or an unreachable daemon) raises
`PlimsollRetryableError`, a `ConnectionError`; path failures are the builtin file errors.
`plimsoll_client.pydantic_ai.map_error` is the one mapping.

**What reaches the application.** Every record the client checked goes to `record_sink=` (by
default `backend.records`; `JsonLinesRecordSink(path)` writes one JSON line each). `plimsoll_shell`'s
and the code tool's answers carry plimsoll's labels in the `ToolReturn`'s `metadata`, which
PydanticAI keeps for the application and does not send to the model.

**Examples.** `examples/pydantic_ai_workspace.py` writes a script with PydanticAI's file tool and
runs it with `plimsoll_shell` in the same session. `examples/pydantic_ai_grant.py` runs a PydanticAI
agent whose model is a scripted `FunctionModel`: it asks the granted code tool for a JavaScript
program and a Python one that call a stand-in API, and the program prints each tool return and the
labels in its `metadata`; run it as [a grant](#a-grant-the-tools-code-calls-one-web-api) says.
`examples/pydantic_ai_crash.py` kills the worker mid-command and a second one takes the session
over ([Tests](#tests) says what it checks).

## Agent workspace

`Workspace` (`plimsoll_client.workspace`) is a shell, files and search over one session, for an
agent framework's tools: `exec`, `read`, `write`, `edit`, `glob`, `grep`, `stat`, `list`,
`read_many`, `make_dir`, `remove`, `rename`, and `persist` and `hydrate` for the whole tree. The
framework adapters that serve a shell to an agent are naming layers over it, so what the daemon
guarantees (the floor the session was opened with, a run record on every call, no network) holds
the same for each.

Every file operation is one *file call* of the session (`Session.run_files`): plimsoll's own
helper program carries it out inside the sandbox as the guest's own user and answers in a typed
form, so a file that is not there is `FileNotFoundError`, a folder `IsADirectoryError`, a file the
guest may not read `PermissionError`, a pipe or a device `OSError` (`ENXIO`, never opened), and no
text from inside the sandbox reaches an error. A session whose provider carries no file calls
(`Session.file_scopes` is empty) refuses every file method, nothing run (`UnsupportedError`). In a
confined workspace (the default) a path names a file in the work directory, and a symbolic link
is followed only while it stays inside it: one that leaves is `WorkspacePathError`.
`confined=False` takes an absolute path anywhere in the sandbox and follows links as the guest's
own shell does.

**On OpenShell a confined workspace follows a link that points out of the work directory.** An
OpenShell session states the sandbox scope alone (`Session.file_scopes == ("sandbox",)`): its work
folder is not a mount of its own, so plimsoll's helper refuses the work scope there
([docs/openshell.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/openshell.md#sessions) says why). A confined workspace on such a
session names each path in the sandbox scope, as the absolute path under the work directory, and
checks it by its name only: a `..` that leads out of the work directory, or an absolute path
outside it, is still `WorkspacePathError` before any call, but a symbolic link inside the work
directory that points outside it (one the agent's own code made, say) is followed, to whatever the
sandbox's user may reach there. The sandbox's walls are then the boundary, not the work directory.
Each call's record names the scope it used.

A read returns at most `max_bytes` (8 MiB at most, `MAX_READ_BYTES`). `read_whole` returns a whole
file and `read_pieces` yields it 8 MiB a call; every read states the file's size as it opened it,
and when a piece states another size than the first, or the pieces do not add up to it (another
call of the session, or a process in the sandbox, changed the file), they raise
`WorkspaceChangedError` rather than return a cut or spliced copy; a change that keeps the size is
not seen. Both take a `limit`, 64 MiB (`MAX_WHOLE_BYTES`) unless you pass another (`None` for
none): a longer file raises `WorkspaceTooLargeError` on its first piece's answer, before any other
piece is read. A whole read ends in your process's memory, and code in the sandbox can make a file
of any size for nothing (a sparse file takes no disk), so the limit is what keeps an agent's read
from making your process hold all of it; 64 MiB is eight calls, far past what a model takes in one
tool answer. `read_head(path, max_bytes)` reads the first `max_bytes` of a file of any length the
same way. The ADK, OpenAI Agents, Deep Agents and PydanticAI adapters read whole files through
`read_whole`, so each refuses a file past 64 MiB (PydanticAI's before it reads any of it, from the
size it measures first).

A write of up to 4 MiB (`MAX_WRITE_BYTES`) is one call that replaces the file whole: the file
holds the new content, or after an error what it held before. A longer one replaces the file with
its first 4 MiB and appends the rest a call at a time, so a failure partway leaves the first
pieces and the call that failed is never repeated (it may have changed the file): write it again
from the start. `glob` is matched by the helper, part by part (`*`, `?`, `[...]` within a part,
`**` as a whole part for any depth), and a leading dot is not special: `*` matches dot files.
`grep` runs `grep -rnHE` in the sandbox as a program, so only matching lines come back.
`persist` runs `tar` in the sandbox and reads the archive back by file calls (up to its `limit`,
64 MiB unless you pass another); `hydrate` writes one back the same way and extracts it. Both
stage the archive in the work directory, beside the tree, so a tree past about half of the work
directory's room cannot be saved or restored this way (on docker, whose work directory is a 128 MiB
tmpfs by default, 51 MiB of files persisted and 64 MiB did not): that is a `WorkspaceTooLargeError`
saying so. A persist or hydrate stopped by its cancel handle still removes its archive.

Commands are project calls, and every step is one of the module's fixed scripts: the command and
every argument travel as files under `.plimsoll-shell/` in the work directory, which the daemon
writes before the step runs. Nothing an agent writes becomes a step. The shell's working directory
and its exported variables persist between commands through two files there (`cwd`, `env`); files
persist as in any session. What does not persist: a process a command leaves running (the
session's sweep ends it with the call), and `exit` in a command ends the step before its state is
saved. Output limits are the daemon's, reported by the truncation flags on the outcome. Paths are
resolved against the work directory, not the shell's current directory; an absolute path inside
the work directory is accepted, and `root` is the work directory as the session's open stated it.

A call the daemon answered without a usable result raises `WorkspaceCallError`, a `RuntimeError`
whose `result` is the checked answer (a `ProjectResult` for a command, a `FilesResult` for a file
call: its outcome, the tier, the sentence the provider states beside the tier, and the run record),
so the record is not lost with the error. Outcome `setup_failed` means no step began: the command
did not run. `protocol_error`, `runner_failed` or a command's result with no step mean it may have
run.

```python
from plimsoll_client import Client, Workspace

client = Client("http://127.0.0.1:8080")  # a daemon whose project image carries python3
with Workspace(client.open_session(minimum_isolation="kernel")) as w:
    w.write("src/app.py", "print('hello')\n")
    out = w.exec("cd src && python3 app.py")
    print(out.exit_code, out.stdout_text, out.cwd)  # 0 hello /work/src
    print(w.grep("print", "src"))                    # src/app.py:1:print('hello')
    w.edit("src/app.py", "hello", "goodbye")
    snapshot = w.persist()                           # a tar of the tree, to hydrate elsewhere
```

The real thing is checked on a docker session by `tests/docker_workspace_check.py`, which
`make docker-suite` runs (`TestPythonWorkspaceDocker`; under gVisor with `SANDBOX_DOCKER_RUNTIME=runsc`); `tests/test_workspace.py`
checks what is sent against a fake session whose file calls answer as the helper does.

## Claude Managed Agents, self-hosted worker

`plimsoll_client.anthropic_worker` (extra `anthropic`, `pip install "plimsoll-client[anthropic]"`)
serves the six tools a Claude Managed Agents session sends to a self-hosted worker (`bash`,
`read`, `write`, `edit`, `glob`, `grep`) from a plimsoll session instead of the worker host.
The worker dispatches tool calls by name, so `PlimsollTools.tools` stands in for the SDK's
`beta_agent_toolset_20260401` under the same names and input schemas:

```python
import asyncio, os
from anthropic import AsyncAnthropic
from anthropic.lib.environments import EnvironmentWorker
from plimsoll_client import Client
from plimsoll_client.anthropic_worker import PlimsollTools

async def main() -> None:
    tools = PlimsollTools(Client("https://plimsoll.internal", token=os.environ["PLIMSOLL_TOKEN"]),
                          minimum_isolation="kernel")
    async with AsyncAnthropic(auth_token=os.environ["ANTHROPIC_ENVIRONMENT_KEY"]) as client:
        await EnvironmentWorker(
            client,
            environment_id=os.environ["ANTHROPIC_ENVIRONMENT_ID"],
            environment_key=os.environ["ANTHROPIC_ENVIRONMENT_KEY"],
            workdir="/workspace",
            tools=tools.tools,
        ).run()

asyncio.run(main())
```

What it gives: the environment key stays on the worker host and the sandbox holds no
credential; the sandbox has no network; every tool call is a plimsoll call with a run
record; each Managed Agents session gets one plimsoll session, opened at the floor you name
(`kernel` by default) on the first tool call and closed when the runner exits the `bash`
tool (or by `PlimsollTools.close`); the skills the worker downloaded under
`<workdir>/skills/` are written into the sandbox at open, executable bits kept. The tools
keep the built-ins' wording, so a model sees what it would see on the host.

Limits, stated so the model sees them: memory stores are not supported (`/mnt/memory`
stays a copy on the worker host, invisible to `bash` in the sandbox); `read` returns text
only (no images or PDFs); a background job does not survive a call; `cd` and `export`
persist through files, not a process (see Agent workspace). Tested in
`frameworks/anthropic/` with the SDK's own tool classes and call path, against an
in-memory workspace and the in-memory session daemon, with no call to api.anthropic.com.

## OpenAI Agents SDK, sandbox provider

`plimsoll_client.openai_sandbox` (extra `openai-agents`, `pip install "plimsoll-client[openai-agents]"`)
is a sandbox provider for the Agents SDK's `SandboxAgent`: `PlimsollSandboxClient` creates,
resumes and deletes sessions, `PlimsollSandboxSession` runs the agent's commands and files in
one plimsoll session through the Agent workspace above. The SDK's maintainers keep
third-party providers out of the SDK, so this one lives here. Built and tested against
`openai-agents` 0.25.0.

```python
import os
from agents import RunConfig, Runner
from agents.sandbox import SandboxAgent, SandboxRunConfig
from agents.sandbox.session import CallbackSink, Instrumentation
from plimsoll_client import Client
from plimsoll_client.openai_sandbox import PlimsollSandboxClient, PlimsollSandboxClientOptions

def on_event(event, _session):
    # One finish event per command, with what plimsoll states about it.
    if event.op == "exec" and event.phase == "finish":
        print(event.data.get("plimsoll_dispatched"), event.data.get("plimsoll_record_sha256"))

provider = PlimsollSandboxClient(
    Client("https://plimsoll.internal", token=os.environ["PLIMSOLL_TOKEN"]),
    instrumentation=Instrumentation(sinks=[CallbackSink(on_event)]),
)
agent = SandboxAgent(name="coder", instructions="Write and run the script.")
sandbox = SandboxRunConfig(
    client=provider,
    options=PlimsollSandboxClientOptions(minimum_isolation="kernel", languages=("python",), timeout=120),
)
result = await Runner.run(agent, "Count the lines in data.csv", run_config=RunConfig(sandbox=sandbox))
```

What it gives: every command and file operation is a plimsoll call with a run record; the
session is opened at the floor the options name (`kernel` by default); no credential and no
network in the sandbox; the SDK's snapshots and `RunState` work as with any provider, since
`persist_workspace` and `hydrate_workspace` are the workspace's tar. That tar is staged in the
session's work directory, so a snapshot of a tree past about half of that directory's room fails
with `WorkspaceTooLargeError` (on docker the work directory is a 128 MiB tmpfs by default).

**What the app sees for each command.** Six labels, each checked against the values plimsoll
can state, so nothing the guest printed or named can become one: `plimsoll_dispatched` (`yes`,
`no` or `unknown`: whether the call was handed to the sandbox), `plimsoll_refused` (the reason,
when nothing ran), `plimsoll_outcome`, `plimsoll_isolation` and `plimsoll_isolation_qualification`
(the tier, and the sentence the provider states beside it when it states one), and
`plimsoll_record_sha256` (the digest of the run record this client checked). They appear in the
SDK's own two places for sandbox operations:

- in `event.data` of the `exec` finish event every sink of the client's `Instrumentation`
  receives (a `CallbackSink`, the SDK's JSONL file sink, its HTTP sink), for a command that ran
  and for one that failed, with the checked run record itself beside them as `plimsoll_record`
  (a dict of the `RunRecord` fields) whenever the daemon answered with one;
- in the data of the SDK's `sandbox.exec` tracing span, so a tracing processor sees them: the
  labels only, since the SDK sends its traces to OpenAI when `OPENAI_API_KEY` is set and
  tracing is on.

The labels and the record are the only fields plimsoll adds. The SDK's own fields beside them are the SDK's:
its exec event carries the command text (and the output only when the sink's
`EventPayloadPolicy` asks for it), and its function-tool span carries the tool's input and
output unless `RunConfig(trace_include_sensitive_data=False)`. A command the app runs itself,
`await session.exec(...)`, returns a `PlimsollExecResult`: the SDK's `ExecResult` with `record`
(the checked `RunRecord`), `record_sha256`, `isolation`, `isolation_qualification`, `outcome`,
the truncation flags and `labels`. File reads and writes carry no labels: their records are
checked, and not passed on.

**Errors.** A command plimsoll refused before anything ran, or whose call ended in an error
after which it may have run, raises `PlimsollExecError`, the SDK's `ExecTransportError`:
`not_dispatched` is the refusal's reason (None when the command may have run), `retryable` is
`plimsoll_client.retry_on`'s answer (true only for `capacity` and `environment`), `context`
holds the labels, and the plimsoll error is its cause. A refused file call raises the SDK's
`WorkspaceArchiveReadError` or `WorkspaceArchiveWriteError` the same way. A command past its
budget raises `PlimsollExecTimeoutError`, the SDK's `ExecTimeoutError`, with the call's result.
The SDK does not answer the model with a failed command: the run ends with the SDK's
`UserError` ("Error running tool exec_command: ..."), whose cause is the `PlimsollExecError`.

**Retries.** The SDK never runs a failed command again by itself: its only automatic retry is
for model calls, and only when `ModelSettings.retry` asks for it (checked in `openai-agents`
0.25.0, and held by a test that counts the commands the sandbox receives). If your app retries
a failed run, ask the cause first: `err.__cause__.retryable` is false for every command that
may have run.

**Timeouts and cancellation.** A command's budget is the timeout the SDK gives it: the shell
tool gives 10 seconds unless the model asks for more (`yield_time_ms`), and a command given
none gets the options' `timeout`. A budget of zero or less ends the command before anything is
sent. When the SDK cancels a command (the run is cancelled, or a sibling tool call failed), the
call is cancelled as everywhere in this client: a call not yet sent is never sent, and the
connection of one in flight is cut. A command cut in flight may have run and has no answer this
client could check, so the client sends nothing more on that session: `running()` turns false
and each later command is refused before it is sent (`not_dispatched` `request`). A session open
the SDK cancels is closed once the daemon has opened it.

Limits, stated in the docstrings: the work directory is the daemon's (`/work` on docker),
learned from the sandbox at create unless the manifest names it; `resume` opens a new
session and the SDK restores the snapshot into it (this client cannot re-attach to a session
another process opened, and the persisted state carries the session's public fingerprint,
never its ID); no PTY, so no streamed output, no `write_stdin` and no interactive programs; no
exposed ports; no manifest users or groups, and a command the SDK wraps in `sudo -u` for a
`run_as` user is refused before it is sent; a background process does not survive a command;
the whole workspace saved at `stop` must fit one call's 8 MiB artifact budget, so a larger one
fails to save. A file past that budget is read in pieces and checked against its size. The SDK's
workspace fingerprint (which lets a resume that reattaches skip the restore) is turned off: its
helper runs from `/tmp`, which plimsoll's docker sandboxes mount without execute permission.

Tested in `frameworks/openai_agents/`: the provider against the SDK's own base classes, wrapper,
events and tracing over an in-memory workspace that counts every call and over the in-memory
session daemon; and the check OpenAI's provider guide asks for, the SDK's `Runner` driven by its
`ScriptedModel` (no model is called), through success, a tool error, a refusal, timeouts,
cancellation and a start that fails. On a real docker session (`TestPythonExamplesDocker`, in
`make docker-suite`): `examples/openai_agents_sandbox.py`, a `SandboxAgent` through `Runner.run`;
and `frameworks/openai_agents/docker_openai_check.py`, the same `Runner` path with the SDK's shell,
`apply_patch` and `view_image` tools, its file helpers, the isolation checks (no network, a
read-only system, no background process outliving a command), a timeout, a cut command, and a
stop and resume.

## verifiers runtime

`plimsoll_client.verifiers_runtime` (extra `verifiers`, `pip install "plimsoll-client[verifiers]"`)
is a runtime plugin for verifiers, Prime Intellect's library of reinforcement-learning
environments ([runtimes: EXTERNAL · official docs ↗](https://github.com/PrimeIntellect-ai/verifiers/blob/main/docs/runtimes.md)).
A verifiers environment runs a task's setup, commands, files and grading through a
*runtime*; with this one each of those is a call of one plimsoll session, and every call's
run record goes to a log that `check_record_log` rechecks with nothing but the file.
verifiers loads a runtime from outside its own tree by import path (0.4.1.dev97 and later):

```toml
[env.agent.runtime]
type = "custom"
import_path = "plimsoll_client.verifiers_runtime.PlimsollBackend"
url = "https://plimsoll.internal"
minimum_isolation = "kernel"
record_log = "runs/plimsoll-records.jsonl"
```

The bearer token comes from the variable `token_env` names (`PLIMSOLL_TOKEN` by default),
never from the config, because verifiers saves configs into its traces. The trace's runtime
`id` is the session's fingerprint, which every record in the log names.

Every harness verifiers ships installs its agent program inside the runtime from the network
and calls the model from there, so none of them runs in a plimsoll sandbox (measured: the
`bash` harness fails in its own setup, `wget: bad address 'astral.sh'`). The harness
`plimsoll-bash` (`plimsoll_client.verifiers_harness`, id resolved through the top-level
module `plimsoll_bash`) is verifiers' own `bash` harness with its chat loop on the
evaluator, which verifiers' harness contract allows: the loop is the shipped program's
`run_chat_loop`, unedited, every model call goes through verifiers' interception server,
and each `bash` or `edit` call is one session call with a checked record. Select it with
`--env.agent.harness.id plimsoll-bash`; the session image needs `bash`, and `python3` for
`edit`. Driven by the same scripted policy, it and the shipped harness on verifiers' docker
runtime gave the same transcript and reward, message for message, except the network notice
verifiers adds to the system prompt on a runtime with no egress.

Limits, stated in the module docstrings, measured 2026-10-27 with verifiers 0.4.1.dev97:

- **No network in any phase.** A task that allows a host is refused before anything runs;
  a setup or grading script that downloads fails with its own exit code. Every one of
  Terminal-Bench 2's 89 tasks installs its test runner from the network when grading.
- **One image.** The sandbox runs the daemon's image; a task naming another is refused at
  start, naming both (all 89 Terminal-Bench 2 tasks name one).
- **One work directory**, the daemon's (`/work` on docker), or a path the image links to
  it, which the runtime checks inside the sandbox at start. The root file system is
  read-only, so a task that writes `/tests`, `/logs` or `/app` needs an image that provides
  them.
- **No background process**: `run_background` is refused, and with it task tool servers,
  compose and setup daemons. `exec` is buffered: the command runs when its output or exit
  status is first asked for.
- **A phase timeout that cuts a call ends the session's use**, since the call may have run:
  the attempt ends as an error rather than graded (verifiers' docker runtime grades it), and
  `check_record_log` lists that session under `incomplete`.
- **Per-call cost**: about 290 ms a command under runc and 400 ms under gVisor, against
  about 36 ms for verifiers' docker runtime (medians on one development machine, 100 calls
  each; nearly all of it is the daemon's project call). The daemon's default rate limit, 30
  runs a minute per caller, stops an evaluation after about two attempts: raise
  `SANDBOX_RATE_PER_MIN` for evaluation traffic.

Tested in `frameworks/verifiers/` through verifiers' own config loading, provisioning and
network rules against an in-memory session, and on docker by `TestVerifiersRuntimeDocker`
in `make docker-suite`: a small environment with isolated grading validates through
`vf-validate`, and its record log checks. `frameworks/verifiers/attempt/` runs a complete
attempt through `vf-eval` with a scripted model (no model is called) and measures it; with
`--model` it runs a real one, which spends (its limits are in `examples/verifiers/README.md`).

## Answer-key tripwire and canary run

`plimsoll_client.tripwire` checks the requests an AI evaluation sent to the model it tests,
offline, with no daemon and the standard library only:

```sh
# the answer key (truth labels, reference numbers, planted file names) in recorded model requests
python3 -m plimsoll_client.tripwire tripwire --sealed sealed.json recorded-requests/
# a canary run: markers per hidden place, planted for one run, none may reach a request
python3 -m plimsoll_client.tripwire canary make truth reference-times plan-names -o canary.json
python3 -m plimsoll_client.tripwire canary check --sealed canary.json --planted hidden/ --requests recorded-requests/
```

Each exits 0 when it finds nothing, 1 on a finding and 2 when its input does not load.
`find_sealed(request, sealed)` checks one request before it is sent. The file formats, a
worked example, the matching rules and what it cannot catch:
[docs/answer-key-tripwire.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/answer-key-tripwire.md).
Tested offline by `tests/test_tripwire.py`.

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
  have run but ended in an error comes with its record (`PlimsollError.unanswered`, with no
  result and the error's code); the session checks it (its tier against the call's floor, and its
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

`retry_on(err)` puts that question to a framework's automatic retry: true only when
`not_dispatched` is `capacity` or `environment`, the two reasons where another try of the same
call may pass ([LangChain tool and Deep Agents backend](#langchain-tool-and-deep-agents-backend)).

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
| `AtCapacityError` | Shed by one of the daemon's limits; retry later or elsewhere. `limit` says which, as the daemon states it: `sessions`, `caller_sessions` (closing one of your sessions frees a place), `runs`, `caller_runs` (a running session holds one, so a close may free it), `owner_sessions`, `rate` (only time helps), `paid_seconds`, `queue`, `provider`, or `unknown` (a daemon that does not state it). Every capacity refusal also carries it as `capacity_limit`, including `deadline` (the call's own time ran out before any of it was sent), which comes with the code `deadline_exceeded` or `canceled` and so is not an `AtCapacityError`. The full table: [docs/run-results.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/run-results.md). |
| `SessionEndedError` | The session has ended; `reason` says why (`closed`, `expired`, `disk_exceeded`, `main_process_ended`, `boundary_failed`, `sandbox_changed`, `shutdown`; `replaced`: the daemon closed it to open a newer session for the same `owner`, at its `SANDBOX_MAX_SESSIONS_PER_OWNER`; `not_found`: the daemon has no such session, after a restart, say; `unclaimed`: no request named it before its first idle timeout, so the daemon closed it, as it does a session whose open answer was lost; or `unknown`: an end a newer daemon has). Nothing of the refused call ran: open a new session. |
| `StaleOwnerError` | Another process took the session over; this one must not use it again. Nothing of the refused call ran; the session goes on for its new owner. |
| `CheckpointMismatchError` | A takeover's checkpoint is not the session's head, and the gap is not one the takeover named. Nothing moved. |
| `RecoveringError` | A call on a session taken over across a lost call, before `session.resolve_lost_call()`; `session.lost_call` says whether the daemon answered the lost call. Refused here, with nothing sent; never a retry signal. |
| `HeadMismatchError` | The daemon refused a session call because the head it stated is not the session's (another holder ran a call between this client's); `.head` is the daemon's. Nothing ran; the session sends nothing more. |

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

No usable answer (`TransportError`): the connection failed,
`RequestTimeoutError` (the exchange outlived `request_timeout`),
`ResponseTooLargeError` (over 32 MiB), or `MalformedResponseError` (not a well-formed
message of the expected type). Marked not dispatched, reason `environment`, only when it
failed before any byte of the request could leave (a refused or hanging connect, a failed
TLS handshake); otherwise unmarked, since the daemon may have received the request and
run it.

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
framework's own tool-call path (Agno's `FunctionCall`, CrewAI's `run` and `arun`, LangChain's
`invoke` and `ainvoke` with a tool call), with no model and no agent loop, against the real
daemon handler; `make clients-suite` runs them with every other client suite. A suite whose
directory has a `pytest.ini` runs under pytest: the LangChain one carries LangChain's standard
tool tests. The Deep Agents suite drives Deep Agents' own agent graph with a scripted chat model
over an in-memory workspace. `make docker-suite` runs the framework checks on real docker
sessions, each in its framework's environment: LangChain's standard sandbox tests and a
scripted Deep Agents agent (`TestDeepAgentsDocker`); the commands Agent Framework's shell
environment provider runs to describe the shell (its version, working directory and tool
versions) and a two-command conversation that shares a file, through the shell tool on both
project images (`TestAgentFrameworkDocker`); a scripted smolagents `CodeAgent` whose three steps
share one session's Python interpreter, and a step that prints past the output limit
(`TestSmolagentsDocker`); PydanticAI's own conformance suite for workspace backends, every skipped
rule compared with the list of rules the package does not promise, and agents of the real PydanticAI
with `FileSystem`, `Coder` and `plimsoll_shell` (`TestPydanticAIDocker`); and Google ADK's own
tools, toolset and Runner over `PlimsollEnvironment` (`TestADKEnvironmentDocker`). CI runs that
suite under runc and, in the gvisor
workflow, under runsc. The cancellation cases hold the daemon's Describe
or a Run until released, cancel the await, and count the Run requests that reach the
handler.

`examples/` holds short programs, one per agent kit and one more for ADK's kept sandbox
(`crewai_tool.py`, `agno_tool.py`, `langchain_tool.py`, `adk_executor.py`, `adk_environment.py`,
`openai_agents_sandbox.py`, `agent_framework_shell.py`, `smolagents_executor.py`,
`pydantic_ai_workspace.py`): each hands the kit plimsoll's tool or sandbox, drives it with a
scripted stand-in for the model, and runs one piece of code (the Agent Framework one runs two shell
commands, the second reading the file the first wrote, and prints the labels each function result
carries; the smolagents one runs two steps, the second using a variable the first set; the
PydanticAI one writes a script with PydanticAI's file tool and runs it with `plimsoll_shell` in the
same session). `langchain_retry_guard.py` is LangGraph's retry policy under `retry_on` and the
LangSmith labels of a traced call ([LangChain](#langchain-tool-and-deep-agents-backend)). Each file's
header says what to install and which daemon to start. `TestPythonExamplesDocker` runs all ten, each
in its framework's environment, against a real docker daemon with sessions on, and the six granted
examples (`*_grant.py`) against a daemon of their own with a stand-in for the API; `make docker-suite`
runs it. `pydantic_ai_crash.py` ("kill the worker, keep
the sandbox", with the checkpoint store it uses in `_conversation_lease.py`) kills the process running
a PydanticAI agent while its command runs, and a second process takes the session over across the
lost call: its record says whether the daemon answered it, the call that PydanticAI's resume sends
first is not sent, and the model is told what the record says. With `--freeze`, a
worker that returns after the takeover is refused by its own client. `TestPydanticAICrashDocker` runs
it in both modes against a real docker daemon (`make docker-suite`), and
`frameworks/pydantic_ai/test_crash_chain.py` holds its chain check to good and bad record logs.
