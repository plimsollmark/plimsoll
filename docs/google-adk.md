# Google ADK through plimsoll: the code executor and the environment

Google's Agent Development Kit (ADK) can run an agent's code in two ways, and
`plimsoll_client.adk` fills both with plimsoll instead of the agent's own host:

- **A code executor** (`BaseCodeExecutor`): the model writes a Python block and ADK runs it.
  `PlimsollCodeExecutor` runs each block in a new sandbox, with kernel isolation required by
  default. It ships in `plimsoll-client` 0.20.0 and later as the `adk` extra.
  [Below](#the-code-executor).
- **An environment** (`BaseEnvironment`): a place with a working directory where the agent
  runs shell commands and reads and writes files, through ADK's own `EnvironmentToolset`.
  `PlimsollEnvironment` keeps one plimsoll [session (INTERNAL · documentation →)](sessions.md)
  (one sandbox kept for many calls) for the agent. It is in `plimsoll-client` from
  0.28.0. The next release after 0.29.0 is tested with, and its extra installs, exactly
  ADK 2.15.0; 0.28.0 and 0.29.0 install exactly ADK 2.14.1 (2.14.0 made ADK's environment
  interface stable). [Next](#a-kept-sandbox-with-a-shell-and-files).

Recorded calls through the executor, from a CSV sum to a refused floor, replay on its
integration page: [see a run, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/integrations/google-adk/index.html).

Install it into your Python virtual environment, from PyPI or from the repository root:

```sh
pip install 'plimsoll-client[adk]'
pip install './clients/python[adk]'
```

The base client remains dependency-free. Only the `adk` extra and importing this
optional module require ADK. Verification pins Google ADK 2.15.0.

## A kept sandbox with a shell and files

```python
import os
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.tools.environment import EnvironmentToolset
from plimsoll_client import Client
from plimsoll_client.adk import PlimsollEnvironment, PlimsollEnvironmentGuard

environment = PlimsollEnvironment(
    Client(os.environ["PLIMSOLL_URL"], token=os.environ.get("PLIMSOLL_TOKEN")),
    minimum_isolation="kernel",
)
agent = Agent(name="worker", model=your_existing_model,
              tools=[EnvironmentToolset(environment=environment)])
async with Runner(agent=agent, app_name="worker", session_service=your_session_service,
                  plugins=[PlimsollEnvironmentGuard()]) as runner:
    ...  # runner.run_async(...) as usual; leaving the block closes the session
```

The agent gets ADK's own four tools, `Execute`, `ReadFile`, `EditFile` and `WriteFile`, and
each command and each file read or write is one call of the session: behind the isolation
floor the session was opened at, with a checked run record, and with no network.
[`examples/adk_environment.py`](../clients/python/examples/adk_environment.py)
is the same with a scripted stand-in model, so it runs without a model service.

**What happens when.** Making the environment touches nothing. When the agent first runs,
ADK's toolset calls `initialize()`: the environment asks the daemon whether it offers
sessions (refused, marked not dispatched, reason `unsupported`, when it does not), opens one
at `minimum_isolation`, and takes the work directory the open states (`/work` on docker and
E2B, `/tmp/work` on [OpenShell](trainers/glossary.html#openshell)), with no call, which ADK
names to the model. The environment's reads and writes are file calls in the sandbox scope (an
absolute path, a symbolic link followed as the guest's own shell follows it), which every
provider with sessions takes, OpenShell included ([which scopes each provider takes](sessions.md#files)).
A session that takes no file calls (a daemon from before them) states no work directory: the
environment asks once by running `pwd`, its commands work, and its file reads and writes are
refused, marked not dispatched, reason `unsupported`. An open whose await is cancelled closes the session it made, so it does not
hold a place on the daemon, and a `close()` made while an open is on its way waits for that open
and closes the session it made. `Runner.close()`, which the `async with` above calls, closes the toolset, and
that closes the session: the sandbox and its files are gone. `initialize()` after that opens
a new, empty sandbox for a new ADK invocation (the next turn of a conversation, or another
Runner), as ADK's own lifecycle has it; an invocation that used the closed session is refused
instead (below). `lifetime=`, `idle_timeout=`, `owner=`
and `trace_id=` go with the open as for `Client.open_session`.

**If the agent ends without closing**, nothing in your process closes the session. The
daemon does: after its idle limit (5 minutes by default) it suspends the session (on docker
the sandbox is paused and keeps its place), and at the session's lifetime (30 minutes by
default) it closes it and deletes the sandbox. Close the Runner, or open with a short
`lifetime=`.

**One environment for every conversation: `scope="session"`.** By default one environment is
one sandbox, which the guard keeps to one user, so a multi-user app makes an environment per
user. With `scope="session"` (ADK's `EnvironmentScope.SESSION`) one environment keeps a
sandbox per ADK session instead, keyed by the session's app name, user ID and ID, which your
session service set:

```python
environment = PlimsollEnvironment(client, minimum_isolation="kernel", scope="session",
                                  idle_timeout=600)
```

- A conversation's first tool call opens its sandbox, with the ADK user as `owner` (so a
  daemon's per-owner cap counts users) unless you pass one; its later turns, through any
  Runner of this process, use the same sandbox and find their files. Another user's or
  another conversation's tool calls reach their own. ADK runs `initialize` one call at a time
  per ADK session, and the environment opens one sandbox however many calls arrive at once.
- The session's state names the sandbox, under `plimsoll:sandbox`: the ADK session it
  belongs to and the plimsoll session's fingerprint, neither of them a secret. ADK keeps it
  with the session, so a `DatabaseSessionService` keeps it across restarts.
- `close()` closes nothing under this scope: the sandboxes are let go, kept for their
  conversations' next calls. ADK calls `close()` through `Runner.close()`, and an
  `AgentTool`'s nested Runner calls it when its agent finishes, in the middle of its caller's
  turn, which under the default scope closes the caller's sandbox (below). Call
  `await environment.end()` when the app stops, after `Runner.close()`: it closes every sandbox
  the environment holds. `adk eval` and `adk web` never call it, so the environment also closes
  what it still holds when it is garbage-collected and when the Python process exits normally
  (Ctrl+C included; a process killed by a signal it does not handle, such as SIGTERM to
  `adk web`, closes nothing, and its sandboxes stay until the daemon's lifetime, 30 minutes by
  default, which `lifetime=` shortens). With `checkpoint_store=` (below) it leaves them open
  at exit, since another process may attach them.
- **At the daemon's capacity a finished conversation makes room, when the guard is on the
  Runner.** On docker an open session holds one of the caller's concurrent places (4 by
  default) even while it sits idle, so the sandboxes of finished conversations, such as the
  cases of an earlier `adk eval` run, would fill them. When the daemon refuses an open for
  capacity (`AtCapacityError`), the environment closes the least recently used sandbox whose
  conversations are all between turns and that has no call in flight, and tries the open
  once more; with none to close, or when that try is refused too, the refusal is raised as it
  came (marked not dispatched, reason `capacity`, so `retry_on` says it may be tried again).
  It does so only for a limit a close can cure, as the refusal states it
  (`AtCapacityError.limit`): `sessions` and `caller_sessions` (the daemon's or the caller's
  session places), `runs` and `caller_runs` (runs in flight, which a running session holds).
  For the rate limit (`rate`, 30 runs a minute per caller by default), which only time gives
  back, and for every other limit, nothing is closed: an app that retries rate refusals loses
  no conversation's files to them. A daemon older than the limit field states none (`unknown`), so
  against one nothing is closed for room. One sandbox at most for each open, since an open
  needs one place and each sandbox closed is a conversation's files gone.
  Between turns is a fact the Runner states, never a guess: `PlimsollEnvironmentGuard` notes
  each ADK invocation (a turn, or one run of an `AgentTool`'s agent) from its
  `on_user_message_callback` and `before_run_callback`, which ADK calls before it runs the
  agent, to its `after_run_callback` or `on_run_error_callback`, which ADK calls when the run
  has ended (google-adk 2.15.0, `workflow/_node_runner_utils.py:149-219` and
  `utils/_runner_utils.py:194-300`). So a turn waiting on its model, a `SequentialAgent`
  between its sub-agents, and an `AgentTool`'s caller after its agent finished all keep their
  sandbox. The session's events are not such a fact: the Runner stores the user's message
  before the model call, but a `SequentialAgent`'s first sub-agent stores a final answer in
  the middle of the turn (measured on ADK 2.15.0). A run whose consumer stops reading and
  closes it, as `adk web` does when a browser drops a streamed turn, calls
  `after_run_callback`, so its turn ends at once. A run whose task is cancelled from outside
  (an `asyncio` cancel, a `wait_for` deadline) calls neither end callback: its conversation
  stays in its turn until Python frees the run's context, so its sandbox is kept, not closed
  under it. That context is held by a reference cycle, so it goes at Python's next garbage
  collection of young objects (measured on ADK 2.15.0, CPython 3.12), and not while anything
  still holds the cancelled task.
  Register the guard on every Runner that runs a conversation using the environment (on the
  `App`'s `plugins` for `adk eval` and `adk web`, which carry them to every Runner they make:
  measured on google-adk 2.15.0 for `adk eval`, sequential and at its default parallelism, and
  for `adk web`'s chat and its Eval tab).
  A sandbox reached by a call from an invocation the guard did not see begin is never closed
  to make room, since nothing says when that conversation's next turn starts; then, at the
  daemon's capacity, a new conversation is refused until a sandbox is closed some other way
  (`end()`, the daemon's `lifetime`, or an `idle_timeout` short enough to end idle sessions on
  that daemon). A conversation whose sandbox was closed to make room is refused from then on,
  as below (`reopen_after_close=True` gives it an empty one instead).
- **Past 256 sandboxes held**, opens in flight counted, a new conversation's open lets go of
  the least recently used sandbox in the same way: between turns, no call in flight (closed,
  and its conversation refused from then on; with `checkpoint_store=` any sandbox without a
  call in flight is dropped instead, and attached again by its next call). When none can go,
  the open is refused, `AtCapacityError` marked not dispatched: a sandbox with a call in
  flight is never let go.
- **An `AgentTool`'s agent sharing the environment works in its caller's sandbox.** ADK runs
  it in a nested ADK session whose state is a copy of its caller's, so it finds the sandbox
  the caller's state names, and the nested Runner's close lets it go: the caller's next call,
  and its next turn, find the wrapped agent's files. When the wrapped agent is the first to use
  the environment, it opens the sandbox and names it in its state, and ADK hands that change
  to the caller's state, so the caller uses the same sandbox. This holds with
  `include_plugins=False` too, and through agents that never use the environment, since it
  rides the state, not the invocation. When the caller's first model answer holds its own
  environment call and the `AgentTool` call together, both open at once, before either is in
  the state: with `include_plugins=True` (the default) ADK records on the nested run which
  invocation it belongs to, and the two share one sandbox. With `include_plugins=False` ADK
  records nothing, so they open one each; the conversation's next call (in that turn or a
  later one) is then refused, `SessionEndedError` reason `replaced`, marked not dispatched,
  saying the conversation reached two sandboxes, rather than working in the wrapped agent's
  sandbox without the caller's files (measured on ADK 2.15.0, where the wrapped agent's state
  change is the one the caller's state keeps). Keep `include_plugins=True` for an `AgentTool`
  whose agent shares the environment.
- **A conversation whose state names a sandbox this environment does not hold is refused,**
  `SessionEndedError` reason `not_found`, marked not dispatched, never given an empty one: one
  closed by `end()`, one let go past 256 (above), one closed to make room at capacity, or one another process opened (a restart, another
  replica). Start a new ADK session for that user, or pass `reopen_after_close=True` to give
  such a conversation a new, empty sandbox instead (its files are gone; this scope only, and
  not with a checkpoint store).
  With `checkpoint_store=` (a `plimsoll_client.CheckpointStore` only your application can
  write, and the client's `daemon_name`) the environment keeps each sandbox's checkpoint in
  the store under a key derived from the ADK session's app, user and ID, and attaches the
  sandbox again in place of the refusal, so a conversation carries on after a restart or on
  another replica (one process at a time: an attach takes the session over from the one
  before). A state whose fingerprint is not the sandbox's is refused as `replaced`, and a
  state that names a sandbox with no fingerprint is refused before anything is sent (marked
  not dispatched, reason `permission`): the fingerprint is what ties the mark to one sandbox,
  so without it the mark could reach another conversation's.
- The app and user always come from the ADK session, never from state, so the state's mark
  (which a client of ADK's API server can write with a run request's `state_delta`) can only
  point at a sandbox of the same user. The checkpoint itself is not kept in session state for
  that reason: whoever holds the caller's token and a checkpoint can take a session over
  (`plimsoll_client.checkpoint`). The guard's one-user rule holds by the key.
- Every call needs ADK's context with a session: a call your own code makes without one is
  refused with `ValueError`, as ADK's toolsets refuse a scoped environment without one. Use the
  default scope for direct use. `environment.sessions` maps each held ADK session to its
  plimsoll `Session`; `environment.session` is None under this scope. ADK's `working_dir`
  takes no context, which is fine here: every sandbox has the same work directory.

**Commands.** Each command runs in a new `sh` in the work directory, as in ADK's own local,
E2B and Daytona environments: the files persist from one command to the next, a `cd` or an
`export` does not, which is also what ADK's instruction to the model says (chain dependent
commands with `&&` in one `Execute`). A non-zero exit is a result, not an error. ADK's
`Execute` tool gives every command 30 seconds; `execute(timeout=None)`, when you call it
yourself, gets the daemon's longest budget, and a budget of zero or less is a timed-out result
with nothing sent, as `LocalEnvironment` gives. When the daemon cut a stream at its output
limit, a line starting `plimsoll:` at the end of `stderr` says so, since ADK's result has no
field for it. `env_vars=` adds variables to every command: they enter the sandbox, so never a
credential.

**Paths.** Relative to the work directory, or absolute anywhere in the sandbox (the sandbox
is the boundary, as for ADK's E2B and Daytona environments). A path that climbs out of the
work directory with `..`, and the workspace's own `.plimsoll-shell` directory, are refused
before anything is sent. Every read and write is a file call, carried out inside the sandbox
by plimsoll's own helper, never a shell command. Files of any bytes are read 8 MiB a call
and written 4 MiB a call (a write up to 4 MiB replaces the file whole; a longer one replaces
it with its first 4 MiB and appends the rest, so a failure partway leaves the first pieces),
and a file is read whole up to 64 MiB: a longer one is a `WorkspaceTooLargeError`, refused after its first
piece, since a sandbox can make a file of any size for nothing (a sparse file) and a read ends in
your process's memory. A file longer than one call which changes size while it is read (ADK may run an `Execute` beside
a `ReadFile`) is a `WorkspaceChangedError`, an `OSError`, never a cut copy.
A missing file is `FileNotFoundError`, a directory `IsADirectoryError`, a file the sandbox's
user cannot read or write `PermissionError`, a folder on a write's way that is a file
`NotADirectoryError`, a FIFO, socket or device `OSError` with `ENXIO` (never opened), a full or
read-only disk `OSError` with `ENOSPC` or `EROFS`, as ADK's tools expect. Each carries the
path as the model gave it and no text from the sandbox.

**What plimsoll states, per call.** `environment.calls` holds a `PlimsollCall` for every call
the environment made: the method that made it, the ADK tool call it served (with the guard),
whether it was dispatched (`yes`, `no` with the refusal's reason, or `unknown` when no answer
came back and it may have run), the outcome, the tier and the sentence the provider states
beside it, and the checked `RunRecord` with its SHA-256. It holds no output, command or path.
`await environment.execute(...)` called directly returns a `PlimsollExecutionResult`, ADK's
`ExecutionResult` with that call in `plimsoll` and the complete `ProjectResult` in `execution`.

**Register `PlimsollEnvironmentGuard` first.** It is an ADK plugin, and for each tool call it:

- ties each plimsoll call to the ADK tool call, and sends the tool call's ID to the daemon as
  plimsoll's trace ID, so the daemon's audit line joins ADK's span and the session's event;
- labels ADK's `execute_tool` span with plimsoll's trusted labels, one value per plimsoll call:
  `plimsoll_record_sha256`, `plimsoll_isolation`, `plimsoll_isolation_qualification`,
  `plimsoll_dispatched`, `plimsoll_refused`, `plimsoll_outcome` and `plimsoll_calls`, the
  keys the LangChain tool puts on a LangSmith run. Each value is checked against its closed
  set and is empty when it does not pass, so nothing the code wrote reaches the trace this way;
- stops the agent after a tool call one of whose plimsoll calls may have run without a
  complete answer (no answer at all, or a runner that failed after a step began). It raises
  `PlimsollEnvironmentError`, which ADK wraps in `RuntimeError`, and the run ends;
- keeps one sandbox to one user: the first ADK app and user whose tool call reaches the
  environment hold it until it closes, and another user's tool call is refused before
  anything is sent (marked not dispatched, reason `permission`). One session is one trust
  domain: everything one call does is there for every later call. One user's several
  conversations share it (under the default scope; with `scope="session"` each has its own);
- notes when each ADK invocation begins and ends, from the Runner's own callbacks, which is
  how `scope="session"` tells a conversation between turns from one in a turn (above).

**Why the stop matters.** ADK does not rerun a failed tool by itself. But its environment
tools hand any error of the environment to the model as an ordinary failed result, and a
model told a command failed tends to run it again; ADK's `ReflectAndRetryToolPlugin`, when
you register it, asks the model to, for any error a tool raises. A command that already ran
would then run twice. A refusal before anything ran (the floor, a daemon at capacity) is left
to the model and to the retry plugin, since nothing ran. If you handle tool errors yourself,
`plimsoll_client.retry_on(error)` says which may be tried again:

```python
from plimsoll_client import retry_on

def on_tool_error(tool, args, tool_context, error):
    if retry_on(error):  # nothing ran, and another try may pass
        return {"status": "error", "error": f"{error}; nothing ran, you may try again"}
    return None  # anything else ends the run, so nothing runs twice
```

**What it does not do.** No process stays running between commands (the session's sweep
ends it with its call). ADK may run several `Execute` calls at once; one session runs one
call at a time, so they run one after another. No network. The shell is BusyBox `sh` on
plimsoll's docker images, not bash.

**A lost sandbox is named, never replaced.** The sandbox is lost when the daemon ends the
session (its lifetime, a restart) and when a call ends without an answer the client can
check, as a call cancelled after it was sent does: ADK cancels the other calls of a parallel
batch when one of them fails, and the guard's stop is such a failure. The client then sends
nothing more on that session, since the cut call may have run. The call that found the loss
raises its own error (or returns its answer); the environment then closes the session, which
frees its place on the daemon, and every later call raises `SessionEndedError`, marked not
dispatched, saying the sandbox and its files were lost and why (reason `closed` when the
client stopped the session, the daemon's own reason when the daemon ended it). It never opens
a new sandbox in its place, as ADK's E2B environment does, because the agent would take an
empty sandbox for the one with its files. Under the default scope this holds for every
conversation using the environment until `close()` (which `Runner.close()` calls), after
which the next `initialize()` opens a new, empty sandbox for a new ADK invocation, while an
invocation that used the lost one stays refused; or give the agent a new environment. Under
`scope="session"` it holds for that conversation only, until `end()`: start a new ADK session
for it, and the other conversations go on in their own sandboxes. `reopen_after_close=True`
does not give a lost conversation a new sandbox (it is for one the environment closed between
turns), and a lost conversation holds no sandbox, so none is closed for it to make room. A
call refused before it was sent (the floor, a daemon at capacity) leaves the sandbox as it
was.

Do not share one environment between an
agent and an agent it wraps with `AgentTool`: ADK runs the wrapped agent in a nested Runner
that closes that agent's toolsets when it finishes, and a toolset's close closes its
environment, so the session is closed under the agent that wraps it (ADK's own guide warns of
this for any two toolsets that share one environment). ADK 2.15 initializes the environment
before every tool call, so the wrapping agent's next call would open a new, empty sandbox, in
which the wrapped agent's files are not. The environment refuses it: an ADK invocation is held
to the first session it used, and so is the invocation that ran it as an `AgentTool`. Once that
session is closed, every call of either raises `SessionEndedError` (reason `closed`, marked not
dispatched) rather than opening a new sandbox or joining one another conversation opened, and
the refusal ends the invocation (ADK raises an error of `initialize` out of the tool call). The
error says what to do: give the wrapped agent an environment of its own; its sandbox is gone
when it finishes, and each call of the `AgentTool` gets a new one, as each runs in an empty ADK
session. Or share it under `scope="session"` (above), where the wrapped agent works in its
caller's sandbox and the caller keeps its files; the hold stays there as a second guard. The
invocation is ADK's `invocation_id` on the tool's context,
one per invocation, so concurrent invocations never share one; the wrapping invocation is the one
ADK's `AgentTool` records on each invocation of its nested Runner, which it does when the tool
inherits the Runner's plugins (`include_plugins=True`, its default). An `AgentTool` made with
`include_plugins=False` records none, and there the wrapping agent's next call is not refused:
do not share an environment with such a tool's agent under the default scope. The hold reaches
one level up: an agent that shares an environment with an agent two `AgentTool`s down, through a
middle agent that never uses it, is not refused either. `scope="session"` covers both. A direct call that passes no context
(your own code, not ADK's tools) is held to nothing. ADK 2.15 passes every
environment method the calling tool's context, which `PlimsollEnvironment` uses to tie each
call to its tool call, and builds the model's instructions without opening the environment, so
the first request to the model does not name the work directory; every request after the first
tool call does. ADK 2.15's per-user scope is not offered: a user's conversations would
share one sandbox's files, and the per-session scope already serves every user from one
environment. ADK for TypeScript,
Go and Java is not covered.

## The code executor

```python
import os
from google.adk.agents import Agent
from plimsoll_client import Client
from plimsoll_client.adk import PlimsollCodeExecutor, PlimsollCodeExecutorGuard

executor = PlimsollCodeExecutor(
    client=Client(os.environ["PLIMSOLL_URL"], token=os.environ.get("PLIMSOLL_TOKEN")),
    minimum_isolation="kernel",
    artifact_paths=("answer.json",),
)
agent = Agent(name="calculator", model=your_existing_model, code_executor=executor)
```

Register the execution guard first on your Runner:

```python
from google.adk.artifacts import InMemoryArtifactService
from google.adk.runners import Runner

runner = Runner(
    agent=agent,
    app_name="calculator",
    session_service=your_session_service,
    # Required when the executor names artifact_paths (see below).
    artifact_service=InMemoryArtifactService(),
    plugins=[PlimsollCodeExecutorGuard()],
)
```

`your_session_service` is the session service your application configures; in
production, pass your own artifact service in place of the in-memory one.
ADK 2.15 saves every file a block returns through the Runner's artifact service, and
without one it raises `ValueError: Artifact service is not initialized.` after the block
has run (ADK 2.14 did so for every execution, files or not). The guard refuses a Runner with
no artifact service whose agents (sub-agents and agents wrapped as tools with `AgentTool`
included) use a `PlimsollCodeExecutor` that names `artifact_paths`, in ordinary and live
runs, before any model or code request (`UnsupportedError`, marked
`not_dispatched="unsupported"`, inside ADK's `RuntimeError`). An executor hands ADK only the
files its `artifact_paths` name, so one that names none needs no artifact service.

Keep `RunConfig.support_cfc` false. In ADK 2.15.0, as in 2.14.1, compositional function calling
(planning several tool calls together) with `support_cfc=True` replaces a root
agent's custom executor with Gemini's built-in code execution. That route sends no
code to plimsoll and provides neither its isolation floor nor its checked run record.
The guard refuses this combination before any model or code request in both
ordinary and live Runner calls. ADK wraps
plugin exceptions in `RuntimeError`; its cause is an `UnsupportedError` marked
`not_dispatched="unsupported"`. Put this guard before other plugins.

Registering only `PlimsollCodeExecutor` cannot prevent that upstream replacement:
ADK never calls the replaced executor. A plain Runner without the guard remains
subject to this configuration bypass. The guard validates Runner invocations;
applications that construct model requests outside Runner must enforce the same rule.

`your_existing_model` is the model your application already configures. The adapter
does not select a model provider or call a model API. ADK's standard code-block flow
supports Python; this executor does not add JavaScript to that flow.

The guard also tells the model how to run code. ADK 2.15 adds its own instruction (a
fenced block, no native `executable_code` parts) only when `optimize_data_file` is on,
which this executor refuses, so without it the model would get no word on the fence or on
the fresh sandbox, and Gemini may answer with a native code part the API rejects. The guard
appends `plimsoll_client.adk.CODE_EXECUTION_INSTRUCTION` to the request of every agent that
executes through plimsoll, with the executor's first code-block delimiters (ADK's default is
a `tool_code` fence; a `python` fence also runs). Another reason to register the guard.

Input strings in ADK's `File.content` are base64-encoded; byte values are raw bytes.
The adapter follows that distinction and accepts UTF-8 text, including CSV and JSON.
`optimize_data_file=True` is refused at construction. ADK's CSV exploration creates
dataframe variables for subsequent blocks, but each block here has a new interpreter.
Installing pandas does not make those variables persist. An application can supply
CSV text through `CodeExecutionInput.input_files` for each block and have that block
read it explicitly. This does not enable ADK's automatic attachment preprocessing;
do not assume that attaching a CSV to a Runner message loads a reusable dataframe.
Binary input, and text that is not UTF-8 (a Windows-1252 export from Excel, say), is
refused before dispatch, naming the file; convert it to UTF-8 before adding it. The model must use `print` to return a
Python value. A bare expression is not implicitly printed.

`artifact_paths` is an application-configured list of relative output paths. The
daemon captures only those files. The adapter returns their raw bytes in ADK's
`output_files`, so JSON, images and other binary output retain their bytes.

Each RPC call with a step report returns `PlimsollCodeExecutionResult`, which ADK accepts
as its native `CodeExecutionResult`. Its additional `execution` field holds the
complete `ProjectResult`: original output bytes, isolation, checked run record,
artifacts, outcome and truncation flags. ADK sends the model its native text event;
that event does not automatically include the extra metadata. A checked record
detects inconsistent data; it does not independently attest a remote daemon.

The executor deliberately refuses `stateful=True`. Variables, imports and files
from one call are absent from the next. ADK 2.15 checks `error_retry_attempts` before
the initial execution, so zero would disable execution and is refused. The default
is ADK's own two attempts, allowing the model to correct a failed block. Applications
can set `error_retry_attempts` to any integer of one or more. Each corrected block
runs in a fresh sandbox.

A refusal before dispatch (any `not_dispatched` reason: the isolation floor, a daemon at
capacity or unreachable, an input file that is not UTF-8 text) is returned as a failed
result, as ADK's own executors report a failure, never raised: ADK calls the executor
with no exception handler, so an exception would end the Runner invocation. Its `stderr`
starts `Nothing ran (<reason>): `, so the model reads that nothing ran, ADK's retry count
bounds further tries within the turn, and later turns of the session are unaffected. The
result's `refusal` field holds the typed error; `execution` and `exit_code` are `None`.
An error without `not_dispatched` may have followed execution, so it propagates and is
never replayed by this adapter.

When no step report arrives, including a `setup_failed` or `protocol_error` result,
the adapter raises `PlimsollCodeExecutionError` and stops the Runner invocation.
Its `execution` field preserves the complete checked result and record. It has no
`not_dispatched` mark: the program may have run, so automatically repeating the
block could repeat its effects. The application must resolve that uncertainty
before choosing whether to make another call. Outcome text alone does not prove
that code never started.

ADK currently classifies its execution event from `stderr`, rather than `exit_code`.
For an observed step, the adapter adds a diagnostic for a nonzero exit with empty
stderr, failed setup, or timeouts. Truncation adds no stderr diagnostic, so cutting otherwise successful
output does not make ADK report a failure. Original bytes and flags remain in `execution`.
ADK would also read any stderr as a failure: it shows the model the stderr alone, drops
stdout, and after `error_retry_attempts` such results stops executing for the turn. So the
exit status decides, as in ADK's own `UnsafeLocalCodeExecutor`: when the program exits 0
and the run completed, its stderr (a warning, say) is appended to `stdout` under the heading
`stderr (the program exited 0):` and ADK gets empty `stderr`. The original bytes stay in
`execution`.

The default budget is 30 seconds, intended for interactive calculations within the
daemon's five-minute maximum. `timeout_seconds` accepts a positive integer up to
300. ADK runs this synchronous executor in a worker thread and gives it no cancellation
signal, so the guard records the asyncio task each model call runs in, and the execution
watches it: when that task is cancelled, a request not yet sent (the Describe before a
Run, say) is never sent, and one in flight has its connection cut, so the thread returns
at once instead of running to the deadline. The daemon's handler sees the connection
close; whether the provider then stops code already running is the provider's. A cut Run
may have executed, so it is never replayed. Without the guard, cancelling stops the wait
only, and the daemon's deadline bounds execution.

Use a project image containing Python and any needed packages, such as
`plimsoll/sandbox-python`. Dependencies are installed when the image is built,
never by the model at runtime. Ordinary Docker reports container isolation and is
refused by the default floor. A container floor is an explicit choice for controlled
development with your own code. Hostile code requires verified kernel or VM isolation.
Changing the endpoint does not carry variables or files to another provider.

Run the installed-framework suite without a model or paid sandbox. `make py-frameworks`
needs Python 3.12, the version CI uses, since the locks are hashed for it:

```sh
make py-frameworks
env -u E2B_API_KEY -u DOCKER_SBX_TOKEN PLIMSOLL_REQUIRE_CLIENTS=1 \
  go test ./clients/python -run 'TestPythonFrameworks/adk' -count=1 -v
```

The suite drives ADK's actual Runner with a scripted model through the real RPC
handler, including explicit text-file inputs and refusal of CSV optimization. The RPC provider in that suite is a fixture,
not proof of isolation. For a real local Docker/gVisor run, use:

```sh
PLIMSOLL_URL=http://127.0.0.1:8746 \
  tmp/py-frameworks/adk/bin/python clients/python/examples/adk_smoke.py
```

That example requires a locally installed client (the installation command above),
or `PYTHONPATH=clients/python/src` when running from the source checkout. It refuses
cloud providers and verifies the returned value, artifact bytes and kernel floor.

The same suite holds the environment's cases (`frameworks/adk/test_adk_environment.py`): the
contract over a stand-in session that counts every call it is handed, ADK's file tools giving
the same answers over `PlimsollEnvironment` as over ADK's `LocalEnvironment`, a scripted agent
through ADK's Runner with its records and span labels, and the retry case with and without the
guard. On a real Docker session, ADK's own tools, toolset and Runner, and the same command
script on `LocalEnvironment` (harmless commands only, in a temporary directory):

```sh
env -u E2B_API_KEY -u DOCKER_SBX_TOKEN go test ./clients/python -run '^TestADKEnvironmentDocker$' -count=1 -v
```

- [ADK environment toolset (EXTERNAL · official docs ↗)](https://adk.dev/integrations/environment-toolset/)
- [ADK code execution (EXTERNAL · official docs ↗)](https://adk.dev/integrations/code-execution/)
- [ADK plugins (EXTERNAL · official docs ↗)](https://adk.dev/plugins/)
- [Dependency images (INTERNAL · documentation →)](guest-dependencies.md)
- [Isolation tiers (INTERNAL · documentation →)](isolation-tiers.md)
- [Execution results (INTERNAL · documentation →)](run-results.md)
