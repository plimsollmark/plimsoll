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
  0.28.0, and is tested with, and its extra installs, exactly ADK 2.14.1 (2.14.0
  made ADK's environment interface stable). [Next](#a-kept-sandbox-with-a-shell-and-files).

Recorded calls through the executor, from a CSV sum to a refused floor, replay on its
integration page: [see a run, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/integrations/google-adk/index.html).

Install it into your Python virtual environment, from PyPI or from the repository root:

```sh
pip install 'plimsoll-client[adk]'
pip install './clients/python[adk]'
```

The base client remains dependency-free. Only the `adk` extra and importing this
optional module require ADK. Verification pins Google ADK 2.14.1.

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
at `minimum_isolation`, and learns the work directory (`/work` on docker), which ADK names
to the model. An open whose await is cancelled closes the session it made, so it does not
hold a place on the daemon, and a `close()` made while an open is on its way waits for that open
and closes the session it made. `Runner.close()`, which the `async with` above calls, closes the toolset, and
that closes the session: the sandbox and its files are gone. `initialize()` after that opens
a new, empty sandbox, as ADK's own lifecycle has it. `lifetime=`, `idle_timeout=`, `owner=`
and `trace_id=` go with the open as for `Client.open_session`.

**If the agent ends without closing**, nothing in your process closes the session. The
daemon does: after its idle limit (5 minutes by default) it suspends the session (on docker
the sandbox is paused and keeps its place), and at the session's lifetime (30 minutes by
default) it closes it and deletes the sandbox. Close the Runner, or open with a short
`lifetime=`.

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
before anything is sent. Files of any bytes are read and written, 8 MiB a call, and a file
is read whole up to 64 MiB: a longer one is a `WorkspaceTooLargeError`, refused after its first
piece, since a sandbox can make a file of any size for nothing (a sparse file) and a read ends in
your process's memory. A file longer than one call which changes size while it is read (ADK may run an `Execute` beside
a `ReadFile`) is a `WorkspaceChangedError`, an `OSError`, never a cut copy.
A missing file is `FileNotFoundError`, a directory `IsADirectoryError`, a file the sandbox's
user cannot read `PermissionError`, as ADK's tools expect.

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
  conversations share it.

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
plimsoll's docker images, not bash. When the session has ended (its lifetime, the daemon),
every later call raises `SessionEndedError`, marked not dispatched: the environment never
opens a new sandbox in its place, as ADK's E2B environment does, because the agent would
take an empty sandbox for the one with its files. After a call that may have run without an
answer, the client sends nothing more on that session. Do not share one environment between an
agent and an agent it wraps with `AgentTool`: ADK runs the wrapped agent in a nested Runner
that closes that agent's toolsets when it finishes, and a toolset's close closes its
environment, so the session is closed under the agent that wraps it (ADK's own guide warns of
this for any two toolsets that share one environment). Give the wrapped agent an environment of
its own; its sandbox is gone when it finishes. ADK's main branch after 2.14.1 (read at commit 691ecbee)
passes every environment method the calling run's context and first calls `initialize()` at
the first tool call; `PlimsollEnvironment` accepts that context already, and on that version
the first request to the model does not yet name the work directory. ADK for TypeScript, Go
and Java is not covered.

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
    # Required for every execution, not only when files come back (see below).
    artifact_service=InMemoryArtifactService(),
    plugins=[PlimsollCodeExecutorGuard()],
)
```

`your_session_service` is the session service your application configures; in
production, pass your own artifact service in place of the in-memory one.
ADK 2.14 saves every code execution result through the Runner's artifact service, and
without one it raises `ValueError: Artifact service is not initialized.` after the block
has run. The guard refuses a Runner with no artifact service whose agents (sub-agents and
agents wrapped as tools with `AgentTool` included) use a `PlimsollCodeExecutor`, in
ordinary and live runs, before any model or code request (`UnsupportedError`, marked
`not_dispatched="unsupported"`, inside ADK's `RuntimeError`).

Keep `RunConfig.support_cfc` false. In ADK 2.14.1, compositional function calling
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

The guard also tells the model how to run code. ADK 2.14 adds its own instruction (a
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
from one call are absent from the next. ADK 2.14 checks `error_retry_attempts` before
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
