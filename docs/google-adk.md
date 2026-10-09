# Google ADK code execution through plimsoll

Google's Agent Development Kit (ADK) lets an agent execute Python blocks through a
`BaseCodeExecutor`. `plimsoll_client.adk.PlimsollCodeExecutor` sends those blocks to
a plimsoll daemon instead of executing on the agent's host. It uses the shared
checked Python client, one fresh sandbox per block, with kernel isolation required
by default. It ships in `plimsoll-client` 0.20.0 and later as the `adk` extra.

Recorded calls through this executor, from a CSV sum to a refused floor, replay on its
integration page: [see a run, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/integrations/google-adk/index.html).

Install it into your Python virtual environment, from PyPI or from the repository root:

```sh
pip install 'plimsoll-client[adk]'
pip install './clients/python[adk]'
```

The base client remains dependency-free. Only the `adk` extra and importing this
optional module require ADK. Verification pins Google ADK 2.11.0.

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
ADK 2.11 saves every code execution result through the Runner's artifact service, and
without one it raises `ValueError: Artifact service is not initialized.` after the block
has run. The guard refuses a Runner with no artifact service whose agents (sub-agents and
agents wrapped as tools with `AgentTool` included) use a `PlimsollCodeExecutor`, in
ordinary and live runs, before any model or code request (`UnsupportedError`, marked
`not_dispatched="unsupported"`, inside ADK's `RuntimeError`).

Keep `RunConfig.support_cfc` false. In ADK 2.11.0, compositional function calling
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

The guard also tells the model how to run code. ADK 2.11 adds its own instruction (a
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
from one call are absent from the next. ADK 2.11 checks `error_retry_attempts` before
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

- [ADK code execution (EXTERNAL · official docs ↗)](https://adk.dev/integrations/code-execution/)
- [ADK plugins (EXTERNAL · official docs ↗)](https://adk.dev/plugins/)
- [Dependency images (INTERNAL · documentation →)](guest-dependencies.md)
- [Isolation tiers (INTERNAL · documentation →)](isolation-tiers.md)
- [Execution results (INTERNAL · documentation →)](run-results.md)
