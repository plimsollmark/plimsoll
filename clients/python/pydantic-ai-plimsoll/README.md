# pydantic-ai-plimsoll

A PydanticAI agent with file tools reads and writes wherever its workspace is, and PydanticAI's `LocalWorkspace` is
your own machine ("This isolates nothing", in its own docstring). This package makes the workspace one plimsoll
session instead: a sandbox in plimsoll, a sandbox service you run yourself, possibly somewhere else, that keeps the
agent's files from one step to the next and has no fallback: if the sandbox is weaker than you asked for, nothing
runs. Every call of the session gets a run record, a checked statement of what was sent, what came back and where it
ran.

It has three parts:

- **`PlimsollWorkspace`**, a PydanticAI capability that supplies one plimsoll session as the run's workspace, so
  PydanticAI's own `FileSystem` tools (read, write, edit, list, search, find, create a directory) work in the sandbox.
- **`plimsoll_shell`**, a shell tool the capability adds, which runs commands in the same session.
- **`plimsoll_code_tool`**, a tool that runs each call's Python or JavaScript in a fresh sandbox.

## Install

```sh
pip install pydantic-ai-plimsoll pydantic-ai-harness
```

PydanticAI's `FileSystem` capability, which the example below uses, is in `pydantic-ai-harness`. Install the two in
one command: each `pydantic-ai-harness` release requires one exact `pydantic-ai-slim`, so in one command pip picks the
harness release that matches this package's pin, while a later `pip install pydantic-ai-harness` on its own takes the
newest release and replaces the pinned `pydantic-ai-slim` with its own.

It needs a running `plimsolld`, the plimsoll daemon, reachable from the agent
([getting started (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/getting-started.md)).
The workspace needs a provider with sessions: docker (with a project image), E2B or OpenShell today
([which providers (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#which-providers)).
Sessions are off until the daemon is started with `SANDBOX_MAX_SESSIONS` set (for example `SANDBOX_MAX_SESSIONS=4`);
without it the workspace raises `PlimsollWorkspaceGoneError`, saying the daemon has no sessions.
Python 3.11 or later, as PydanticAI requires.

## Use the workspace

```python
from pydantic_ai import Agent
from pydantic_ai_harness import FileSystem
from pydantic_ai_plimsoll import Client, PlimsollWorkspace

workspace = PlimsollWorkspace(client=Client("https://plimsoll.internal:8746", token=TOKEN),
                              minimum_isolation="kernel")
agent = Agent(model, capabilities=[workspace, FileSystem()])
result = await agent.run("Write a script that counts the words in notes.txt, then run it.")
```

**PydanticAI's `Coder` and `Shell` add no shell tool here, and say nothing about it.** With this package as the
workspace, an agent given `Coder` or `Shell` has no `shell` or `run_command` tool at all, and no error tells you or the
model why (PydanticAI leaves those tools out when the workspace has no commands). Give commands to the agent through
`plimsoll_shell`, which this package adds, instead.

What the workspace needs and does:

- **The floor is yours to set.** `minimum_isolation` (`process`, `container`, `kernel` or `vm`) has no default. When the
  session opens, its tier is checked against the floor before anything runs; below it, the session is closed and the
  run's workspace operation raises `PlimsollWorkspaceGoneError`.
- **Files only, as PydanticAI counts it.** The backend implements PydanticAI's `WorkspaceBackend`,
  `SupportsFilesystem` and `SupportsRealpath`; it does not implement `SupportsCommands`. PydanticAI's contract for a
  backend with commands says it must "never stop a process the command detached into its own session", and plimsoll's
  sessions kill every process a call leaves behind when the call ends. So `ctx.workspace.run` raises PydanticAI's
  `UserError`, and **PydanticAI's `Coder` and `Shell` capabilities do not work on it**: they run every command as a
  background job and check on it with later calls, and with no command support their shell tools are left out of the
  model's tools without an error. Commands go through `plimsoll_shell` instead.
- **`plimsoll_shell` runs in the same session**, so it sees the files the file tools wrote. The shell is the image's
  (BusyBox `sh` on plimsoll's docker images, not bash); the shell's directory and its exported variables persist from
  one command to the next. A process left running in the background is stopped when its command returns, and a
  background process that keeps the command's output open makes the command wait until it exits or the command's time
  budget ends; the tool's description tells the model both. A non-zero exit and a command past its budget are results
  the model reads. Pass `shell_tool=False` to leave the tool out.
- **One process, or every process with a checkpoint store.** A later run of the same conversation, whose message
  history carries the workspace's ref, reaches the same session through the capability's registry of open sessions in
  this process. Give the capability a `checkpoint_store` and a `checkpoint_key` (a function of the run context
  returning a key you derive from your verified user and conversation, never from model or user text), and a run in
  another process takes the session over from the store (plimsoll's session reattach) and keeps it for the backends
  rebuilt there; the process that held it is refused from then on, and takes the session back from the store once,
  sending its operation again, before it gives up. Every call passes through the store, so two processes never send
  at once. A call whose answer was lost leaves the store pending with that call; the next process takes the session
  over across it, and plimsoll returns the lost call's record, which says whether the daemon answered the call (which
  does not show that the command ran to its end) or the call ended without an answer (which does not show that the
  command started: it may have done none, part or all of its work), and the call's answer when the daemon kept it
  (it keeps the last answer in memory unless the session was opened to keep none).
  The session is then recovering, and plimsoll's client sends nothing until it is resolved. The model's next tool
  call, whichever it is (`plimsoll_shell` or a file tool), is not run: the lost call's record goes to your
  `record_sink` first, the model gets a failed tool result (PydanticAI's `ToolFailed`) saying what the record says and
  the lost call's output when its answer came back (cut to `max_output_chars`), the backend resolves the session, and
  the run goes on. So a lost command or file write is never sent again before the model has been told; once told, the
  model may send it again on purpose, and then it runs. The store is an object with `load` and an atomic `compare_and_set`, kept where only your application can write
  ([checkpoint store (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#carrying-a-session-on-from-another-worker)),
  and the client needs `daemon_name` equal to the capability's `daemon` and a token: plimsoll refuses the takeover in
  open development mode. Without a store, another process, or this one after a restart, gets
  `PlimsollWorkspaceGoneError`. Either way the backend never opens a fresh sandbox in place of the one a ref names,
  because the agent would take it for the one holding its files. The ref is
  `WorkspaceRef(provider="plimsoll", id="<daemon>/<fingerprint>")`, the name you gave the daemon (`daemon=`, default
  `"plimsoll"`) and the session's public fingerprint, never the session ID (which works as a key) or a URL. With
  `owner=`, a function of the run context that names your application's verified end user, a ref reaches a session
  only for the user who opened it, and the daemon's per-user cap applies (`SANDBOX_MAX_SESSIONS_PER_OWNER`).
- **Not for durable execution yet.** Under Temporal, DBOS or Prefect, PydanticAI rebuilds the backend for every
  workspace call in whichever worker runs it, and runs a call again when its answer was lost. The checkpoint store is
  what makes that safe, but no engine's own test has run against this package yet, so it still refuses durable
  execution with a `UserError` that says why, before anything runs.
- **A run never closes the session.** It ends when its lifetime does (`lifetime=`, which may only shorten the
  daemon's, 30 minutes by default and 12 hours at most), or when you call `workspace.destroy(ref)`. A session left idle
  is suspended by the daemon and resumes, files kept, on its next call.
- **Every call has a budget,** 120 seconds unless you set `timeout`; `max_timeout` caps it.

## Kill the worker, keep the sandbox

The example `pydantic_ai_crash.py`
([the example, its page in its header (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/clients/python/examples/pydantic_ai_crash.py))
answers the question PydanticAI's crash recovery leaves open: did the call that was in flight run? The second worker's
first tool call after the takeover, whatever it is, is not run, and the model is told what plimsoll knows of the lost
call first; a command the model then sends again on purpose runs.

1. A worker process runs a PydanticAI agent that writes `triage.py` into its plimsoll sandbox and runs it with
   `plimsoll_shell`.
2. A supervisor kills that worker with `SIGKILL` 1.5 seconds into the command.
3. A second worker continues the run from PydanticAI Harness's `StepPersistence` (its frontier snapshot, taken just
   before the tool ran), whose ledger marks the call "started" with no end.
4. PydanticAI sends the call that was in flight again; the second worker takes the sandbox over across it from the
   checkpoint store, plimsoll's record of the lost call says the call ended without an answer (canceled), the resumed
   call is not sent, and the model gets a failed tool result saying so.
5. The model reads the file the cut command wrote, and PydanticAI accepts its typed answer only after an output
   validator checks it against that file in the sandbox.
6. The two workers' logs of checked run records form one chain, the lost call's record included, and the daemon's own
   count when the sandbox closes matches it.

With `--freeze`, the first worker is stopped between calls instead, and when it wakes after the second worker took
over, its write is refused by its own client, with nothing sent, because the application's checkpoint store no longer
serves it. The model is a scripted stand-in, so nothing calls a model service; it needs a daemon with sessions on,
the Python project image and a token, and `_conversation_lease.py` beside it (the checkpoint store the application
supplies). Its header lists every limit, and says why its evidence is not signed.

## Errors

A call that may have run is never reported as one that did not. PydanticAI's durable engines decide what to retry by
an error's class, so this package raises its own subclasses of PydanticAI's:

- **`PlimsollOutcomeUnknownError`**, a `WorkspaceUnavailableError`: the call may have run (its answer was lost, did
  not check, or its record could not be kept). It was not retried. Unless the session recorded the call, the session
  sends nothing more and later operations raise `PlimsollWorkspaceGoneError`.
- **`PlimsollLostCallError`**, PydanticAI's `ToolFailed` and a plain `WorkspaceError`: the first operation after a
  takeover across a lost call, which was not sent; its message is what the model is told (what the lost call's record
  says, and its output when its answer came back), and `.lost` holds the lost call. The backend resolved the session
  before raising it, so the next operation runs. Raised inside a tool, PydanticAI gives it to the model as a failed
  tool result and the run goes on.
- **`PlimsollWorkspaceGoneError`**, a `WorkspaceUnavailableError`: the session ended, is not open in this process, or
  plimsoll refused it for good (`reason` names which: `isolation`, `permission`, `closed`, `expired` and so on).
- **`PlimsollRetryableError`**, a `ConnectionError`: plimsoll refused before anything ran, and another try may pass
  (the daemon was busy, after the backend's own retries of up to about 30 seconds, or could not be reached).
- **The builtin file errors** (`FileNotFoundError`, `IsADirectoryError`, `NotADirectoryError`, `FileExistsError`,
  `PermissionError`) for a path, `ValueError` for an argument plimsoll refused, and PydanticAI's
  `WorkspaceTimeoutError` and `WorkspaceOutputLimitError` for a file operation past its budget or its answer's limit.

## Records

Every record the client checked goes to `record_sink=`, a function you pass; without one they are kept on the backend,
`backend.records`. The record of a call lost before a takeover goes there too, once, before the new process sends any
call (a sink that fails is offered it again on the next operation, and nothing is sent until it takes it), so the logs
of two processes that held the session form one chain with no hole. `JsonLinesRecordSink(path)` appends each to a file,
one JSON object a line; the lines of one session form its chain, each naming the one before. It is a log of checked
records, not a signed bundle.

## Use the code tool

```python
from pydantic_ai import Agent
from pydantic_ai_plimsoll import Client, CodeExecutor, plimsoll_code_tool

agent = Agent(model, tools=[plimsoll_code_tool(CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN)))])
```

The model gets back JSON saying whether the code ran (yes, no with the reason, or unknown), the output, the exit code,
whether anything was cut short or timed out, the isolation tier the code ran behind, and the SHA-256 of the run's
record. The tool never raises: a refusal is information for the model. Its answer's `metadata`, which PydanticAI keeps
for your application and does not send to the model, carries plimsoll's labels (`plimsoll_dispatched`,
`plimsoll_refused`, `plimsoll_outcome`, `plimsoll_isolation`, `plimsoll_record_sha256`), as does `plimsoll_shell`'s.
`CodeExecutor` requires the `kernel` tier by default. The tool's default language is Python, which on docker needs a
project image with `python3` in it (`SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python:latest`): on the default
image every Python call comes back refused, and `plimsoll_code_tool(..., languages=("javascript",))` offers
JavaScript instead.

**One web API, if you grant one.** `CodeExecutor(client, grant_profile="lights", api_description=...)`, with a profile
the operator configured on the daemon and the description `plimsoll-specgen` wrote for it, lets the code tool's code call
that profile's routes, and nothing else, through plimsoll's broker, which adds the API's key outside the sandbox.
JavaScript works on every provider that gives a project run a grant; Python too on docker and openshell, through
`import plimsoll_host` (pass `languages=("javascript",)` for a daemon elsewhere: the default, Python, is refused there
when the tool is built). The tool reads the daemon's answer when it is built, offers only the languages that can call
the API there, and tells the model the routes; the model never names a profile. The code can do whatever an allowed
route permits and read whatever it returns
([capability grants (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/capability-grants.md#from-an-agent-kits-code-tool)).
The workspace and `plimsoll_shell` take no grant.

## How it was tested

PydanticAI's own conformance suite for workspace backends (`pydantic_ai.workspaces.conformance`, pydantic-ai-slim
2.70.0) runs on real docker sessions: the 20 rules a backend with files only can be held to pass, and 20 of its 40
rules skip. Every one of those needs commands (every command rule, the file rules that make their case with a
command: a symlink, a FIFO, a `chmod`, and the attach rule that starts a detached process). The two other attach rules
run with a backend of a second capability, standing for another process, taking the session over from a shared
checkpoint store; three more cases there show a session taken back after another process took it, a command whose
answer was lost not sent again before the next process's model was told, and an agent in the next process told that
its lost command's call ended without an answer, its run going on, with the two processes' record logs forming one
chain. A separate check makes
those cases through `plimsoll_shell` (the links, a loop of links, a FIFO, an unreadable file) and holds the backend to
the same rules' expectations. Agents of the real
PydanticAI drive `FileSystem`, `Coder` and `plimsoll_shell` through a scripted model; no model provider is called by
any test.

## What it is not

- **Not a hosted service.** You run `plimsolld` on your own machine or cluster, with a provider you pick
  ([isolation tiers (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/isolation-tiers.md)).
- **Not attestation.** A reported tier is the daemon's configuration and provider evidence plus a startup check, not
  hardware proof.
- **Not supported:** PydanticAI's `Coder` and `Shell` (above); durable execution (above); a session reached from
  another process without a checkpoint store; background jobs that outlive their command.

## Versions

This package's version moves with plimsoll's releases, and each version requires the `plimsoll-client` release of the
same number, which holds the code (`plimsoll_client.pydantic_ai`). The names here are plimsoll-client's own, gathered
so an agent imports from one place. It pins `pydantic-ai-slim` at exactly 2.70.0: PydanticAI's guide says new or
stricter rules for backends may come in minor releases, so each new release is tested against the conformance suite
before the pin moves. The durable-execution check reads one private name of PydanticAI's
(`pydantic_ai.durable_exec._operation_backend.in_durable_unit`) and the run context's `in_durable_context`; it names
the durability capability in its refusal through a second private name (`pydantic_ai.durable_exec._base`), and a
test checks both are there at the pinned release.

Licensed under the Apache License 2.0. Source:
[plimsoll on GitHub (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/pydantic-ai-plimsoll).
