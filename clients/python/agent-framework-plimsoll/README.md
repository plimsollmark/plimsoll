# agent-framework-plimsoll

An agent with a shell runs whatever commands its model writes. Microsoft Agent Framework's own `LocalShellTool` runs them
on your machine ("arbitrary commands run on the host with the agent's privileges", in its own error message), and
`DockerShellTool` runs them in a container on the agent's machine. This package runs them in plimsoll instead, a
sandbox service you run yourself, possibly somewhere else, and it has no fallback: if the sandbox is weaker than you
asked for, nothing runs.

It has three parts:

- **`PlimsollShellTool`**, the agent's shell over one plimsoll session: the files a command writes, the shell's
  directory and its exported variables are there for the next command.
- **`PlimsollFileStore`**, the harness's file store over the same session: the model's file tools (read, write, list,
  grep, replace) and its shell work on one sandbox, so a file written with either is the file the other reads.
- **`plimsoll_code_tool`**, a tool that runs each call's Python or JavaScript in a fresh sandbox.

## Install

```sh
pip install agent-framework-plimsoll
```

It needs a running `plimsolld`, the plimsoll daemon, reachable from the agent
([getting started (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/getting-started.md)).
The shell tool needs a provider with sessions: docker (with a project image), E2B or OpenShell today
([which providers (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#which-providers)).
Sessions are off until the daemon is started with `SANDBOX_MAX_SESSIONS` set (for example `SANDBOX_MAX_SESSIONS=4`);
without it entering `PlimsollShellTool` raises plimsoll's `UnsupportedError`, saying the daemon has no sessions.
Python 3.11 or later, as Agent Framework requires.

## Use the shell tool

```python
from agent_framework import InMemoryAgentFileStore, create_harness_agent
from agent_framework_plimsoll import Client, PlimsollShellTool

async with PlimsollShellTool(Client("https://plimsoll.internal:8746", token=TOKEN),
                             minimum_isolation="kernel") as shell:
    agent = create_harness_agent(chat_client, shell_executor=shell, file_memory_store=InMemoryAgentFileStore())
    session = agent.create_session()
    print(await agent.run("Count the lines in every .py file here.", session=session))
```

`file_memory_store=InMemoryAgentFileStore()` is there because the harness otherwise keeps its file memory (notes the
model writes for itself with its `file_memory_*` tools, shown back to it on each run) in `./agent-file-memory/` on the
machine the agent runs on, outside the sandbox. Agent Framework's `InMemoryAgentFileStore` keeps that memory in the
agent's own process instead: nothing is written to disk, and the memory lasts as long as the store object does.
`disable_file_memory=True` turns the memory off.

The tool is Agent Framework's shell executor (`start`, `run`, `close`, `as_function`), so the harness gives it to the
model as its `run_shell` tool and its environment provider runs a few commands through it to tell the model what shell it
has. With an agent of your own, `client.get_shell_tool(func=shell.as_function())` is the same tool.

**The chat client has to carry a shell tool.** `create_harness_agent` gives the model the shell only when the chat client
implements Agent Framework's `SupportsShellTool`; otherwise it logs "Shell tool not available" as a warning, leaves the shell
out, and the agent answers without running anything in plimsoll. `OpenAIChatClient` (OpenAI's Responses API) and
`AnthropicClient` carry it, and so do the clients built on them (Foundry, Azure AI, and Anthropic on Bedrock, Foundry and
Vertex); `OpenAIChatCompletionClient` and the Ollama, Gemini, Bedrock and GitHub Copilot clients do not (read from those
packages' source as published on 2026-11-22). Check with `isinstance(chat_client, SupportsShellTool)` before relying on it.

What the shell tool needs and does:

- **The floor is yours to set.** `minimum_isolation` (`process`, `container`, `kernel` or `vm`) has no default. When the
  session opens, its tier is checked against the floor before any command is sent; below it, the session is closed and
  `InsufficientIsolationError` is raised.
- **One session for the conversation.** A process left running in the background is stopped when its command ends. A
  session left idle is suspended by the daemon and resumes, files kept, on its next command. Once the session has ended
  (its lifetime ran out, the daemon closed it, or you closed the tool), every later command raises `SessionEndedError`;
  the tool never opens a fresh sandbox in its place, because the agent would take it for the one holding its files.
- **A refusal raises, and a command that may have run stops the run.** A command plimsoll refused before anything ran,
  and a command on an ended session, raise plimsoll's own exceptions, and the model is shown the framework's error result
  ("Error: Function failed.", with the detail only if you set the framework's `include_detailed_errors`), never a refusal
  dressed as command output. A command that may have run without an answer to show for it (the answer was lost, the
  run ended without the command's report, or any error plimsoll cannot vouch ran nothing) ends the agent's run instead: `agent.run` raises Agent Framework's
  `MiddlewareFailure`, whose `__cause__` is plimsoll's error, so the model never gets the chance to run it again. They are plimsoll's exceptions, not Agent Framework's own shell errors, because its
  environment provider reads a probe that raises one of those as a command that is not installed. A command that runs
  and fails, and one past its time budget, are normal results.
- **No human approval by default.** The tool's `approval_mode` is `never_require`: the sandbox, not a person, is the
  boundary. Microsoft's own `LocalShellTool` and `DockerShellTool` default to `always_require`, which asks a person to
  approve each command, so swapping one of them for this tool drops that step unless you keep it:
  `PlimsollShellTool(client, minimum_isolation="kernel", approval_mode="always_require")`.
- **Every command has a budget,** 120 seconds unless you set `timeout`; `max_timeout` caps any budget. plimsoll enforces
  it: the daemon stops the command and kills whatever it left running.
- **The shell is the image's.** On plimsoll's docker images that is BusyBox `sh`, not bash; the tool's description tells
  the model so.
- **The environment provider describes the agent's machine, not the sandbox.** Agent Framework's
  `ShellEnvironmentProvider` tells the model it is "operating a POSIX shell session on" a description of the operating
  system it reads with Python's `platform.platform()` in the agent's own process, which names the agent's host, not
  plimsoll's Alpine image or the sandbox's kernel. Its `instructions_formatter` option replaces that text.

## Give the harness files too

```python
from agent_framework import InMemoryAgentFileStore, create_harness_agent
from agent_framework_plimsoll import Client, PlimsollShellTool, harness_options

async with PlimsollShellTool(Client("https://plimsoll.internal:8746", token=TOKEN),
                             minimum_isolation="kernel") as shell:
    agent = create_harness_agent(chat_client, **harness_options(shell), file_memory_store=InMemoryAgentFileStore())
    session = agent.create_session()
    print(await agent.run("Write a plan to plan.md, then run the tests it names.", session=session))
```

`harness_options(shell)` fills both of the harness's slots on the shell tool's one session: `shell_executor` (the shell
tool) and `file_access_store` (a `PlimsollFileStore` over it), and sets the file tools' approval to the shell tool's
`approval_mode`. Agent Framework otherwise asks a person to approve every file tool call; an approval on a file write
while the shell writes the same files unasked would guard nothing, so the two go together, and
`PlimsollShellTool(..., approval_mode="always_require")` makes a person approve both. `PlimsollFileStore(shell)` alone
is the store, for `file_access_store=`.

- **`file_approval` sets the file tools' approval on its own.** `harness_options(shell, file_approval="always_require")`
  keeps Microsoft's default, a person approves every file tool call whatever the shell does;
  `file_approval="never_require"` asks for none; `None`, the default, follows the shell. Pass it there: the harness's
  own switches (`file_access_disable_readonly_tool_approval`, `file_access_disable_write_tool_approval`) given beside
  `**harness_options(shell)` are a keyword given twice, which Python refuses with `TypeError`.
- **A chat client with no shell tool keeps the file tools.** The harness leaves the shell out (the "Shell tool not
  available" warning above) but still gives the model the file tools on the sandbox, and since they follow the shell
  tool's `approval_mode` (`never_require` unless you set it), nobody is asked before a file write. The sandbox still
  bounds what a write reaches; if you want a person to approve each one, pass `file_approval="always_require"`.
- **The harness tells the model its files last; these do not.** Its file instructions say "These files persist beyond
  the current session and may be shared across sessions or agents"; with this store they are the sandbox's files, and
  they end when the sandbox session does. `create_harness_agent` takes no text for its file tools, so to change it,
  leave `harness_options` out and pass a provider of your own, with the two approval switches set as you want them:

  ```python
  from agent_framework import FileAccessProvider

  files = FileAccessProvider(PlimsollFileStore(shell), instructions=YOUR_TEXT,
                             disable_readonly_tool_approval=True, disable_write_tool_approval=True)
  agent = create_harness_agent(chat_client, shell_executor=shell, context_providers=[files],
                               file_memory_store=InMemoryAgentFileStore())
  ```
- **Keep the harness's memory out of the sandbox.** With `file_memory_store=PlimsollFileStore(shell)`, every
  `agent.run` after the sandbox session ends raises `SessionEndedError` before the model is called (the harness makes
  the memory's directory on each run and does not catch the error), and code the shell runs can rewrite the memory's
  index, which the harness shows the model as a user message on each run. Use `InMemoryAgentFileStore()` for memory
  that stays off the agent's disk.
- **A folder per session ends with the sandbox too.** With `file_access_session_scoped=True` (or a `scope`), the
  harness makes the session's folder in the store at the start of every run, outside any error handling, so once the
  sandbox session has ended every `agent.run` raises `SessionEndedError` before the model is called. Without it, the
  run goes on, and each file tool call comes back to the model as the framework's error result.

What the file store does and refuses:

- **Paths are relative to the sandbox's work directory** (`/work` on docker and E2B, `/tmp/work` on OpenShell). A path that is absolute, holds a `.` or
  `..` segment, a backslash or a control character, or names the workspace's own state (`.plimsoll-shell`) is
  refused with `ValueError` before anything is sent.
- **No symbolic links, anywhere on the path.** A path through a link (the last component included, a dangling link
  included, a link that points inside the work directory included) is refused with `ValueError` and the operation
  does not happen; a listing leaves links out and a search skips them. The store looks at each part of the path (one
  `stat` call each, which never follows the link it names) before the operation's own call, and a link that leaves
  the work directory is refused inside that call too: plimsoll's helper resolves every path beneath the work
  directory in one kernel call (`openat2` with `RESOLVE_BENEATH`), so a link swapped in between the two by a process
  of the guest's still reaches no file outside it (one that stays inside is followed, to a file the store could name
  by its own path). On OpenShell that second refusal is not there: its sessions take file calls in the sandbox scope
  alone (an absolute path, links followed, because the work directory there is not a mount of its own:
  [why (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/openshell.md#sessions)), so the
  store's look at each part is the whole check, and a link swapped in between the look and the call by a process of
  the guest's is followed, out of the work directory, to whatever the sandbox's user may reach. These refusals keep
  the store's paths inside the work directory, as Agent Framework asks of a store; what keeps the agent's code in is
  the sandbox, not the store.
- **Files up to 1 MiB by default, 8 MiB at most.** A write past `max_file_bytes` (1 MiB by default, at most 8 MiB, the
  most one file call reads) is refused with `OSError` (`errno.EFBIG`) before anything is sent; a file past it in the
  sandbox (a sparse one costs the guest nothing) is never read, since its size is read first, and a search skips it.
  Larger files are the shell's. A write up to 4 MiB is one call that publishes the whole file at once; a longer one
  is the first 4 MiB, then appends, and a failure partway leaves the first pieces.
- **Text only.** The framework's file store holds `str`: a file that is not UTF-8 raises `ValueError` on read and is
  skipped by a search, as Microsoft's own disk store does. A name the store does not take as a path (one holding a
  newline or another control character, or a backslash) is left out of its listings and searches.
- **It never reaches past what the shell can.** It is the same session, with the same floor and no grant: every
  operation is one or a few of the session's file calls, carried out inside the sandbox by plimsoll's own helper as
  the sandbox's user, with typed answers; no operation sends shell text. The session must take file calls: docker,
  E2B and OpenShell sessions do
  ([which providers and scopes (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#files)),
  and on one that does not (a daemon from before file calls) every operation raises plimsoll's `UnsupportedError`
  with nothing sent.
- **Errors are the framework's kind.** `FileExistsError` (`overwrite=False` on a file there), `IsADirectoryError`,
  `NotADirectoryError` and `PermissionError` reach the model as the file tool's own message. A refusal of plimsoll's
  before anything ran raises plimsoll's exception, and an operation that may have run without an answer ends the
  agent's run with `MiddlewareFailure`, as a shell command does.
- **What it does not carry:** the file tools' results are the framework's text, so they carry none of plimsoll's
  labels (each call still has its run record in the session's chain). A search lists the files in scope, a page of
  about 1 MiB a call, and reads them up to 16,384 files and about 8 MiB a call; the pattern is matched in the agent's process
  with the framework's own compiler, never in the sandbox. 5,000 small files take about 1.0 s under runc and 1.1 s
  under gVisor; 60,000 take about 7.2 s under gVisor, inside the framework's 10-second bound for one search, in 4
  read calls of up to 16,384 files (measured 2026-11-27 on docker; at 1,024 files a call it was 59 calls and 10.5 s). Each operation costs one call per part of its path beside its own (a file at
  `notes/today.txt` is three calls; a read three parts deep took about 0.4 s under runc, 0.3 s under gVisor). Agent Framework marks its file store experimental, and
  importing the package prints its warning once.

## Use the code tool

```python
from agent_framework import Agent
from agent_framework_plimsoll import Client, CodeExecutor, plimsoll_code_tool

tool = plimsoll_code_tool(CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN)))
agent = Agent(client=chat_client, tools=[tool])
```

The model gets back JSON saying whether the code ran (yes, no with the reason, or unknown), the output, the exit code,
whether anything was cut short or timed out, the isolation tier the code ran behind, and the SHA-256 of the run's
record. The tool never raises: a refusal is information for the model, and Agent Framework ends a request after three
tool errors in a row. `CodeExecutor` requires the `kernel` tier by default. The tool's default language is Python,
which on docker needs a project image with `python3` in it (`SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python:latest`):
on the default image every Python call comes back refused.

**One web API, if you grant one.** `CodeExecutor(client, grant_profile="lights", api_description=...)`, with a profile
the operator configured on the daemon and the description `plimsoll-specgen` wrote for it, lets the code tool's code call
that profile's routes, and nothing else, through plimsoll's broker, which adds the API's key outside the sandbox.
JavaScript works on every provider that gives a project run a grant; Python too on docker and openshell, through
`import plimsoll_host` (pass `languages=("javascript",)` for a daemon elsewhere: the default, Python, is refused there
when the tool is built). The tool reads the daemon's answer when it is built, offers only the languages that can call
the API there, and tells the model the routes; the model never names a profile. The code can do whatever an allowed
route permits and read whatever it returns
([capability grants (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/capability-grants.md#from-an-agent-kits-code-tool)).
The shell tool's session takes no grant.

## What reaches your application

Each command's answer carries what plimsoll states about the call, and nothing of it comes from what the command printed:

- **`await shell.run(command)`** returns a `PlimsollShellResult`, Agent Framework's own `ShellResult` with the tier the
  command ran at (`isolation`), the sentence the provider states beside the tier (`isolation_qualification`, empty when
  it states none), how the run ended (`outcome`), the SHA-256 of the run record the client checked (`record_sha256`)
  and the checked result itself (`result`, whose `record` is the record).
- **Through an agent**, each command's function result keeps the model's text, and its text item's
  `additional_properties` carry the five fields Microsoft's own shell tool puts there (`stdout`, `stderr`, `exit_code`,
  `truncated`, `timed_out`) and plimsoll's labels: `plimsoll_dispatched` (`yes`, `no`, or `unknown` when an error left
  it open), `plimsoll_refused` (the reason, when nothing ran), `plimsoll_outcome`, `plimsoll_isolation`,
  `plimsoll_isolation_qualification` and `plimsoll_record_sha256`. The code tool's function result carries the same
  labels. Each value is checked against the values plimsoll can state and left out if it does not match.
- **A refusal**, which the shell tool raises, reaches a function middleware of yours as the exception itself, with its
  reason in `not_dispatched`; `call_labels(exception)` gives the same labels.

```python
from agent_framework import function_middleware
from agent_framework_plimsoll import call_labels

@function_middleware
async def record_plimsoll(context, call_next):
    try:
        await call_next()
    except Exception as e:
        log.info("refused or lost: %s", call_labels(e))
        raise
    log.info("ran: %s", context.result[0].additional_properties)

agent = create_harness_agent(chat_client, shell_executor=shell, middleware=[record_plimsoll])
```

## Retries

Agent Framework does not run a failed tool call again by itself: a tool's exception becomes one error result for the
model, and three in a row end the request. After a refusal the model may ask for the same command again, which is safe,
since nothing ran; after a command that may have run, the run has already stopped. If you add a retry of your own,
ask `plimsoll_client.retry_on(exception)` first: it says yes only to a refusal plimsoll marked as having run nothing,
when another try may pass (the daemon was at capacity, or could not be reached before anything was sent). Every other
error may have followed the command running, and a second run could repeat what it did.

## Tracing

When Agent Framework's OpenTelemetry instrumentation is on (it is by default) and your application has an OpenTelemetry
SDK recording spans, the framework opens a span for each tool call, and both tools add plimsoll's labels to it as
attributes named `plimsoll.dispatched`, `plimsoll.refused`, `plimsoll.outcome`, `plimsoll.isolation`,
`plimsoll.isolation_qualification` and `plimsoll.record_sha256`, on results and on refusals alike. They never add the
command, the code or the output. Whether the framework itself records a tool's arguments and result on that span is the
framework's own sensitive-data setting, not this package's.

## What it is not

- **Not a hosted service.** You run `plimsolld` on your own machine or cluster, with a provider you pick
  ([isolation tiers (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/isolation-tiers.md)).
- **Not attestation.** A reported tier is the daemon's configuration and provider evidence plus a startup check, not
  hardware proof.
- **Not supported:** an interactive terminal; a session reattached from another process (the tool holds its session in
  the process that opened it); a CodeAct provider (Agent Framework's other way to run code, as Microsoft's Hyperlight
  and Monty packages do).

## Versions

This package's version moves with plimsoll's releases, and each version requires the `plimsoll-client` release of the
same number, which holds the code (`plimsoll_client.agent_framework`). `Client`, `CodeExecutor`, `PlimsollShellTool`,
`PlimsollShellResult`, `PlimsollFileStore`, `harness_options`, `plimsoll_code_tool` and `call_labels` here are
plimsoll-client's own names, gathered so an agent
imports from one place. It is tested with, and installs with, exactly `agent-framework-core` 1.26.0 and exactly
`agent-framework-tools` 1.0.0b261112, the framework's shell tools, a beta released about weekly: pip installs those
versions beside it and refuses others, and each new release of either is tested before its pin moves. The tool marks itself as the agent's shell with a constant from a private module of Agent
Framework (`agent_framework._tools.SHELL_TOOL_KIND_VALUE`), as Microsoft's own `DockerShellTool` does, and the file
store's search uses the framework's own pattern compiler and time bound from another
(`agent_framework._harness._file_access`); a framework release that moves either breaks the import with a message
saying so.

Licensed under the Apache License 2.0. Source:
[plimsoll on GitHub (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/agent-framework-plimsoll).
