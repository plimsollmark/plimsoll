# smolagents-plimsoll

A smolagents `CodeAgent` acts by writing Python, and its default executor runs that Python in your own process. This
package runs it in plimsoll instead, a sandbox service you run yourself, possibly somewhere else, and it has no fallback:
if the sandbox is weaker than you asked for, nothing runs.

**`PlimsollExecutor`** is the agent's Python executor over one plimsoll session: each step of the agent is one cell in
the session's Python interpreter, so the variables, functions and imports one step defines are there in the next.
**`code_agent`** builds the `CodeAgent` around it, so that a failure of the sandbox stops the run.

## Install

```sh
pip install smolagents-plimsoll
```

It needs a running `plimsolld`, the plimsoll daemon, reachable from the agent
([getting started (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/getting-started.md)).
The executor needs a provider with sessions: docker (with a project image that has Python, such as `plimsoll/sandbox-python`), E2B or OpenShell today
([which providers (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#which-providers)).
Sessions are off until the daemon is started with `SANDBOX_MAX_SESSIONS` set (for example `SANDBOX_MAX_SESSIONS=4`);
without it building the executor raises plimsoll's `UnsupportedError`, saying the daemon has no sessions.
On a daemon whose image has no Python, building the executor raises plimsoll's refusal and closes the session.
Python 3.10 or later, as smolagents requires.

## Use

```python
from smolagents import AgentLogger, LogLevel
from smolagents_plimsoll import Client, PlimsollExecutor, code_agent

executor = PlimsollExecutor([], AgentLogger(LogLevel.INFO),
                            client=Client("https://plimsoll.internal:8746", token=TOKEN),
                            minimum_isolation="kernel")
with code_agent(executor, tools=[], model=model) as agent:   # closes the session after
    print(agent.run("What is the 20th Fibonacci number?"))
```

`model` is any smolagents model, such as `InferenceClientModel` or `LiteLLMModel`. The first argument,
`additional_imports`, must be empty (nothing is installed, below), and the second is a smolagents logger, as for
smolagents' own executors. Building the executor opens the session and checks its tier; leaving the `with` block, or
`agent.cleanup()`, closes it, and the sandbox and its files are gone.

## What the executor needs and does

- **The floor is yours to set.** `minimum_isolation` (`process`, `container`, `kernel` or `vm`) has no default. When the
  session opens, its tier is checked against the floor before any of the agent's code is sent; below it, the session is
  closed and `InsufficientIsolationError` is raised.
- **Build the agent with `code_agent`.** smolagents turns every error an executor raises into an error its model is
  shown, and goes on to the next step. So the executor keeps the first error after which the run cannot go on as
  `executor.fatal_error` and sends nothing more, and the agent `code_agent` builds stops at the end of that step: its
  `run` raises that error, plimsoll's own, in place of smolagents' "Agent interrupted.". Those errors are: a cell
  plimsoll refused before anything ran; a cell that may have run without an answer to show for it (any error of the
  session's call that is not a refusal, plimsoll's or not); a cell on a session that has ended (its lifetime ran out, or
  the daemon closed it); and a step that finds the sandbox's interpreter restarted, so the variables and tools of the
  earlier steps are gone. With `stream=True` the steps are handed on as they come and the error is raised in place of
  the final answer. A plain `CodeAgent(executor=executor)` sends nothing more either, but goes on asking its model until
  `max_steps` and then returns the model's own answer, made up after the sandbox failed; check `executor.fatal_error`
  after such a run.
- **The code's own errors are the model's to fix.** An exception the agent's code raises comes back to the model as
  smolagents' `AgentError`, with what the step printed and the traceback, as smolagents' own remote executors report it.
- **Each step has a time budget,** `timeout`, 120 seconds unless you set it; the daemon cuts a longer budget to its own
  limit for a call (120 seconds by default on docker). A step past its budget is stopped and the sandbox ends its
  interpreter: the model is told, and the next step finds the interpreter restarted, which ends the run.
- **A step that prints past the sandbox's output limit** (64 KiB by default on docker) loses its result, which comes at
  the end of its output: the model is shown that the output was cut, and the run goes on.
- **One session for the run.** `lifetime` (seconds, 3600 unless you set it) may only shorten the daemon's own session
  lifetime (30 minutes by default), and a run that outlasts it ends with `SessionEndedError` at its next step. A session
  with no call for the daemon's idle timeout (5 minutes by default), while the model takes its time, is suspended: on
  docker its interpreter is kept, but on E2B and OpenShell a suspend ends it, so the next step finds it restarted and the
  run ends. A session
  is one trust domain: everything a step does is there for every later step, so use one executor for one agent and one
  user ([who may share a session (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#who-may-share-a-session)).
  `owner` names that user for a daemon's per-owner cap. The executor needs a `plimsoll_client.Client`; an `AsyncClient`
  raises `TypeError`, since smolagents calls its executor synchronously.

## Limits, stated plainly

- **No pickle, ever.** smolagents' `allow_pickle=True` lets a final answer travel from the sandbox as a pickle, and
  unpickling it in your process runs code the sandbox chose there: code in the sandbox could then run code outside it,
  which is what the sandbox is there to prevent. `PlimsollExecutor(..., allow_pickle=True)` raises `ValueError` before
  a session is opened, and so does setting the attribute later; a final answer that arrives as a pickle anyway is
  refused unread. Variables (`agent.run(..., additional_args=...)`) travel as JSON-safe values only, as smolagents' own
  executors send them without pickle.
- **The final answer is plain data.** The executor sends its own definition of the `final_answer` tool, which carries
  what smolagents' own carries (JSON values, tuples, sets, bytes, dates and times, decimals, paths, and dataclasses, as
  a dictionary), with no NumPy or Pillow import, because `plimsoll/sandbox-python` has no Pillow. A final answer that
  is an image, a NumPy array or a NumPy number (`numpy.int64(3)`, say) is refused with an error the model is shown, so
  it can answer with a plain value (`value.tolist()`, `value.item()`). One that claims to be an image, an array, or any
  kind the executor's own definition does not write is refused in your process too, with the kind named: smolagents'
  reader runs in your process and learns new kinds with new releases, so it is handed only the kinds listed above and
  Pillow never opens bytes from the sandbox. For the same reason a dictionary with a key named `__type__` is carried
  only when that key holds one of those kinds' own marks.
- **Nothing is installed.** smolagents asks its executor to install every package a tool's code imports from outside
  Python's standard library, and this executor refuses any install: a plimsoll sandbox has no network by default, and
  packages belong in the image its operator runs. So a tool whose code imports `numpy` makes `agent.run` raise
  `ValueError` when the run starts, before anything is sent, even though `plimsoll/sandbox-python` has NumPy and SciPy.
  The agent's own steps can import whatever the image has.
- **Tools run in the sandbox, and cannot reach the network.** smolagents sends each tool's code, its class attributes
  included, into the sandbox's interpreter, and the tool runs there, in the step's cell; so anything written into a
  tool's code is visible to the agent's code. A cell carries no grant, the permission that lets a call reach an API
  ([capability grants (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/capability-grants.md)),
  so no tool can reach the network from a step, and unlike the other kits' code tools this executor takes no grant. A
  web search tool does not work here.
- **The record of a step can be forged by the agent's own code, and forges only its own answer.** The executor reads
  each step's value, output and error from a line its own helper in the sandbox's interpreter prints, marked with a
  random value fresh for each step. The agent's code runs in that same interpreter and can read the mark, so it can
  forge what the executor reads back as its step's result; it can forge nothing but the agent's own answer. The run
  record of each cell is plimsoll's: the client checks it and its place in the session's chain.
- **Text from the sandbox arrives printable.** smolagents' console logger prints what a step printed, a step's value and
  the final answer on your terminal as they are (it escapes its error messages, not these), so code in the sandbox could
  send your terminal escape sequences: a new window title, a cleared screen, or, on a terminal that allows it, the
  clipboard. The executor writes each control character but tab, newline and carriage return as a visible escape
  (`\x1b` for the escape character) in what a step printed, its error, a value or final answer that is text, and a final
  answer that is a path. Text inside a list, a dictionary or another value is handed over as it came, since smolagents
  prints such a value as its `repr`, which escapes it; escape it yourself before you print it.
- **Not tested:** smolagents' managed agents (an agent another agent calls as a tool, which smolagents sends to the
  executor with the tools); any smolagents release but 1.26.0.

## What reaches your application

smolagents asks an executor only for each step's output, value or error, and the final answer. What plimsoll states
about each cell, none of it from what the cell's code printed, is in `executor.records`: a `PlimsollCellRecord` per cell
the client checked, with the tier the cell ran at (`isolation`), the sentence the provider states beside the tier
(`isolation_qualification`, empty when it states none), how the cell ended (`outcome`: `completed`, or `timed_out` when
its budget ended it), the SHA-256 of its run record (`record_sha256`), the record itself (`record`) and the checked
result (`result`).

```python
for cell in executor.records:
    print(cell.isolation, cell.outcome, cell.record_sha256)
assert executor.records[-1].record_sha256 == executor.session.last_record_sha256
```

The records are in the order the cells ran: first the executor's own setup cell, then one for each call smolagents made
(the variables and the tools' definitions at the start of each run, then each step). So they are the session's chain of
records: each names the one before it, and the last is the end of the chain the client checked. A cell that answered is
kept whatever its code did (an error, a lost result, a timeout). A call that raised adds none; when its error carries
the checked record of a call that may have run, that record is `executor.fatal_error.record`.

## What it is not

- **Not a hosted service.** You run `plimsolld` on your own machine or cluster, with a provider you pick
  ([isolation tiers (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/isolation-tiers.md)).
- **Not attestation.** A reported tier is the daemon's configuration and provider evidence plus a startup check, not
  hardware proof.

## Versions

This package's version moves with plimsoll's releases, and each version requires the `plimsoll-client` release of the same
number, which holds the code (`plimsoll_client.smolagents`). `Client`, `PlimsollExecutor`, `PlimsollCellRecord` and
`code_agent` here are plimsoll-client's own names, gathered so an agent imports from one place. It is tested with, and
installs with, exactly smolagents 1.26.0 (released 2026-05-29): pip installs that version beside it and refuses another.
The executor copies smolagents' final-answer protocol to send its own `final_answer` and reaches into parts of smolagents
that are not its public interface, so its tests pin the parts that protocol lives in, and a smolagents release that changes
any of them fails them instead of breaking quietly; each new release is tested before the pin moves.

Licensed under the Apache License 2.0. Source:
[plimsoll on GitHub (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/smolagents-plimsoll).
