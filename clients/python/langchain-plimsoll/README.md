# langchain-plimsoll

An agent that writes code has to run it somewhere, and "somewhere" is usually your machine or a hosted sandbox you
cannot inspect. This package runs a LangChain, LangGraph or Deep Agents agent's code in plimsoll, a sandbox service you
run yourself, and it has no fallback: if the sandbox is weaker than you asked for, nothing runs.

It has two parts:

- **`PlimsollCodeTool`**, a LangChain tool (`plimsoll_run_code`) that runs each call in a fresh sandbox. LangGraph's
  `ToolNode`, `create_agent` and any graph of your own call it like any other LangChain tool.
- **`PlimsollSandbox`**, a Deep Agents sandbox backend over one plimsoll session: one sandbox kept for the agent's whole
  run, so the files it writes and the shell's directory are there for its next command. Deep Agents gives the agent its
  `execute` tool and its file tools (`ls`, `read_file`, `write_file`, `edit_file`, `glob`, `grep`) on top of it
  ([Deep Agents sandboxes (EXTERNAL · official docs ↗)](https://docs.langchain.com/oss/python/deepagents/sandboxes)).

## Install

```sh
pip install langchain-plimsoll                 # the tool: needs only langchain-core
pip install 'langchain-plimsoll[deepagents]'   # and the Deep Agents backend
```

The tool needs only `langchain-core`. The example below builds its agent with `create_agent`, which is in `langchain`:
`pip install langchain` for it.

It needs a running `plimsolld`, the plimsoll daemon, reachable from the agent
([getting started (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/getting-started.md)).
The tool's default language is Python, which on docker needs a project image with `python3` in it
(`SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python:latest`): on the default image every Python call comes back
refused. Python 3.11 or later, as langchain-core requires.

## Use the tool

```python
from langchain.agents import create_agent
from langchain_plimsoll import Client, CodeExecutor, PlimsollCodeTool

executor = CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN))
agent = create_agent(model, tools=[PlimsollCodeTool(executor)])
```

The agent passes the tool code (Python or JavaScript) and optional input files, and gets back JSON saying whether the code
ran (yes, no with the reason, or unknown), the output, the exit code, whether anything was cut short or timed out, the
isolation tier the code ran behind, and the SHA-256 of the run's record.

## Use the Deep Agents backend

```python
from deepagents import create_deep_agent
from langchain_plimsoll import Client, PlimsollSandbox

with PlimsollSandbox.open(Client("https://plimsoll.internal:8746", token=TOKEN)) as backend:
    agent = create_deep_agent(model=model, backend=backend, system_prompt=f"Work in {backend.root}.")
    agent.invoke({"messages": [{"role": "user", "content": "Write and test a CSV parser."}]})
```

Deep Agents does not tell the model where to work; `backend.root` is the sandbox's work directory (`/work` on docker),
which is where the agent's files belong. Leaving the `with` block closes the session, and the sandbox and its files are
gone.

What the backend needs and does:

- **Python 3 in the sandbox.** Deep Agents' file tools are small `python3` scripts it runs through `execute`. `open`
  refuses a daemon that does not state Python before any sandbox is made; on docker that is the `plimsoll/sandbox-python`
  image (`SANDBOX_DOCKER_PROJECT_IMAGE`).
- **Searches that never answer "no matches" by mistake.** Deep Agents' `grep` sends GNU grep options with its errors
  discarded. plimsoll's docker images are Alpine Linux, whose `grep` is BusyBox's and has neither option, so every such
  search would come back empty. When the sandbox's `grep` is not GNU grep, the backend sends each search through Deep
  Agents' own `python3` search instead, which reports its errors. It skips hidden files, as Python's glob does.
- **A refusal stops the run.** If plimsoll refuses a command (the daemon is at capacity, the session has ended, the tier
  is too low), or a command may have run without an answer to show for it, the backend raises. It never hands the model a
  refusal dressed as command output, because Deep Agents reads that output as data: its `ls` reads text it cannot parse
  as an empty directory. A command that runs and fails is a normal result with its exit code.
- **A thread resumed on another worker keeps its sandbox.** Open the backend with a checkpoint store and a key, and
  attach to it from the worker that resumes the thread:

  ```python
  from plimsoll_client import MemoryCheckpointStore  # for tests: use storage only your app can write

  key = f"{user_id}/{thread_id}"  # from identities your app verified, never from model or user text
  backend = PlimsollSandbox.open(Client(url, token, daemon_name="prod"), checkpoint_store=store, checkpoint_key=key)
  # On the worker that resumes the thread:
  backend = PlimsollSandbox.attach(Client(url, token, daemon_name="prod"), key, store=store)
  ```

  The second worker gets the same sandbox and its files, and the first is refused from then on. A store is an object
  with `load` and an atomic `compare_and_set`; every call passes through it, so two workers never send at once, and a
  worker that died mid-command leaves a record the next one takes over from (if that command ran with its answer lost,
  the next one's first command may not repeat it). A missing key raises `LookupError`, never a new sandbox. The daemon
  needs callers with tokens: open development mode refuses the takeover, and anyone holding the token and a session's run
  records can take it over. The rules:
  [carrying a session on from another worker (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#carrying-a-session-on-from-another-worker).
  When the session ends (the daemon's lifetime or idle limit), every later call raises; the backend never opens a fresh
  sandbox in its place, since the agent would take it for the one holding its files.
- **Every command has a budget.** A command with no timeout gets the backend's default (120 s); `timeout=0` gets the
  daemon's longest; a command past its budget answers exit 124 with what it printed. A process left in the background is
  stopped when its command ends.

## Retries

LangGraph and LangChain retry nothing unless you ask: retries are off by default in both. You turn them on with a
`RetryPolicy` on a graph node (or on every node, with `set_node_defaults`), or with `ToolRetryMiddleware` on an agent.
Once on, both frameworks' default rules retry a plimsoll error, including one after which the code may already have run,
so a retry can run it a second time: a file appended to twice, a request sent twice. `retry_on` is the rule to give them
instead. It retries only a refusal plimsoll marked as having run nothing, and only when another try may pass: the daemon
was at capacity, or could not be reached before anything was sent. Every other error is left to stop the run.

```python
from langchain.agents.middleware import ToolRetryMiddleware
from langgraph.types import RetryPolicy
from langchain_plimsoll import retry_on

# A graph node that calls plimsoll
builder.add_node("run", node, retry_policy=RetryPolicy(retry_on=retry_on))

# A Deep Agents agent: its execute and file tools
agent = create_deep_agent(model=model, backend=backend, middleware=[ToolRetryMiddleware(retry_on=retry_on)])
```

- **Where it matters.** The Deep Agents backend raises on a refusal (above), and so do `Client` and `CodeExecutor`
  called from a node of your own: that is where a retry rule meets plimsoll. `PlimsollCodeTool` never raises for a
  refusal or a lost answer; it answers with them as its JSON (`ran` false or `"unknown"`), so no retry rule sees them.
- **Which refusals.** Every plimsoll error says whether anything ran: a refusal raised before any code was handed to the
  sandbox carries a reason, and an error without one may have followed execution
  ([what comes back, and what it means (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/run-results.md)).
  `retry_on` says yes to the reasons `capacity` (the daemon was full or over a rate limit and turned the run away) and
  `environment` (the daemon or its token check could not be reached before anything was sent, or a session's sandbox
  could not be read back before the call). It says no to the others, since the same daemon answers them the same way:
  `request`, `permission`, `protocol`, `unsupported` and `isolation`. One `environment` cause, an image outside your
  software rule, fails the same way each time; a retry of it costs the policy's few attempts and runs nothing.
- **Only plimsoll's errors.** It says no to every exception that is not plimsoll's (every plimsoll error is a
  `plimsoll_client.PlimsollError`). For a node that also calls a service whose errors you want retried, decide both in
  one rule: `RetryPolicy(retry_on=lambda e: retry_on(e) if isinstance(e, PlimsollError) else your_rule(e))`. A second
  `RetryPolicy` on the same node does not do this: LangGraph uses the first policy whose rule says yes, so a later policy
  with LangGraph's default rule would still retry plimsoll's errors.

## What it does, and what it refuses to do

- **No fallback.** Both parts require the `kernel` isolation tier by default (gVisor, a user-space kernel, or a virtual
  machine). Against a daemon that states less, they refuse before any code is sent. Lowering the floor is a choice you
  make in code: `CodeExecutor(client, minimum_isolation="container")`, `PlimsollSandbox.open(client,
  minimum_isolation="container")`.
- **A checked record of every run.** Each answer carries a run record, the daemon's statement of what was sent, what came
  back and where it ran, and the client recomputes its digests before handing the result on.
- **One web API, if you grant one, for the tool.** `CodeExecutor(client, grant_profile="lights", api_description=...)`,
  with a profile the operator configured on the daemon and the description `plimsoll-specgen` wrote for it, lets the
  tool's code call that profile's routes, and nothing else, through plimsoll's broker, which adds the API's key outside
  the sandbox. JavaScript works on every provider that gives a project run a grant; Python too on docker and openshell,
  through `import plimsoll_host`. The tool reads the daemon's answer when it is built, offers only the languages that
  can call the API there, and tells the model the routes; the model never names a profile. The code can do whatever an
  allowed route permits and read whatever it returns
  ([capability grants (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/capability-grants.md#from-an-agent-kits-code-tool)).
  The Deep Agents backend's calls take no grant.
- **Tested against LangChain's own suites.** The tool passes LangChain's standard tool tests (`langchain-tests`). The
  backend passes LangChain's standard sandbox tests on a real plimsoll session, except seven cases where
  langchain-tests 1.2.0 and deepagents 0.7.38 disagree with each other (six about what `glob` returns, one about writing
  over an existing file); they fail the same way for any backend built on Deep Agents' `BaseSandbox`.

## Tracing

If you turn on LangSmith tracing, LangChain sends each tool call's inputs and outputs, which here are the model's code
and what it printed, to LangSmith. That is LangChain's switch, not this package's; LangSmith's `hide_inputs` and
`hide_outputs` settings turn it off
([LangSmith tracing (EXTERNAL · official docs ↗)](https://docs.langchain.com/langsmith/mask-inputs-outputs)).

`PlimsollCodeTool` adds two things of its own, and neither carries the code or its output:

- **One ID in both logs.** Each call sends the LangChain run ID of the tool call (the ID LangSmith shows for that run) as
  the run's `trace_id`, which the daemon writes on the run's audit line and does nothing else with. To find what the
  daemon did for a traced tool call, search its log for the run's ID. The daemon accepts 1 to 64 characters of letters,
  digits and `.`, `_`, `:` and `-`; LangChain's IDs are UUIDs, which fit. An ID you set yourself (`run_id` in the
  config) that does not fit is not sent at all, never cut short, since a shortened ID would match nothing.
- **Labels on the tool call's run.** When the call is traced, the tool adds metadata to its run: `plimsoll_record_sha256`
  (the run record's digest, which the client checked), `plimsoll_isolation` (the tier the code ran behind) and
  `plimsoll_isolation_qualification` (the sentence a provider states beside its tier, when it states one),
  `plimsoll_dispatched` (`yes`, `no` or `unknown`: whether the run reached the provider, or an error left that open),
  `plimsoll_refused` (the reason, when it did not) and `plimsoll_outcome` (how the run ended: `completed`,
  `setup_failed`, `timed_out`, `protocol_error` or `runner_failed`). Each value is checked against the values plimsoll
  can state and left out if it does not match, so nothing the code printed can reach these fields. In LangSmith you can
  then filter for runs that were refused, ran below a tier, or may have run without an answer. With tracing off the tool
  adds nothing, and it imports no part of LangSmith that is not already loaded.

## What it is not

- **Not a hosted service.** You run `plimsolld` on your own machine or cluster, with a provider you pick: docker under
  gVisor, an E2B or Docker Cloud microVM, a Kubernetes agent-sandbox pod, and others
  ([isolation tiers (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/isolation-tiers.md)).
  The Deep Agents backend needs a provider with sessions: docker, E2B or OpenShell.
- **Not attestation.** A reported tier is the daemon's configuration and provider evidence plus a startup check, not
  hardware proof.

## Versions

This package's version moves with plimsoll's releases, and each version requires the `plimsoll-client` release of the same
number, which holds the code (`plimsoll_client.langchain` and `plimsoll_client.deepagents`). `Client`, `CodeExecutor`,
`PlimsollCodeTool` and `PlimsollSandbox` here are plimsoll-client's own classes, gathered so an agent imports from one
place. It is tested with, and installs with, exactly langchain-core 1.8.0, and its `deepagents` extra with exactly
deepagents 0.7.38: pip installs those versions beside it and refuses others, and each new release of either is tested
before its pin moves.

Licensed under the Apache License 2.0. Source:
[plimsoll on GitHub (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/langchain-plimsoll).
