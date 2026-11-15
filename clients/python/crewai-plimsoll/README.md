# crewai-plimsoll

A CrewAI agent that writes and runs code needs a sandbox, and CrewAI no longer brings one. Its Code Interpreter tool
was removed after CVE-2026-2275: in CERT/CC's words, "The CrewAI CodeInterpreter tool falls back to SandboxPython when
it cannot reach Docker", which let an attacker who could steer the agent through a prompt injection run code outside the
intended Docker isolation
([CERT/CC VU#221883 (EXTERNAL · advisory ↗)](https://www.kb.cert.org/vuls/id/221883)). CrewAI's documentation now says
"Use a dedicated sandbox service"
([CrewAI docs (EXTERNAL · official docs ↗)](https://docs.crewai.com/en/tools/ai-ml/codeinterpretertool)).

This package is a CrewAI tool that runs an agent's code in plimsoll, a sandbox service you run yourself, and it has no
fallback: if the sandbox is weaker than you asked for, nothing runs.

## Install

```sh
pip install crewai-plimsoll
```

It needs a running `plimsolld`, the plimsoll daemon, reachable from the crew
([getting started (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/getting-started.md)).
CrewAI itself supports Python 3.10 to 3.13.

## Use

```python
from crewai import Agent
from crewai_plimsoll import Client, CodeExecutor, PlimsollCodeTool

executor = CodeExecutor(Client("https://plimsoll.internal:8746", token=TOKEN))
agent = Agent(
    role="Analyst",
    goal="Answer with numbers you computed",
    backstory="You check your arithmetic by running it.",
    tools=[PlimsollCodeTool(executor)],
)
```

The tool is named `plimsoll_run_code`. The agent passes it code (Python or JavaScript) and optional input files, and gets
back whether the code ran (yes, no with the reason, or unknown), the output, the exit code, whether anything was cut short
or timed out, the isolation tier the code ran behind, and the SHA-256 of the run's record.

## What it does, and what it refuses to do

- **Every call runs in a fresh sandbox.** Nothing a call writes or starts is there for the next one.
- **No fallback.** `CodeExecutor` requires the `kernel` isolation tier by default (gVisor, a user-space kernel, or a
  virtual machine). Against a daemon that states less, it refuses before any code is sent, and the refusal says nothing
  ran. Lowering the floor is a choice you make in code: `CodeExecutor(client, minimum_isolation="container")`.
- **A checked record of every run.** Each answer carries a run record, the daemon's statement of what was sent, what came
  back and where it ran, and the client recomputes its digests before handing the result to the crew.
- **CrewAI's tool cache never answers for it.** A cached answer would carry no checked record, so the tool makes the cache
  miss for its name. A cache handler of your own that overrides `read` is not covered: keep `cache=False` for such a
  crew.

## What it is not

- **Not a hosted service.** You run `plimsolld` on your own machine or cluster, with a provider you pick: docker under
  gVisor, an E2B or Docker Cloud microVM, a Kubernetes agent-sandbox pod, and others
  ([isolation tiers (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/blob/main/docs/isolation-tiers.md)).
- **Not attestation.** A reported tier is the daemon's configuration and provider evidence plus a startup check, not
  hardware proof.

## Versions

This package's version moves with plimsoll's releases, and each version requires the `plimsoll-client` release of the same
number, which holds the tool's code (`plimsoll_client.crewai`). `Client`, `CodeExecutor` and `PlimsollCodeTool` here are
plimsoll-client's own classes, gathered so a crew imports from one place.

Licensed under the Apache License 2.0. Source:
[plimsoll on GitHub (EXTERNAL · source repo ↗)](https://github.com/plimsollmark/plimsoll/tree/main/clients/python/crewai-plimsoll).
