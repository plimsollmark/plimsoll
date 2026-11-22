"""PydanticAI + plimsoll: kill the worker, keep the sandbox.

A PydanticAI agent triages a web server's log in a plimsoll sandbox, and the process running it is killed while its
command runs. A second process carries the same run on, in the same sandbox, and plimsoll answers the question
PydanticAI's own crash recovery leaves open: did the call that was in flight run? In six lines:

1. Worker A writes triage.py into the sandbox and runs it with plimsoll's shell tool.
2. The supervisor kills worker A with SIGKILL 1.5 s into that command, the way a crashed machine looks from outside.
3. Worker B continues the run from StepPersistence's last snapshot. Its ledger marks the tool call "started" with no
   end, which PydanticAI's own guide says to treat as unknown: "the side effect may or may not have happened".
4. PydanticAI sends the call that was in flight again. Worker B takes the sandbox over across that call, plimsoll hands
   it the daemon's record of the lost call (no answer: canceled after 1.5 s), does not send the repeat, and tells the
   model what the record says.
5. The model reads by_route.json, which the cut command wrote before the kill, and PydanticAI accepts its typed answer
   only after a check against that file.
6. One chain of checked run records, the lost call's included, covers both workers, and the daemon's own count when
   the sandbox closes matches it.

What it is not: proof that a command runs at most once. plimsoll's client refuses only an exact repeat sent as the
first call after the takeover. Here PydanticAI's frontier resume makes the repeat that first call. If anything else is
sent first (another command, or any file tool, which sends calls of its own before its read or write), the lost
command can be sent again, and run a second time, with nothing said.

Words used here:

  Worker       one process of the application that runs the agent. Supervisor: this program's main process, which
               starts the two workers and decides which one owns the conversation.
  plimsoll     a sandbox service you run yourself (plimsolld, the daemon) for code an AI wrote. A session is one of
               its sandboxes kept open for many calls; its files stay from one call to the next.
  Run record   the daemon's statement of each call: digests (SHA-256) of what was sent and what came back, where it
               ran, and when. The records of a session form a chain: each names the one before. The client checks
               each record as it arrives.
  Lost call    a call whose answer never reached the worker that sent it. Its record says whether the daemon
               answered it: a result digest when the daemon answered (which does not show that the command ran to
               its end), or an unanswered code when the call ended without an answer (which does not show that the
               command began). Either way its output is lost.
  Takeover     plimsoll's session reattach: another worker of the same caller attaches the session, the daemon
               raises its ownership generation (a number a call must carry; a call with an older one is refused
               before it runs), and the first worker's later calls are refused.
  Checkpoint   the session's fingerprint, ownership generation, call count and last record digest, which the client
  store        keeps in a store the application supplies (_conversation_lease.py, beside this file). Before each
               call the stored record is marked pending with the call's request digest, after it ready. A worker
               that dies mid-call leaves it pending; the next worker's attach names that call, and the daemon takes
               the session over across it and returns its record.
  Lease        the application's note of which worker may use the conversation. In a real application it is a job
               queue's visibility timeout or a lease with an expiry; here the supervisor rewrites a small file.
  StepPersistence  a PydanticAI Harness capability that saves the run's message history at each settled tool step
               (complete snapshot) and, with capture_frontier=True, just before a tool runs (frontier snapshot),
               plus a ledger of each tool call's started, completed or failed, so another process can continue the
               run with continue_run. Resuming a frontier snapshot executes the pending call: the same call, with
               the same tool call ID.
  Workspace ref  PydanticAI's saved name for the workspace, on every model response, so continuing the message
               history continues in the same sandbox. plimsoll's is plimsoll/<the session's public fingerprint>,
               never the session ID.
  ToolFailed   PydanticAI's way for a tool to report a failure the model sees and adapts to, with no retry
               instructions and no cost to the tool's retry budget.

Install:  pip install pydantic-ai-plimsoll pydantic-ai-harness
          Published with plimsoll 0.28.0, after the other adapters; if pip cannot find it yet, from a
          checkout of the repository: pip install ./clients/python ./clients/python/pydantic-ai-plimsoll pydantic-ai-harness
          _conversation_lease.py, in the same directory of the repository, must sit beside this file. Python
          3.11 or later, POSIX only (signals and file locks).
Daemon:   a plimsolld with sessions on, the Python project image, and a token (a takeover is refused in open
          development mode). From a checkout, after `make docker-images` (docs/getting-started.md has every step):
              export PLIMSOLL_TOKEN=$(openssl rand -hex 16)   # 32 characters, the daemon's minimum
              SANDBOX_PROVIDER=docker SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python \\
              SANDBOX_MAX_SESSIONS=4 SANDBOX_RATE_PER_MIN=120 PLIMSOLL_ADDR=127.0.0.1:8746 go run ./cmd/plimsolld
          SANDBOX_RATE_PER_MIN=120 because one run makes about 25 calls in a few seconds and the daemon allows 30 a
          minute per caller by default: a second run in the same minute would be refused as over capacity.
Run:      in a shell with the same PLIMSOLL_TOKEN exported:
              PLIMSOLL_URL=http://127.0.0.1:8746 python pydantic_ai_crash.py             # the crash
              PLIMSOLL_URL=http://127.0.0.1:8746 python pydantic_ai_crash.py --freeze    # the returning worker
          The workspace refuses anything weaker than the kernel tier (Docker under gVisor). Plain Docker is the
          container tier: for your own code on your own machine only, add PLIMSOLL_MIN_ISOLATION=container.
          A run takes about 40 s: worker B waits up to 30 s for worker A's pending call to settle before it
          takes the sandbox over (the kit's bound; another worker may still be running that call).
Network:  the model is a scripted stand-in (PydanticAI's FunctionModel), so nothing here calls a model service, and
          PydanticAI sends no traces unless you configure Logfire or another OpenTelemetry exporter: the program
          reaches nothing but the daemon. --model <a PydanticAI model name> runs both workers on a real model
          instead, at that provider's prices; that path is not tested here.

What a crash run prints (docker under runc, so the container tier; the figures are the planted ones, the call
count and digests this run's):

    supervisor : ticket-42 (user ana) goes to worker A
    worker A   : put access.log (600 lines) in a plimsoll sandbox, container tier
    worker A   : the model wrote triage.py and is running it: python3 triage.py
    supervisor : killed worker A (SIGKILL) 1.5 s into that command, the way a crashed machine looks from outside
    supervisor : ticket-42 now belongs to worker B
    worker B   : StepPersistence's ledger: plimsoll_shell (call-1) is 'started' with no end; in its README's words,
                 "the side effect may or may not have happened"
    worker B   : the checkpoint store holds call 11 as pending (request ...), worker A's call that never settled;
                 the kit gives it up to 30 s to settle, then takes the sandbox over across it
    worker B   : PydanticAI resumes the call that was in flight (call-1): python3 triage.py
    worker B   : took the sandbox over (ref plimsoll/..., ownership generation 2) across that call; plimsoll's record
                 of it, call 11: the call ended without an answer (canceled), after 1.5 s
    worker B   : plimsoll did not send call-1 again, and told the model: "plimsoll: this exact command was already
                 sent once in this sandbox, and the call ended without an answer after 1.5 s: the request for it was
                 called off. Whether the command began, and how much of its work it did, is not known, and any
                 output it gave is lost. It was not run again. Look at the sandbox's files before you decide to run
                 it again."
    worker B   : the model read by_route.json, which the cut command had written
    worker B   : first answer refused by the output check: by_route.json says /checkout has error_rate 0.31 (57
                 errors in 184 requests, the first at 12:04), not error_rate 0.5; answer with the file's figures
    worker B   : typed answer: Incident(route='/checkout', first_bad_minute='12:04', errors=57, requests=184,
                 error_rate=0.31, evidence='by_route.json')
    worker B   : runs.log in the sandbox has 1 line: triage.py began once in this sandbox
    worker B   : closed the sandbox: the daemon counts 24 calls, the last record ...
    receipt    : one session, 24 calls: 1 to 10 by worker A; 11 the lost call (no answer: canceled, after 1.5 s; its
                 record reached worker B at the takeover); 12 to 24 by worker B; the daemon's own count at close
                 (24, last ...) matches

How to read it. plimsoll's record says the call ended without an answer: the daemon dispatched it once, and the
worker that sent it went away, and the request was canceled with it. The record does not say whether the command
began; the sandbox's files do. triage.py's first act is a line in runs.log and its second is by_route.json, and its
4 s pause comes after both, standing for a long job, so that the kill lands while it runs. runs.log has one line, and
worker B's repeat was refused with nothing sent, so the script began once, in worker A, and the by_route.json the
model read is that run's. The answer is checked against that file by PydanticAI's output validator, which reads it
through the run's workspace; the scripted model answers wrong once, on purpose, to show the check.

The kill can land at two other moments, and plimsoll tells them apart (the sentences are the kit's, from its code
and its tests, not printed by this run):

- Before the request reached the sandbox: the daemon is still at the stored checkpoint, so the takeover finds no
  lost call, the repeat is sent and runs once, in worker B, and the model gets its output.
- After the sandbox answered, with the answer lost on the way back: the record carries a result digest, and the model
  is told "The sandbox answered the call after ... s, but the answer is lost, so whether the command ran to its end,
  and whether it succeeded, is not known. It was not run again."

The returning worker (--freeze). Worker A stops itself with SIGSTOP between two calls, after triage.py ran and its
output came back; the supervisor moves the lease; worker B takes the sandbox over with no call lost and answers. Then
the supervisor wakes worker A, whose model asks to write report.md. A's client marks the stored record pending before
sending, the lease store refuses the write, and nothing is sent. Its run ends with PlimsollWorkspaceGoneError
(reason "store"). The run ends:

    supervisor : waking worker A
    worker A   : tried to write report.md: refused, nothing was sent (ticket-42 belongs to worker B)
    worker B   : report.md is not in the sandbox; closing it
    worker B   : closed the sandbox: the daemon counts 25 calls, the last record ...
    receipt    : one session, 25 calls: 1 to 11 by worker A, 12 to 25 by worker B; call 12 names call 11; the
                 daemon's own count at close (25, last ...) matches

Who refuses the returning worker: its own client, because the application's store says no. Without such a store the
kit takes the session back for a returning worker, by design, and that worker carries on from its stale history.
Behind the store, the daemon refuses a call that carries an old ownership generation before it runs. PydanticAI's
ConversationStore refuses a stale save of the message history (ConversationConflict); the generation is the same
kind of fence, on the sandbox.

What the application must protect: the caller token (with a checkpoint or the record files, it is enough to take the
session over); the checkpoint store (whoever can write it decides which worker gets the sandbox); and the step store,
which holds the message history, the workspace ref included (history a client sends you must go through PydanticAI's
sanitize_messages, which strips refs).

Limits, plainly:

- The refusal covers one case: the same call, sent as the first call after the takeover. With StepPersistence's
  default snapshot (the last complete one) the model is asked again from before the command, and if it runs anything
  else first, the lost command can run a second time. No file tool is covered at all.
- What plimsoll knows about the lost call is what its record says: whether the daemon answered it, and the two times
  the daemon put on the call. Not how the command exited, and not its output. That docker stopped the command where
  it was is measured on docker only, so the sentence the model gets does not claim it.
- The kill is a 1.5 s timer. On a slow machine it could land before the request reaches the sandbox; the run then
  shows the first of the two other moments above, and its receipt names no lost call.
- Two plain processes and a supervisor, not Temporal, DBOS or Prefect: the kit refuses durable execution today,
  since no engine's own test runs against it.
- Sessions exist on docker (with a project image), E2B and OpenShell. A takeover needs an authenticated caller and the
  client's daemon_name equal to the capability's daemon. It does not survive a daemon restart, recover a lost call's
  output, extend the session's lifetime (30 minutes by default) or move a session between daemons.
- PydanticAI's Coder and Shell do not work on this workspace; commands go through plimsoll_shell (BusyBox sh).
- The tier is the daemon's configuration and provider evidence plus a startup check, not attestation.

Why nothing is signed. The evidence is two logs of records each worker's client checked as they arrived
(records-A.jsonl, records-B.jsonl, written by JsonLinesRecordSink) and the daemon's count at close; the supervisor
checks they form one chain. Nothing is signed: plimsoll's signing harness (plimsoll-attest) is Go only, and a client
with a signing recorder cannot take a session over, since it cannot resume a chain it did not sign from the first
call. Whoever can edit the files can edit them.

Checked:  clients/python/pydantic_ai_crash_docker_test.go runs this file in both modes against a real docker daemon
          and holds it to the lines above, in order; frameworks/pydantic_ai/test_crash_chain.py holds the chain
          check to good and bad record logs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import signal
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, Field
from pydantic_ai import Agent, ModelRetry, RunContext
from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.messages import ModelMessage, ModelRequest, ModelResponse, RetryPromptPart, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.workspaces import Workspace
from pydantic_ai_harness import FileSystem, StepPersistence
from pydantic_ai_harness.step_persistence import FileStepStore, continue_run

from plimsoll_client import Client
from plimsoll_client.pydantic_ai import CAPACITY_RETRY_SECONDS, JsonLinesRecordSink, PlimsollWorkspace, PlimsollWorkspaceGoneError

import _conversation_lease as lease

URL = os.environ.get("PLIMSOLL_URL", "http://127.0.0.1:8746")
TOKEN = os.environ.get("PLIMSOLL_TOKEN")
FLOOR = os.environ.get("PLIMSOLL_MIN_ISOLATION", "kernel")

# How long after worker A's command starts the supervisor kills worker A. The command's script pauses 4 s after
# writing its file, standing for a long job, so the kill lands while it runs.
KILL_AFTER_SECONDS = 1.5


def say(who: str, text: str) -> None:
    print(f"{who:<11}: {text}", flush=True)


# ---- the job ----


@dataclass(frozen=True)
class Job:
    """The conversation, as the application verified it: never from model or user text."""

    user: str
    ticket: str

    @property
    def key(self) -> str:
        return f"{self.user}/{self.ticket}"


JOB = Job(user="ana", ticket="ticket-42")


class Incident(BaseModel):
    route: str  # the route whose errors rose
    first_bad_minute: str = Field(pattern=r"^\d\d:\d\d$")  # the minute of its first 5xx, HH:MM
    errors: int = Field(ge=0)  # its 5xx answers in the log
    requests: int = Field(gt=0)  # its requests in the log
    error_rate: float = Field(ge=0, le=1)  # errors / requests, to two places
    evidence: str  # the sandbox file the figures come from


def access_log(seed: int = 42) -> str:
    """Ten minutes of a web server's log, 12:00 to 12:09, 600 requests over four routes. /checkout has 184 of them,
    and 57 answer 503, every one from 12:04 on; every other answer is 200. Fixed by the seed, so every run triages
    the same log and the answer is 57 of 184, 0.31, first at 12:04."""
    rnd = random.Random(seed)
    routes = ["/checkout"] * 184 + ["/"] * 140 + ["/search"] * 140 + ["/login"] * 136
    rnd.shuffle(routes)
    late = [i for i, route in enumerate(routes) if route == "/checkout" and i // 60 >= 4]
    # The first /checkout request of 12:04 fails, so the first bad minute is 12:04, and 56 more after it.
    failing = {late[0], *rnd.sample(late[1:], 56)}
    lines = [f"2026-11-19T12:{i // 60:02d}:{i % 60:02d} GET {route} {503 if i in failing else 200}" for i, route in enumerate(routes)]
    return "\n".join(lines) + "\n"


TASK = (
    "access.log in your sandbox is a web server's log, one request a line: time, method, route, status. Find which "
    "route started failing, and when. Write triage.py, which first appends one line to runs.log, then counts each "
    "route's requests and 5xx answers into by_route.json (for each route: requests, errors, first_bad as HH:MM, "
    "error_rate rounded to two places), prints how many routes it found, and then sleeps 4 seconds (it stands for a "
    "long job). Run it with plimsoll_shell, read by_route.json, and answer with the figures it holds."
)

# The script the scripted model writes. Its first act is a line in runs.log, so the sandbox itself counts how many
# times it began; its pause comes after by_route.json is written.
TRIAGE = '''import collections, json, time
open("runs.log", "a").write("triage.py began\\n")
by = collections.defaultdict(lambda: {"requests": 0, "errors": 0, "first_bad": None})
for line in open("access.log"):
    when, _, route, status = line.split()
    r = by[route]
    r["requests"] += 1
    if status.startswith("5"):
        r["errors"] += 1
        r["first_bad"] = r["first_bad"] or when[11:16]
out = {k: dict(v, error_rate=round(v["errors"] / v["requests"], 2)) for k, v in by.items()}
json.dump(out, open("by_route.json", "w"), indent=1, sort_keys=True)
print(len(out), "routes")
time.sleep(4)
'''

SHELL_COMMAND = "python3 triage.py"


# ---- the scripted model: it decides from the history, so either worker gives the same next step ----


def _read_file_json(content: str) -> Any:
    """by_route.json from FileSystem's read_file answer: a header line, then each line numbered and tabbed."""
    body = content.split("\n", 1)[1] if "\n" in content else ""
    return json.loads("\n".join(re.sub(r"^\s*\d+\t", "", line) for line in body.splitlines()))


class Scripted:
    """A stand-in for a model, so nothing here calls a model service: write triage.py, run it, read by_route.json,
    answer once with a wrong error_rate (to show the output check), then answer with the figures the check names.
    Worker A in freeze mode, once woken, first tries to write report.md."""

    def __init__(self, *, woken_write: bool = False) -> None:
        self.woken_write = woken_write

    def __call__(self, messages: List[ModelMessage], info: AgentInfo) -> ModelResponse:
        answer = info.output_tools[0].name
        plan: List[Tuple[str, Dict[str, Any]]] = [
            ("write_file", {"path": "triage.py", "content": TRIAGE}),
            ("plimsoll_shell", {"command": SHELL_COMMAND}),
        ]
        if self.woken_write:
            plan.append(("write_file", {"path": "report.md", "content": "# ticket-42, from worker A\n"}))
        plan.append(("read_file", {"path": "by_route.json"}))
        turn = sum(isinstance(m, ModelResponse) for m in messages)
        if turn < len(plan):
            name, args = plan[turn]
            return ModelResponse(parts=[ToolCallPart(name, args, tool_call_id=f"call-{turn}")])
        parts = [p for m in messages if isinstance(m, ModelRequest) for p in m.parts]
        read = [p for p in parts if isinstance(p, ToolReturnPart) and p.tool_name == "read_file"]
        checked = [p for p in parts if getattr(p, "tool_name", "") == answer and isinstance(p, (RetryPromptPart, ToolReturnPart))]
        if not read:
            return ModelResponse(parts=[TextPart("by_route.json was never read")])
        r = _read_file_json(str(read[-1].content))["/checkout"]
        figures = {"route": "/checkout", "first_bad_minute": r["first_bad"], "errors": r["errors"],
                   "requests": r["requests"], "error_rate": 0.5, "evidence": "by_route.json"}
        if checked:
            m = re.search(r"error_rate ([0-9.]+)", str(checked[-1].content))
            if m:
                figures["error_rate"] = float(m.group(1))
        return ModelResponse(parts=[ToolCallPart(answer, figures, tool_call_id=f"call-{turn}")])


# ---- the narrator: what each worker prints, and, in freeze mode, worker A's stop ----


@dataclass
class Narrator(AbstractCapability[Any]):
    who: str
    mode: str
    freeze_at: int = 0
    requests: int = field(default=0, init=False)
    announced: bool = field(default=False, init=False)
    refused: bool = field(default=False, init=False)  # this worker's shell command was refused as a repeat
    ran_shell: bool = field(default=False, init=False)  # this worker's shell command ran and answered
    executed: Set[str] = field(default_factory=set, init=False)  # the tool call IDs this worker executed

    async def before_tool_execute(self, ctx: RunContext[Any], *, call: Any, tool_def: Any, args: Any) -> Any:
        self.executed.add(call.tool_call_id)
        if call.tool_name == "plimsoll_shell":
            command = args.get("command", "") if isinstance(args, dict) else ""
            if self.who == "worker A":
                say(self.who, f"the model wrote triage.py and is running it: {command or SHELL_COMMAND}")
            else:
                say(self.who, f"PydanticAI resumes the call that was in flight ({call.tool_call_id}): {command or SHELL_COMMAND}")
        return args

    async def before_model_request(self, ctx: RunContext[Any], request_context: Any) -> Any:
        self.requests += 1
        messages = list(getattr(request_context, "messages", None) or ctx.messages)
        last = messages[-1] if messages else None
        if self.who == "worker B" and not self.announced:
            self._announce(ctx)
        for part in getattr(last, "parts", []) if isinstance(last, ModelRequest) else []:
            name = getattr(part, "tool_name", "")
            outcome = getattr(part, "outcome", "")
            if name == "plimsoll_shell" and part.tool_call_id not in self.executed:
                continue  # a return in the history this worker continued from, not one of its own calls
            if name == "plimsoll_shell" and outcome == "failed":
                self.refused = True
                say(self.who, f"plimsoll did not send {part.tool_call_id} again, and told the model: \"{part.content}\"")
            elif name == "plimsoll_shell" and outcome == "success":
                self.ran_shell = True
                if self.freeze_at:
                    say(self.who, f"triage.py ran, and its answer came back: {str(part.content).splitlines()[-1]!r}")
            elif name == "read_file" and outcome == "success":
                say(self.who, f"the model read by_route.json, which {self._writer(ctx)}")
            elif isinstance(part, RetryPromptPart) or outcome == "retried":
                say(self.who, f"first answer refused by the output check: {str(part.content).splitlines()[0]}")
        if self.freeze_at and self.requests == self.freeze_at:
            say(self.who, "stops here, between two calls (SIGSTOP to itself, standing for a machine that stalls)")
            os.kill(os.getpid(), signal.SIGSTOP)
        return request_context

    def _writer(self, ctx: RunContext[Any]) -> str:
        """Which run of triage.py wrote the by_route.json the model read, from what this worker saw."""
        if self.who == "worker B" and self.ran_shell:
            return "triage.py wrote when worker B ran it"
        if self.refused:
            lost = getattr(getattr(getattr(ctx.workspace, "backend", None), "session", None), "lost_call", None)
            if lost is not None and lost.unanswered:
                return "the cut command had written"
            return "worker A's command wrote before its answer was lost"
        return "worker A's triage.py wrote"

    def _announce(self, ctx: RunContext[Any]) -> None:
        backend = getattr(ctx.workspace, "backend", None)
        session = getattr(backend, "session", None)
        if session is None:
            return
        self.announced = True
        ref = backend.ref
        try:
            generation = session.checkpoint().generation
        except Exception:  # the takeover's generation is narration only
            generation = "?"
        lost = session.lost_call
        if lost is None:
            say(self.who, f"took the sandbox over (ref {ref.id[:22]}..., ownership generation {generation}); no call was lost")
            return
        took = (lost.ended_unix_ms - lost.started_unix_ms) / 1000
        kind = f"the call ended without an answer ({lost.unanswered})" if lost.unanswered else "the sandbox answered it, and the answer is lost"
        say(self.who, f"took the sandbox over (ref {ref.id[:22]}..., ownership generation {generation}) across that call; "
                      f"plimsoll's record of it, call {lost.sequence}: {kind}, after {took:.1f} s")


# ---- one worker ----


def build(worker: str, state: str, mode: str, model_name: Optional[str]) -> Tuple[PlimsollWorkspace, FileStepStore, Agent]:
    workspace = PlimsollWorkspace(
        client=Client(URL, TOKEN, daemon_name="plimsoll"),
        minimum_isolation=FLOOR,
        checkpoint_store=lease.LeaseCheckpointStore(os.path.join(state, "checkpoints"), worker),
        checkpoint_key=lambda ctx: ctx.deps.key,
        owner=lambda ctx: ctx.deps.user,
        record_sink=JsonLinesRecordSink(os.path.join(state, f"records-{worker}.jsonl")),
    )
    steps = FileStepStore(os.path.join(state, "steps"))
    model: Any = model_name or FunctionModel(Scripted(woken_write=worker == "A" and mode == "freeze"))
    narrator = Narrator(who=f"worker {worker}", mode=mode, freeze_at=3 if worker == "A" and mode == "freeze" else 0)
    agent = Agent(model, deps_type=Job, output_type=Incident,
                  capabilities=[workspace, FileSystem(), StepPersistence(store=steps, capture_frontier=True), narrator])

    @agent.output_validator
    async def matches_the_file(ctx: RunContext[Job], out: Incident) -> Incident:
        # PydanticAI accepts the answer only when it matches the file in the sandbox, read through the run's workspace.
        try:
            data = json.loads(await ctx.workspace.read_text(out.evidence))
        except FileNotFoundError:
            raise ModelRetry(f"{out.evidence} is not in the sandbox")
        worst = max(data, key=lambda route: data[route]["error_rate"])
        want = data.get(out.route)
        if out.route != worst or not isinstance(want, dict):
            raise ModelRetry(f"{out.evidence} says the route whose errors rose is {worst}, not {out.route}")
        if (out.first_bad_minute, out.errors, out.requests, out.error_rate) != (want["first_bad"], want["errors"], want["requests"], want["error_rate"]):
            raise ModelRetry(
                f"{out.evidence} says {out.route} has error_rate {want['error_rate']} ({want['errors']} errors in "
                f"{want['requests']} requests, the first at {want['first_bad']}), not error_rate {out.error_rate}; "
                "answer with the file's figures"
            )
        return out

    return workspace, steps, agent


async def worker_a(state: str, mode: str, model_name: Optional[str]) -> int:
    who = "worker A"
    workspace, _, agent = build("A", state, mode, model_name)
    backend = workspace.backend(key=JOB.key, owner=JOB.user)
    log = access_log()
    await Workspace(backend).write_text("access.log", log)
    say(who, f"put access.log ({log.count(chr(10))} lines) in a plimsoll sandbox, {backend.session.isolation} tier")
    try:
        result = await agent.run(TASK, deps=JOB, workspace=backend, conversation_id=JOB.ticket)
    except PlimsollWorkspaceGoneError as e:
        if mode == "freeze" and e.reason == "store":
            say(who, f"tried to write report.md: refused, nothing was sent ({JOB.ticket} belongs to worker "
                     f"{lease.holder(os.path.join(state, 'checkpoints'), JOB.key)})")
            return 0
        say(who, f"run ended: {type(e).__name__}(reason={e.reason!r}): {e}")
        return 1
    say(who, f"finished on its own: {result.output!r}")
    return 1  # in crash mode it is killed first; in freeze mode its write is refused


async def worker_b(state: str, mode: str, model_name: Optional[str]) -> int:
    who = "worker B"
    workspace, steps, agent = build("B", state, mode, model_name)
    run_a = (await steps.list_runs(conversation_id=JOB.ticket))[-1].run_id
    unresolved = await steps.list_unresolved_tool_effects(run_id=run_a)
    for u in unresolved:
        say(who, f"StepPersistence's ledger: {u.tool_name} ({u.tool_call_id}) is {u.status!r} with no end; in its "
                 "README's words, \"the side effect may or may not have happened\"")
    if not unresolved:
        say(who, "StepPersistence's ledger: every tool call of worker A's run has an end")
    stored = lease.LeaseCheckpointStore(os.path.join(state, "checkpoints"), "B").load(JOB.key)
    if stored is not None and stored.state == "pending":
        say(who, f"the checkpoint store holds call {stored.checkpoint.calls + 1} as pending (request "
                 f"{stored.request_sha256[:12]}...), worker A's call that never settled; the kit gives it up to "
                 f"{CAPACITY_RETRY_SECONDS:.0f} s to settle, then takes the sandbox over across it")
    elif stored is not None:
        say(who, f"the checkpoint store is ready after call {stored.checkpoint.calls}: no call was in flight")
    # The frontier snapshot ends in the model response that asked for the call in flight, so the run resumes by
    # executing it: the same call, with the same tool call ID. No workspace argument: the history's ref names it.
    history = await continue_run(steps, run_id=run_a, include_interrupted=True)
    result = await agent.run(message_history=history, deps=JOB, conversation_id=JOB.ticket)
    say(who, f"typed answer: {result.output!r}")
    ref = result.workspace.ref
    backend = workspace.backend(ref, owner=JOB.user, key=JOB.key)
    began = (await Workspace(backend).read_text("runs.log")).count("\n")
    times = {1: "once", 2: "twice"}.get(began, f"{began} times")
    say(who, f"runs.log in the sandbox has {began} line{'s' if began != 1 else ''}: triage.py began {times} in this sandbox")
    if mode == "freeze":
        say(who, "ready: waiting for the supervisor")
        if sys.stdin.readline().strip() != "close":
            return 1
        if await Workspace(backend).exists("report.md"):
            say(who, "report.md is in the sandbox: worker A wrote it")
            return 1
        say(who, "report.md is not in the sandbox; closing it")
    lost = backend.session.lost_call  # the record the takeover returned, which the client checked, or None
    summary = workspace.destroy(ref)  # the client compares the daemon's count and last digest with its own chain
    assert summary is not None
    with open(os.path.join(state, "close.json"), "w", encoding="utf-8") as f:
        json.dump({"session": summary.session, "calls": summary.calls, "last_record_sha256": summary.last_record_sha256,
                   "end": summary.end, "lost_call_sha256": lost.sha256 if lost is not None else ""}, f)
    say(who, f"closed the sandbox: the daemon counts {summary.calls} calls, the last record {summary.last_record_sha256[:12]}")
    return 0


# ---- the chain check ----


def read_records(path: str) -> List[Dict[str, Any]]:
    """The records a JsonLinesRecordSink wrote at ``path``, in order; none when there is no file."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line)["record"] for line in f if line.strip()]


def check_chain(a: Sequence[Dict[str, Any]], b: Sequence[Dict[str, Any]], close: Dict[str, Any]) -> Tuple[List[str], str]:
    """Checks the two workers' record logs against each other and against ``close``, worker B's close statement:
    one session; sequences 1 to N with no gap; each record naming the one before; every record of worker A before
    every record of worker B; when worker B's takeover returned the record of a lost call (``lost_call_sha256``),
    that record first in worker B's log, and no other record without an answer; N and the last digest equal to the
    daemon's own count at close. Returns the problems found and, when there are none, the receipt line."""
    problems: List[str] = []
    chain = list(a) + list(b)
    if not a or not b:
        return [f"a worker's log is empty (worker A {len(a)} records, worker B {len(b)})"], ""
    sessions = {r["session"] for r in chain}
    if len(sessions) != 1:
        problems.append(f"the logs name {len(sessions)} sessions, not one")
    elif close.get("session") not in sessions:
        problems.append("the close statement names another session")
    if max(r["sequence"] for r in a) > min(r["sequence"] for r in b):
        problems.append("a record of worker B comes before worker A's last")
    sequences = [r["sequence"] for r in chain]
    if sequences != list(range(1, len(chain) + 1)):
        problems.append(f"the sequences are not 1 to {len(chain)} in order: {sequences}")
    if chain[0]["previous_sha256"] != "":
        problems.append("the first record names a record before it")
    for before, after in zip(chain, chain[1:]):
        if after["previous_sha256"] != before["sha256"]:
            problems.append(f"call {after['sequence']} does not name call {before['sequence']}")
    lost = close.get("lost_call_sha256", "")
    if lost and b[0]["sha256"] != lost:
        problems.append("worker B's log does not start with the record of the call lost before its takeover")
    stray = [r for r in chain if r.get("unanswered") and not (lost and r["sha256"] == lost)]
    if stray:
        problems.append(f"{len(stray)} record(s) state no answer and are not the lost call's: call "
                        + ", ".join(str(r["sequence"]) for r in stray))
    if (close.get("calls"), close.get("last_record_sha256")) != (len(chain), chain[-1]["sha256"]):
        problems.append(f"the daemon's own count at close ({close.get('calls')}, last {str(close.get('last_record_sha256'))[:12]}) "
                        f"is not the logs' ({len(chain)}, last {chain[-1]['sha256'][:12]})")
    if problems:
        return problems, ""
    n, na = len(chain), len(a)
    matched = f"the daemon's own count at close ({close['calls']}, last {close['last_record_sha256'][:12]}) matches"
    if not lost:
        return [], f"one session, {n} calls: 1 to {na} by worker A, {na + 1} to {n} by worker B; call {na + 1} names call {na}; {matched}"
    r = b[0]
    took = (r["ended_unix_ms"] - r["started_unix_ms"]) / 1000
    how = f"no answer: {r['unanswered']}, after {took:.1f} s" if r["unanswered"] else f"the sandbox answered after {took:.1f} s, and the answer is lost"
    return [], (f"one session, {n} calls: 1 to {na} by worker A; {na + 1} the lost call ({how}; its record reached worker B "
                f"at the takeover); {na + 2} to {n} by worker B; {matched}")


# ---- the supervisor ----


class Worker:
    """One worker process, its output forwarded line by line, with an event per marker it may print."""

    def __init__(self, name: str, state: str, mode: str, model_name: Optional[str], markers: Sequence[str]) -> None:
        argv = [sys.executable, os.path.abspath(__file__), "--worker", name, "--state", state]
        argv += ["--freeze"] if mode == "freeze" else []
        argv += ["--model", model_name] if model_name else []
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, env=dict(os.environ, PYTHONUNBUFFERED="1", PYDANTIC_AI_NO_BANNER="1"))
        self.seen = {m: threading.Event() for m in markers}
        self.done = threading.Event()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            print(line, end="", flush=True)
            for marker, event in self.seen.items():
                if marker in line:
                    event.set()
        self.done.set()

    def wait_for(self, marker: str, timeout: float = 300) -> bool:
        """True once the worker printed ``marker``; False if it ended first or the time ran out."""
        event = self.seen[marker]
        while not event.wait(0.1):
            timeout -= 0.1
            if self.done.is_set() or timeout <= 0:
                return event.is_set()
        return True

    def waitpid(self, flags: int = 0) -> int:
        _, status = os.waitpid(self.proc.pid, flags)
        if not os.WIFSTOPPED(status):
            self.proc.returncode = os.waitstatus_to_exitcode(status)
            self.done.wait(10)
        return status


def supervise(mode: str, model_name: Optional[str]) -> int:
    who = "supervisor"
    state = tempfile.mkdtemp(prefix="pydantic-ai-crash-")  # mode 0700: only this user
    checkpoints = os.path.join(state, "checkpoints")
    lease.claim(checkpoints, JOB.key, "A")
    say(who, f"{JOB.ticket} (user {JOB.user}) goes to worker A")
    a = Worker("A", state, mode, model_name, ["is running it", "stops here"])
    if mode == "crash":
        if not a.wait_for("is running it"):
            say(who, "worker A never started its command")
            return 1
        threading.Event().wait(KILL_AFTER_SECONDS)
        os.kill(a.proc.pid, signal.SIGKILL)
        status = a.waitpid()
        if not (os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL):
            say(who, f"worker A ended before the kill (exit {os.waitstatus_to_exitcode(status)})")
            return 1
        say(who, f"killed worker A (SIGKILL) {KILL_AFTER_SECONDS} s into that command, the way a crashed machine looks from outside")
    else:
        status = a.waitpid(os.WUNTRACED)
        if not os.WIFSTOPPED(status):
            say(who, f"worker A ended instead of stopping (exit {os.waitstatus_to_exitcode(status)})")
            return 1
        # waitpid sees the stop as soon as it happens, while A's own "stops here" line, written just before, reaches
        # this output through the pump thread: wait for that line, so the two are printed in the order they happened.
        a.wait_for("stops here", timeout=10)
        say(who, "worker A stopped answering")
    lease.claim(checkpoints, JOB.key, "B")
    say(who, f"{JOB.ticket} now belongs to worker B")
    b = Worker("B", state, mode, model_name, ["ready: waiting"])
    if mode == "freeze":
        if not b.wait_for("ready: waiting"):
            say(who, "worker B never got ready")
            os.kill(a.proc.pid, signal.SIGKILL)
            a.waitpid()
            return 1
        say(who, "waking worker A")
        os.kill(a.proc.pid, signal.SIGCONT)
        status = a.waitpid()
        assert b.proc.stdin is not None
        b.proc.stdin.write("close\n")
        b.proc.stdin.flush()
        if os.waitstatus_to_exitcode(status) != 0:
            b.proc.wait(300)
            say(who, f"worker A exited {os.waitstatus_to_exitcode(status)} after waking")
            return 1
    if b.proc.wait(300) != 0:
        say(who, f"worker B exited {b.proc.returncode}")
        return 1
    b.done.wait(10)
    try:
        with open(os.path.join(state, "close.json"), encoding="utf-8") as f:
            close = json.load(f)
    except FileNotFoundError:
        say(who, "worker B left no close statement")
        return 1
    problems, receipt = check_chain(read_records(os.path.join(state, "records-A.jsonl")),
                                    read_records(os.path.join(state, "records-B.jsonl")), close)
    for p in problems:
        say("receipt", f"FAILED: {p}")
    if problems:
        return 1
    say("receipt", receipt)
    say("evidence", f"{state}: records-A.jsonl, records-B.jsonl (one checked run record a line), close.json")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Kill a PydanticAI worker mid-command; a second worker keeps its plimsoll sandbox.")
    p.add_argument("--freeze", action="store_true", help="freeze worker A between calls and wake it after worker B took over")
    p.add_argument("--model", default=None, help="a PydanticAI model name for both workers (default: the scripted model)")
    p.add_argument("--worker", choices=["A", "B"], help=argparse.SUPPRESS)
    p.add_argument("--state", help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    mode = "freeze" if args.freeze else "crash"
    if args.worker is None:
        return supervise(mode, args.model)
    run = worker_a if args.worker == "A" else worker_b
    return asyncio.run(run(args.state, mode, args.model))


if __name__ == "__main__":
    sys.exit(main())
