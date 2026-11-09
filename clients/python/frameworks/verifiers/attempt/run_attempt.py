"""One configuration of the verifiers attempt: a task, a model, a harness and a runtime, run
through verifiers' own ``vf-eval``, and what it measured printed as JSON.

By default the model is scripted (``policies``): every number measures the harness, the
runtime and verifiers' machinery, never a model. Run from ``clients/python`` with the verifiers
environment ``make py-frameworks PY_FRAMEWORKS=verifiers`` builds, under the docker lock:

    flock ../../tmp/docker.lock ../../tmp/py-frameworks/verifiers/bin/python -m \\
        frameworks.verifiers.attempt.run_attempt --task plimsoll-sum --runtime plimsoll \\
        --serve ../../tmp/plimsolld --out ../../tmp/vf-attempt/sum-runc

``--serve`` starts a plimsolld of its own on loopback (docker provider, sessions on, the
operator image ``agent.Dockerfile`` builds, a fresh bearer token) and stops it after; ``--url`` uses a
running one instead. ``--runtime docker`` runs verifiers' own docker runtime for the
baseline. ``--task uuid-ctf`` needs prime-envs' ``reasoning/uuid_ctf`` package directory
given with ``--taskset-path`` (its evaluator-side code runs in this process, as verifiers
runs every taskset). For the plimsoll runtime every call's record goes to a log, which is
rechecked with ``check_record_log`` and summarized.

``--model`` with ``--upstream-base`` and a key runs a real model instead, and spends: the
driver keeps the key, ``vf-eval`` talks to a relay on loopback (``model_relay``) with a token
made for the run, and the relay refuses further calls once the run's dollar budget
(``--cost-cap-usd``, at list prices with cached input at its cached price; never above
$0.96) is reached. The token budgets are a backstop, set by default so that they cannot cut
an attempt before the dollars would. ``--fake-upstream POLICY`` is the same run with a
scripted server on loopback as the upstream and a random canary as its key: nothing leaves
the machine, and the summary says ``dry_run``. After the run every file written (and each
``--scan-file``, such as the driver's own log) and both children's environments are checked
for the key; a hit fails the run.

Where the key comes from decides who can read it. ``--upstream-key-stdin`` reads one line from
a pipe (``your-secret-tool | ... --upstream-key-stdin``): the key is then in
no process's environment at all. ``--upstream-key-var`` reads a variable instead (what
a secrets wrapper provides); popping it afterwards does NOT remove it from
``/proc/<this pid>/environ``, which keeps the block the process started with, so this
process, ``flock`` and any wrapper above it keep the key readable to any process of the
same user, task code included. The children get explicit environments without it, and the
task package is pinned by hash; that narrows the exposure and does not close it.
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import glob
import hashlib
import json
import os
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Any, Dict, Iterator, List, Optional

from plimsoll_client.verifiers_runtime import IMPORT_PATH, check_record_log

from ..scripted_model import ScriptedModel
from .model_relay import ModelRelay, parse_upstream, scan_files, scan_tree
from .policies import POLICIES

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
CLIENT = os.path.dirname(os.path.dirname(FRAMEWORK))
IMAGE = "plimsoll-wip/verifiers-agent:dev"

# The variable vf-eval reads its key from: with a real model, the relay's token for this run,
# which opens the relay and nothing else.
RELAY_KEY_VAR = "PLIMSOLL_RELAY_KEY"
# A scripted upstream's stand-in for a reasoning model's thinking, so a dry run sends verifiers
# the kind of delta a reasoning model's stream carries.
FAKE_REASONING = "Thinking about the task."
# ...and the share of each prompt it reports as served from cache, as a caching API does.
FAKE_CACHED_SHARE = 0.5
# prime-envs' uuid_ctf package, file by file, as read before it was pinned (the same list as
# primeFiles in examples/verifiers/run.go; a test there holds the two equal). The environment
# handed to vf-eval keeps a key out of its process, but its task code still runs as this user,
# with this user's files, so with a real key on the machine only the reviewed code may run.
PINNED_TASK_FILES = {
    "README.md": "f1e2e0fff9a62c1a37982af7d337945e70bec13f3d943a88dd41237d5fd6be5a",
    "pyproject.toml": "b7adf8fdad4ca96a3e337d378a700ae49c55a77d84241929e8a8574a177e8591",
    "uuid_ctf/__init__.py": "f685dbc0245a548fe88e4c9ba613ee0acaf49d32bdc0540b6c3f6784a9736d1a",
    "uuid_ctf/taskset.py": "c288d09395a75534364abc62fec62592668f2b2674cb66efdd362cd2d667441b",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def serve(binary: str, out: str, docker_runtime: str, image: str, rate_per_min: int, pids: Optional[List[int]] = None) -> Iterator[tuple]:
    """A plimsolld on loopback with docker sessions and a fresh bearer token; yields its
    URL and the token once /readyz answers. ``pids``, if given, gets its process id."""
    port = _free_port()
    token = secrets.token_urlsafe(32)
    env = {
        "PLIMSOLL_TOKEN": token,
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", ""),
        "SANDBOX_PROVIDER": "docker",
        "SANDBOX_DOCKER_PROJECT_IMAGE": image,
        "SANDBOX_DOCKER_RUNTIME": docker_runtime,
        "SANDBOX_MAX_SESSIONS": "4",
        # One attempt makes 10 to 25 session calls; the default of 30 a minute per caller
        # stops an evaluation after about two attempts.
        "SANDBOX_RATE_PER_MIN": str(rate_per_min),
        "PLIMSOLL_ADDR": f"127.0.0.1:{port}",
    }
    if os.environ.get("DOCKER_HOST"):
        env["DOCKER_HOST"] = os.environ["DOCKER_HOST"]
    log = open(os.path.join(out, "plimsolld.log"), "wb")
    proc = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    if pids is not None:
        pids.append(proc.pid)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 300
        while True:
            if proc.poll() is not None:
                raise RuntimeError(f"plimsolld exited {proc.returncode}; see {log.name}")
            try:
                with urllib.request.urlopen(url + "/readyz", timeout=5) as r:
                    if r.status == 200:
                        break
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(f"plimsolld not ready after 300 s; see {log.name}")
            time.sleep(0.5)
        yield url, token
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()


def _toml(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    return json.dumps(value)  # a TOML basic string


# The variables vf-eval keeps from the caller's environment: where programs and the home
# directory are, the locale and temporary directory, and how to reach docker for the docker
# runtime's baseline.
_VF_EVAL_PASS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "DOCKER_HOST")


def write_config(path: str, tables: Dict[str, Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for table, fields in tables.items():
            f.write(f"[{table}]\n")
            for key, value in fields.items():
                f.write(f"{key} = {_toml(value)}\n")
            f.write("\n")


PHASES = ("boot", "setup", "agent", "finalize", "scoring")


def summarize_traces(run_dir: str) -> List[Dict[str, Any]]:
    """Per rollout, from verifiers' saved traces (one episode a line, its rollouts under
    ``traces``): the weighted reward and each reward, the stop condition and errors, each
    phase's seconds (boot is provisioning the runtime), the model's and the harness's share
    of the agent phase, model turns and tool results."""
    rows = []
    for path in sorted(glob.glob(os.path.join(run_dir, "**", "traces.jsonl"), recursive=True)):
        with open(path, encoding="utf-8") as f:
            episodes = [json.loads(line) for line in f if line.strip()]
        for episode in episodes:
            for t in episode.get("traces") or []:
                timing = t.get("timing") or {}
                phases = {}
                for name in PHASES:
                    span = timing.get(name) or {}
                    if span.get("start") and span.get("end"):
                        phases[name] = round(span["end"] - span["start"], 3)
                ends = [s["end"] for s in timing.values() if isinstance(s, dict) and s.get("end")]
                agent = timing.get("agent") or {}
                rewards = t.get("rewards") or {}
                weight = sum(r.get("weight", 1.0) for r in rewards.values())
                roles = [(n.get("message") or {}).get("role") for n in t.get("nodes") or []]
                usage = [c.get("usage") or {} for c in t.get("calls") or []]
                # verifiers' prompt_tokens leaves out what the API served from cache and keeps
                # that in cached_input_tokens; the API bills both.
                cached_in = sum(u.get("cached_input_tokens") or 0 for u in usage)
                billed_in = sum(u.get("prompt_tokens") or 0 for u in usage) + cached_in
                billed_out = sum(u.get("completion_tokens") or 0 for u in usage)
                rows.append(
                    {
                        "task_idx": ((t.get("task") or {}).get("data") or {}).get("idx"),
                        "trace_id": t.get("id"),
                        # What an API bills: every call's whole prompt, so a conversation
                        # is paid for again on each turn. verifiers' own count, which its
                        # max_total_tokens checks, counts each input token once.
                        "input_tokens": billed_in,
                        "cached_input_tokens": cached_in,
                        "output_tokens": billed_out,
                        "total_tokens": billed_in + billed_out,
                        "verifiers_new_tokens": t.get("num_total_tokens"),
                        "answer_first_role": answer_first_role(t),
                        "reward": round(sum(r["score"] * r.get("weight", 1.0) for r in rewards.values()) / weight, 6) if weight else None,
                        "rewards": {k: r.get("score") for k, r in rewards.items()},
                        "metrics": t.get("metrics"),
                        "stop_condition": t.get("stop_condition"),
                        "errors": [e.get("message", e) if isinstance(e, dict) else e for e in t.get("errors") or []],
                        "seconds": phases,
                        "total_s": round(max(ends) - timing["start"], 3) if ends and timing.get("start") else None,
                        "model_s": round((agent.get("model") or {}).get("duration", 0.0), 3),
                        "harness_s": round((agent.get("harness") or {}).get("duration", 0.0), 3),
                        "model_turns": len(t.get("calls") or []),
                        # "length" means the last answer was cut at the per-call output cap.
                        "last_finish_reason": ((t.get("calls") or [{}])[-1]).get("finish_reason"),
                        "tool_results": roles.count("tool"),
                        "runtime": (t.get("agent") or {}).get("runtime"),
                    }
                )
    return rows


def answer_first_role(trace: Dict[str, Any]) -> Optional[str]:
    """The role of the first message in a saved trace holding the task's expected answer
    ("assistant" or "tool" is the model working it out), or None. Reading a "system" or
    "user" here would mean the answer key reached the model."""
    expected = (((trace.get("task") or {}).get("data") or {}).get("result_uuid") or "").lower()
    if not expected:
        return None
    for node in trace.get("nodes") or []:
        message = node.get("message") or {}
        if expected in json.dumps(message, default=str).lower():
            return message.get("role")
    return None


def _refuse_walk_error(e: OSError) -> None:
    raise e


def check_task_files(root: str) -> None:
    """Requires root to be exactly the pinned task package, and refuses anything else.

    The root goes on PYTHONPATH ahead of the standard library, so beyond the bytes of each
    pinned file nothing else may sit under it that Python could import or load: a symlink
    (a linked directory named json would shadow the real module and be hashed as nothing), a
    __pycache__ directory or compiled file (a hash-based .pyc runs in place of the source it
    names), a file that is not a regular one (a FIFO would hang the read), or a directory
    that cannot be read."""
    found = {}
    for directory, subdirs, names in os.walk(root, onerror=_refuse_walk_error, followlinks=False):
        for name in [*subdirs, *names]:
            path = os.path.join(directory, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if name == "__pycache__" or name.endswith((".pyc", ".pyo")):
                raise RuntimeError(f"{root} is not the pinned task package: {rel} is compiled bytecode or its cache")
            if os.path.islink(path):
                raise RuntimeError(f"{root} is not the pinned task package: {rel} is a symbolic link")
        for name in names:
            path = os.path.join(directory, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if not stat.S_ISREG(os.lstat(path).st_mode):
                raise RuntimeError(f"{root} is not the pinned task package: {rel} is not a regular file")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    raise RuntimeError(f"{root} is not the pinned task package: {rel} is not a regular file")
                found[rel] = hashlib.sha256(f.read()).hexdigest()
    if found != PINNED_TASK_FILES:
        changed = sorted(k for k in set(found) | set(PINNED_TASK_FILES) if found.get(k) != PINNED_TASK_FILES.get(k))
        raise RuntimeError(f"{root} is not the pinned task package: {changed}")


def _private_pycache() -> str:
    path = tempfile.mkdtemp(prefix="plimsoll-pycache-")
    atexit.register(shutil.rmtree, path, True)
    return path


def eval_environment(token: str, taskset_paths: List[str]) -> Dict[str, str]:
    """All vf-eval gets. It imports the outside taskset's evaluator code into its own process,
    so it holds only what the run needs, never this shell's other variables (a key set for
    some other tool would otherwise be readable by that code)."""
    env = {name: os.environ[name] for name in _VF_EVAL_PASS if name in os.environ}
    env.update({
        "PYTHONPATH": os.pathsep.join([os.path.join(CLIENT, "src"), FRAMEWORK, *map(os.path.abspath, taskset_paths)]),
        "PYTHONDONTWRITEBYTECODE": "1",
        # Never read the taskset's own __pycache__ (check_task_files refuses one, this holds
        # if one appears later): compiled files are read only from this empty private directory.
        "PYTHONPYCACHEPREFIX": _private_pycache(),
        # Keeps the working directory off sys.path; PYTHONPATH itself must stay, it is how the
        # taskset is found, which is why this is not -I.
        "PYTHONSAFEPATH": "1",
        "PLIMSOLL_TOKEN": token,
    })
    return env


def expected_values(preset: str, tasks: int, taskset_paths: List[str]) -> Dict[str, List[str]]:
    """What the task hides from the model, read by a child of its own in vf-eval's environment:
    this process holds an API key, so the outside task's code never runs in it."""
    script = os.path.join(HERE, "expected_values.py")
    proc = subprocess.run(
        [sys.executable, "-B", script, "--difficulty", preset, "--num-samples", str(tasks)],
        env=eval_environment("", taskset_paths), capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"reading the task's expected values failed:\n{proc.stderr[-2000:]}")
    return json.loads(proc.stdout)


def block_holds(env: Dict[str, str], secret: str) -> bool:
    """Whether an environment block about to be handed to a child holds secret, in a name or a value."""
    return any(secret in k or secret in v for k, v in env.items())


def environment_holds(pid: int, secret: str) -> bool:
    """Whether a running process was started with secret in its environment. Popen returns
    after the exec, so this reads the child's own, not a copy of this process's."""
    with open(f"/proc/{pid}/environ", "rb") as f:
        return secret.encode("utf-8") in f.read()


def priced(rows: List[Dict[str, Any]], price_in: float, price_cached: float, price_out: float) -> None:
    """Adds each attempt's cost at list price, from its own token counts: cached input at the
    cached price, the rest of the input at the input price."""
    for row in rows:
        cached = row.get("cached_input_tokens") or 0
        spent = ((row.get("input_tokens") or 0) - cached) * price_in + cached * price_cached + (row.get("output_tokens") or 0) * price_out
        row["cost_usd"] = round(spent / 1e6, 6)


def relay_cost(totals: Dict[str, Any], price_in: float, price_cached: float, price_out: float) -> float:
    """The run's cost at list price from the relay's count; a call whose usage is unknown is
    counted at the output price, the dearest."""
    cached = totals["cached_prompt_tokens"]
    spent = (totals["prompt_tokens"] - cached) * price_in + cached * price_cached + (totals["completion_tokens"] + totals["charged_without_usage"]) * price_out
    return round(spent / 1e6, 6)


# The most the owner approved a real run to cost (2026-10-27, 2026-10-30).
MAX_COST_CAP_USD = 0.96


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--task", choices=sorted(POLICIES), required=True)
    p.add_argument("--policy", default="gold")
    p.add_argument("--runtime", choices=["plimsoll", "docker"], default="plimsoll")
    p.add_argument("--shipped-harness", action="store_true", help="verifiers' own bash harness instead of plimsoll-bash")
    p.add_argument("--serve", metavar="PLIMSOLLD", help="start this plimsolld for the run")
    p.add_argument("--docker-runtime", default="", help="the served daemon's SANDBOX_DOCKER_RUNTIME: '' (runc) or runsc")
    p.add_argument("--image", default=IMAGE, help="the served daemon's session image")
    p.add_argument("--rate-per-min", type=int, default=600, help="the served daemon's SANDBOX_RATE_PER_MIN (its default, 30, stops an evaluation after about two attempts)")
    p.add_argument("--url", help="a running plimsolld instead of --serve")
    p.add_argument("--floor", default=None, help="minimum_isolation (default: container under runc, kernel under runsc)")
    p.add_argument("--workdir", help="the runtime's work directory (a task's own wins)")
    p.add_argument("--rollouts", type=int, default=1)
    p.add_argument("--tasks", type=int, help="tasks to attempt (default 1, or 10 with --model)")
    p.add_argument("--concurrency", type=int, help="attempts at once (default 1, or 2 with --model)")
    p.add_argument("--preset", help="uuid-ctf's difficulty preset (default extra_easy, or easy with --model)")
    p.add_argument("--rollout-timeout", type=float, help="verifiers' agent phase timeout, seconds")
    p.add_argument("--eval-timeout", type=float, help="vf-eval's whole run, seconds (default 1800, or 3600 with --model)")
    real = p.add_argument_group("a real model (spends; see the module's docstring)")
    real.add_argument("--model", help="the model's id at the upstream; turns on the real-model mode")
    real.add_argument("--upstream-base", help="an OpenAI-compatible base URL, https unless it is this machine")
    real.add_argument("--upstream-key-var", help="the variable holding the API key, read once and popped; /proc/<pid>/environ still holds it (see the module's docstring)")
    real.add_argument("--upstream-key-stdin", action="store_true", help="read the API key as one line from stdin: it is then in no process's environment")
    real.add_argument("--scan-file", action="append", default=[], metavar="FILE", help="also scan this file for the key after the run, such as the driver's own redirected log")
    real.add_argument("--max-total-tokens", type=int, default=400000, help="verifiers' cap on one attempt's new tokens (each input token once, so far below what is billed)")
    real.add_argument("--run-token-budget", type=int, help="a backstop on the whole run's billed tokens (default: what the cost cap buys at the cheapest price, so the dollars always stop the run first)")
    real.add_argument("--attempt-token-budget", type=int, help="a backstop on one attempt's billed tokens (default: the same, so no attempt is cut before the dollar cap would cut it)")
    real.add_argument("--price-in", type=float, default=0.06, help="USD per million uncached input tokens, list price")
    real.add_argument("--price-cached", type=float, default=0.03, help="USD per million cached input tokens")
    real.add_argument("--price-out", type=float, default=0.24, help="USD per million output tokens, list price")
    real.add_argument("--cost-cap-usd", type=float, default=MAX_COST_CAP_USD, help=f"the relay's dollar budget for the run; refused above ${MAX_COST_CAP_USD}")
    real.add_argument("--fake-upstream", metavar="POLICY", help="a dry run: this policy on a scripted loopback server is the upstream, and the key is a random canary")
    p.add_argument("--vf-eval", help=argparse.SUPPRESS)  # a test's stand-in for verifiers' program
    p.add_argument("--taskset-path", action="append", default=[], help="a directory to import an outside taskset from")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    harness = "bash" if args.shipped_harness else "plimsoll-bash"
    if args.policy not in POLICIES[args.task]:
        p.error(f"no policy {args.policy!r} for {args.task}; have {sorted(POLICIES[args.task])}")
    use_real = args.model is not None or args.fake_upstream is not None
    real_run = args.model is not None and args.fake_upstream is None  # a live API, not a scripted upstream
    key = ""
    if use_real:
        if args.model is None:
            p.error("--fake-upstream rehearses a real run: give the --model it would use")
        if args.task != "uuid-ctf" or args.runtime != "plimsoll" or args.shipped_harness:
            p.error("a real model runs uuid-ctf through plimsoll-bash on the plimsoll runtime")
        if args.fake_upstream is not None and args.fake_upstream not in POLICIES[args.task]:
            p.error(f"no policy {args.fake_upstream!r} for {args.task}; have {sorted(POLICIES[args.task])}")
        if len(args.taskset_path) != 1:
            p.error("a real model needs the one --taskset-path of the pinned task package")
        try:
            check_task_files(args.taskset_path[0])
        except (OSError, RuntimeError) as e:
            p.error(str(e))
        if not 0 < args.cost_cap_usd <= MAX_COST_CAP_USD:
            p.error(f"the cost cap is ${args.cost_cap_usd}; it must be above 0 and at most ${MAX_COST_CAP_USD}, the approved spend")
        if min(args.price_in, args.price_cached) < 0 or args.price_out <= 0:
            p.error("the prices must be non-negative, with a positive output price")
        # The cheapest token is the cheapest price; the whole cap spent on those is the most
        # tokens the dollars allow, so a backstop at that never fires before the cap does.
        cheapest = min(args.price_in, args.price_cached, args.price_out)
        most_tokens = int(args.cost_cap_usd / cheapest * 1e6) + 1 if cheapest > 0 else 1 << 40
        if args.run_token_budget is None:
            args.run_token_budget = most_tokens
        if args.attempt_token_budget is None:
            args.attempt_token_budget = most_tokens
        if args.fake_upstream is None:
            if not args.upstream_base or bool(args.upstream_key_var) == args.upstream_key_stdin:
                p.error("--model needs --upstream-base and exactly one of --upstream-key-var and --upstream-key-stdin")
            try:
                parse_upstream(args.upstream_base)
            except ValueError as e:
                p.error(str(e))
            if args.upstream_key_stdin:
                key = sys.stdin.readline().strip()
            else:
                key = os.environ.get(args.upstream_key_var, "")
            if not key:
                p.error("the API key is empty: nothing on stdin" if args.upstream_key_stdin else f"{args.upstream_key_var} is not set")
        else:
            key = "canary-" + secrets.token_hex(24)
        if args.upstream_key_var:
            # Every child gets an environment written out by name. This drops the variable from
            # os.environ only: /proc/<pid>/environ keeps the block the process started with
            # (the module's docstring says what that leaves readable).
            os.environ.pop(args.upstream_key_var, None)
    preset = args.preset or ("easy" if use_real else "extra_easy")
    tasks = args.tasks or (10 if use_real else 1)
    concurrency = args.concurrency or (2 if use_real else 1)
    eval_timeout = args.eval_timeout or (3600 if use_real else 1800)
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    floor = args.floor or ("kernel" if args.docker_runtime == "runsc" else "container")
    record_log = os.path.join(out, "records.jsonl")
    children: List[int] = []
    with contextlib.ExitStack() as stack:
        url, token = args.url, os.environ.get("PLIMSOLL_TOKEN", "")
        if args.runtime == "plimsoll" and url is None:
            if not args.serve:
                p.error("--runtime plimsoll needs --serve or --url")
            url, token = stack.enter_context(serve(os.path.abspath(args.serve), out, args.docker_runtime, args.image, args.rate_per_min, children))
        relay: Optional[ModelRelay] = None
        model: Optional[ScriptedModel] = None
        client: Dict[str, Any]
        extra_env: Dict[str, str] = {}
        if use_real:
            hidden = expected_values(preset, tasks, args.taskset_path)
            upstream = args.upstream_base
            if args.fake_upstream is not None:
                model = stack.enter_context(ScriptedModel(POLICIES[args.task][args.fake_upstream], require_key=key, reasoning=FAKE_REASONING, cached_share=FAKE_CACHED_SHARE))
                upstream = model.base_url
            relay = stack.enter_context(
                ModelRelay(upstream_base=upstream, api_key=key, model=args.model, token_budget=args.run_token_budget,
                           attempt_budget=args.attempt_token_budget, usd_budget=args.cost_cap_usd,
                           price_in=args.price_in, price_cached=args.price_cached, price_out=args.price_out, log_path=os.path.join(out, "relay.jsonl"), hidden=hidden["answers"] + hidden["sources"], answers=hidden["answers"])
            )
            client = {"base_url": relay.base_url, "api_key_var": RELAY_KEY_VAR}
            extra_env[RELAY_KEY_VAR] = relay.local_token
        else:
            model = stack.enter_context(ScriptedModel(POLICIES[args.task][args.policy]))
            client = {"base_url": model.base_url, "api_key_var": "PLIMSOLL_SCRIPTED_MODEL_KEY"}
        taskset: Dict[str, Any] = {"id": args.task}
        if args.task == "uuid-ctf":
            taskset.update(difficulty=preset, num_samples=tasks)
        if args.runtime == "plimsoll":
            runtime: Dict[str, Any] = {
                "type": "custom",
                "import_path": IMPORT_PATH,
                "url": url,
                "minimum_isolation": floor,
                "record_log": record_log,
            }
        else:
            runtime = {"type": "docker"}
        if args.workdir:
            runtime["workdir"] = args.workdir
        tables: Dict[str, Dict[str, Any]] = {
            "client": client,
            "env.taskset": taskset,
            "env.agent.harness": {"id": harness},
            "env.agent.runtime": runtime,
        }
        if use_real:
            tables["env.agent"] = {"max_total_tokens": args.max_total_tokens}
        if args.rollout_timeout:
            tables["env.agent.timeout"] = {"rollout": args.rollout_timeout}
        config = os.path.join(out, "eval.toml")
        write_config(config, tables)
        vf_eval = args.vf_eval or os.path.join(os.path.dirname(sys.executable), "vf-eval")
        command = [vf_eval, "@", config, "-m", args.model or "scripted", "-n", str(tasks), "-r", str(args.rollouts), "-c", str(concurrency),
                   "--no-push", "--no-rich", "-o", os.path.join(out, "runs"), "--run.dir", "run"]
        env = {**eval_environment(token, args.taskset_path), **extra_env}
        started = time.monotonic()
        held_by: List[str] = []
        timed_out = False
        with open(os.path.join(out, "vf-eval.log"), "wb") as log:
            proc = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, cwd=out)
            if key:
                children.append(proc.pid)
                # vf-eval's environment is env, exactly: checked from the block it was handed,
                # the others from /proc. Reading /proc alone raced a child that had already
                # exited, whose environ reads empty, so a fast vf-eval holding the key passed
                # the check (seen under load, 2026-11-05).
                held_by = [str(pid) for pid in children if (pid == proc.pid and block_holds(env, key)) or environment_holds(pid, key)]
                if held_by:
                    # Stopped at once: the run must not go on with task code able to read it.
                    proc.kill()
            try:
                proc.wait(timeout=eval_timeout)
            except subprocess.TimeoutExpired:
                # The relay's log and the traces so far still stand, and the summary still
                # gets written, so a run that outlasts this is not lost.
                timed_out = True
                proc.kill()
                proc.wait()
        wall = round(time.monotonic() - started, 3)
        summary: Dict[str, Any] = {
            "task": args.task,
            "policy": None if real_run else args.policy,
            "key_source": ("stdin" if args.upstream_key_stdin else "env") if real_run else None,
            "harness": harness,
            "runtime": args.runtime,
            "docker_runtime": (args.docker_runtime or "runc") if args.runtime == "plimsoll" else None,
            "floor": floor if args.runtime == "plimsoll" else None,
            "rate_per_min": args.rate_per_min if args.serve and args.runtime == "plimsoll" else None,
            "vf_eval_exit": proc.returncode,
            "timed_out": timed_out,
            "wall_s": wall,
            "rollouts": summarize_traces(os.path.join(out, "runs")),
        }
        if not real_run:
            summary["model_requests"] = len(model.requests) if model is not None else 0
        ok = proc.returncode == 0 and not timed_out
        if relay is not None:
            priced(summary["rollouts"], args.price_in, args.price_cached, args.price_out)
            totals = relay.totals()
            for row in summary["rollouts"]:
                # An attempt the relay stopped ran out of budget, which says nothing about
                # the model; the page shows it apart from one that ended by itself.
                row["relay_refused"] = relay.refused_attempts.get(row.get("trace_id") or "")
            run_cost = relay_cost(totals, args.price_in, args.price_cached, args.price_out)
            trace_tokens = sum(r.get("total_tokens") or 0 for r in summary["rollouts"])
            leaked_roles = sorted({r["answer_first_role"] for r in summary["rollouts"] if r.get("answer_first_role") in ("system", "user")})
            summary["real_model"] = {
                "dry_run": args.fake_upstream is not None,
                "model": args.model,
                "upstream_host": "loopback" if args.fake_upstream is not None else parse_upstream(args.upstream_base)[1],
                "preset": preset,
                "tasks": tasks,
                "concurrency": concurrency,
                "max_total_tokens_per_attempt": args.max_total_tokens,
                "run_token_budget": args.run_token_budget,
                "attempt_token_budget": args.attempt_token_budget,
                "max_call_output_tokens": relay.max_call_output_tokens,
                "price_in_per_million": args.price_in,
                "price_cached_per_million": args.price_cached,
                "price_out_per_million": args.price_out,
                "cost_cap_usd": args.cost_cap_usd,
                "relay": totals,
                "cost_usd": run_cost,
                # The attempts' costs, each from its own trace, against the relay's: equal
                # to the rounding of six decimals each, or something is uncounted.
                "costs_match_relay": abs(sum(r["cost_usd"] for r in summary["rollouts"]) - run_cost) < 1e-6 * (len(summary["rollouts"]) + 1),
                "trace_total_tokens": trace_tokens,
                "traces_match_relay": trace_tokens == totals["total_tokens"] and totals["charged_without_usage"] == 0,
                "answer_key": {"refused_requests": totals["answer_key_seen"], "first_role_system_or_user": leaked_roles},
            }
            ok = ok and not totals["answer_key_seen"] and not leaked_roles and not held_by
    if args.runtime == "plimsoll" and os.path.exists(record_log):
        try:
            summary["record_log"] = check_record_log(record_log, minimum_isolation=floor)
        except Exception as e:  # reported, not raised: the run's other numbers still stand
            summary["record_log"] = {"error": f"{type(e).__name__}: {e}"}
    if key:
        # A hit fails the run and names the file, never the key. A dry run's canary goes
        # through this same check, which is what proves the check on a run that spends nothing.
        hits = scan_tree(out, key)
        others = scan_files(args.scan_file, key)
        summary["key_check"] = {"files_with_the_key": hits, "other_files_with_the_key": others, "other_files_checked": len(args.scan_file),
                                "children_with_the_key": held_by, "children_checked": len(children)}
        ok = ok and not hits and not others
        if hits or others or held_by:
            print(f"THE KEY LEAKED: rotate it. Files: {hits + others}; child processes: {held_by}", file=sys.stderr)
    print(json.dumps(summary, indent=2))
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    if key and (scan_tree(out, key) or scan_files(args.scan_file, key)):
        print("THE KEY LEAKED into the summary: rotate it", file=sys.stderr)
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
