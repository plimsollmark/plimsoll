"""One configuration of the verifiers attempt: a task, a scripted policy, a harness and a
runtime, run through verifiers' own ``vf-eval``, and what it measured printed as JSON.

The model is scripted (``policies``): every number here measures the harness, the runtime
and verifiers' machinery, never a model. Run from ``clients/python`` with the verifiers
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
"""

from __future__ import annotations

import argparse
import contextlib
import glob
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.request
from typing import Any, Dict, Iterator, List, Optional

from plimsoll_client.verifiers_runtime import IMPORT_PATH, check_record_log

from ..scripted_model import ScriptedModel
from .policies import POLICIES

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.dirname(HERE)
CLIENT = os.path.dirname(os.path.dirname(FRAMEWORK))
IMAGE = "plimsoll-wip/verifiers-agent:dev"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def serve(binary: str, out: str, docker_runtime: str, image: str, rate_per_min: int) -> Iterator[tuple]:
    """A plimsolld on loopback with docker sessions and a fresh bearer token; yields its
    URL and the token once /readyz answers."""
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
    proc = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)
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
                rows.append(
                    {
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
                        "tool_results": roles.count("tool"),
                        "runtime": (t.get("agent") or {}).get("runtime"),
                    }
                )
    return rows


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
    p.add_argument("--rollout-timeout", type=float, help="verifiers' agent phase timeout, seconds")
    p.add_argument("--taskset-path", action="append", default=[], help="a directory to import an outside taskset from")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    harness = "bash" if args.shipped_harness else "plimsoll-bash"
    if args.policy not in POLICIES[args.task]:
        p.error(f"no policy {args.policy!r} for {args.task}; have {sorted(POLICIES[args.task])}")
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    floor = args.floor or ("kernel" if args.docker_runtime == "runsc" else "container")
    record_log = os.path.join(out, "records.jsonl")
    with contextlib.ExitStack() as stack:
        url, token = args.url, os.environ.get("PLIMSOLL_TOKEN", "")
        if args.runtime == "plimsoll" and url is None:
            if not args.serve:
                p.error("--runtime plimsoll needs --serve or --url")
            url, token = stack.enter_context(serve(os.path.abspath(args.serve), out, args.docker_runtime, args.image, args.rate_per_min))
        model = stack.enter_context(ScriptedModel(POLICIES[args.task][args.policy]))
        taskset: Dict[str, Any] = {"id": args.task}
        if args.task == "uuid-ctf":
            taskset.update(difficulty="extra_easy", num_samples=1)
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
            "client": {"base_url": model.base_url, "api_key_var": "PLIMSOLL_SCRIPTED_MODEL_KEY"},
            "env.taskset": taskset,
            "env.agent.harness": {"id": harness},
            "env.agent.runtime": runtime,
        }
        if args.rollout_timeout:
            tables["env.agent.timeout"] = {"rollout": args.rollout_timeout}
        config = os.path.join(out, "eval.toml")
        write_config(config, tables)
        vf_eval = os.path.join(os.path.dirname(sys.executable), "vf-eval")
        command = [vf_eval, "@", config, "-m", "scripted", "-n", "1", "-r", str(args.rollouts), "-c", "1",
                   "--no-push", "--no-rich", "-o", os.path.join(out, "runs"), "--run.dir", "run"]
        # vf-eval imports the outside taskset's evaluator code into its own process, so it
        # gets only what the run needs, never this shell's other variables (a key set for
        # some other tool would otherwise be readable by that code).
        env = {name: os.environ[name] for name in _VF_EVAL_PASS if name in os.environ}
        env.update({
            "PYTHONPATH": os.pathsep.join([os.path.join(CLIENT, "src"), FRAMEWORK, *map(os.path.abspath, args.taskset_path)]),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PLIMSOLL_TOKEN": token,
        })
        started = time.monotonic()
        with open(os.path.join(out, "vf-eval.log"), "wb") as log:
            proc = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, cwd=out, timeout=1800)
        wall = round(time.monotonic() - started, 3)
        summary: Dict[str, Any] = {
            "task": args.task,
            "policy": args.policy,
            "harness": harness,
            "runtime": args.runtime,
            "docker_runtime": (args.docker_runtime or "runc") if args.runtime == "plimsoll" else None,
            "floor": floor if args.runtime == "plimsoll" else None,
            "rate_per_min": args.rate_per_min if args.serve and args.runtime == "plimsoll" else None,
            "vf_eval_exit": proc.returncode,
            "wall_s": wall,
            "model_requests": len(model.requests),
            "rollouts": summarize_traces(os.path.join(out, "runs")),
        }
    if args.runtime == "plimsoll" and os.path.exists(record_log):
        try:
            summary["record_log"] = check_record_log(record_log, minimum_isolation=floor)
        except Exception as e:  # reported, not raised: the run's other numbers still stand
            summary["record_log"] = {"error": f"{type(e).__name__}: {e}"}
    print(json.dumps(summary, indent=2))
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return 0 if proc.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
