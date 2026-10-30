"""What one runtime call costs, through verifiers' own runtime API, on verifiers' docker runtime
and on the plimsoll runtime: provisioning (``start``), a command (``run`` of ``true``), a 1 KiB
write and read, and teardown, each timed on the evaluator. No model and no harness, so the
numbers are the runtimes' own. Run from ``clients/python`` under the docker lock:

    flock ../../tmp/docker.lock ../../tmp/py-frameworks/verifiers/bin/python -m \\
        frameworks.verifiers.attempt.measure_calls --serve ../../tmp/plimsolld \\
        --out ../../tmp/vf-attempt/calls
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import statistics
import time
from typing import Any, Dict, List, Optional

from pydantic import TypeAdapter
from verifiers.v1.runtimes import RuntimeConfig, provision_runtime

from plimsoll_client.verifiers_runtime import IMPORT_PATH, check_record_log

from .run_attempt import IMAGE, serve


def _stats(values: List[float]) -> Dict[str, float]:
    ms = [v * 1000 for v in values]
    return {"median_ms": round(statistics.median(ms), 1), "min_ms": round(min(ms), 1), "max_ms": round(max(ms), 1), "n": len(ms)}


async def measure(config: Dict[str, Any], rounds: int, calls: int) -> Dict[str, Any]:
    starts: List[float] = []
    runs: List[float] = []
    writes: List[float] = []
    reads: List[float] = []
    ends: List[float] = []
    data = os.urandom(1024)
    for _ in range(rounds):
        runtime_config = TypeAdapter(RuntimeConfig).validate_python(config)
        t0 = time.perf_counter()
        cm = provision_runtime(runtime_config)
        view = await cm.__aenter__()
        starts.append(time.perf_counter() - t0)
        try:
            for _ in range(calls):
                t = time.perf_counter()
                result = await view.run(["true"], {})
                runs.append(time.perf_counter() - t)
                assert result.exit_code == 0, result
            t = time.perf_counter()
            await view.write("probe.bin", data)
            writes.append(time.perf_counter() - t)
            t = time.perf_counter()
            assert await view.read("probe.bin", max_bytes=4096) == data
            reads.append(time.perf_counter() - t)
        finally:
            t = time.perf_counter()
            await cm.__aexit__(None, None, None)
            ends.append(time.perf_counter() - t)
    return {"start": _stats(starts), "run_true": _stats(runs), "write_1k": _stats(writes), "read_1k": _stats(reads), "teardown": _stats(ends)}


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--serve", required=True, metavar="PLIMSOLLD")
    p.add_argument("--image", default=IMAGE)
    p.add_argument("--rounds", type=int, default=5, help="runtimes provisioned per configuration")
    p.add_argument("--calls", type=int, default=20, help="run calls per runtime")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    results: Dict[str, Any] = {"rounds": args.rounds, "calls_per_round": args.calls}
    results["docker"] = asyncio.run(measure({"type": "docker"}, args.rounds, args.calls))
    for docker_runtime, floor in (("", "container"), ("runsc", "kernel")):
        label = "plimsoll-" + (docker_runtime or "runc")
        sub = os.path.join(out, label)
        os.makedirs(sub, exist_ok=True)
        log = os.path.join(sub, "records.jsonl")
        with contextlib.ExitStack() as stack:
            url, token = stack.enter_context(serve(os.path.abspath(args.serve), sub, docker_runtime, args.image, 6000))
            os.environ["PLIMSOLL_TOKEN"] = token
            config = {"type": "custom", "import_path": IMPORT_PATH, "url": url, "minimum_isolation": floor, "record_log": log}
            results[label] = asyncio.run(measure(config, args.rounds, args.calls))
        results[label]["record_log"] = check_record_log(log, minimum_isolation=floor)
    print(json.dumps(results, indent=2))
    with open(os.path.join(out, "calls.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
