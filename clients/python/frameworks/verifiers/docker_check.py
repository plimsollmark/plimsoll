"""The verifiers runtime plugin on real docker sessions. Not a test_*.py, so the framework
suite's discover run does not pick it up: it needs docker. verifiers_docker_test.go's
TestVerifiersRuntimeDocker serves a docker daemon with sessions on, sets
PLIMSOLL_DOCKER_SESSIONS_URL and runs this module by name. Without the setting every case
skips, unless PLIMSOLL_DOCKER_REQUIRED=1.

What it proves: the plimsoll-sum environment, unchanged, validates through verifiers' own
``vf-validate`` on the plimsoll runtime (setup, the gold answer scoring 1, an untouched
task graded 0 in a fresh sandbox after its output was carried over), and every call of
every session it opened is in the record log, which rechecks with nothing but the file."""

from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
import unittest

from plimsoll_client.verifiers_runtime import IMPORT_PATH, check_record_log

HERE = os.path.dirname(os.path.abspath(__file__))


def _setting(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        if os.environ.get("PLIMSOLL_DOCKER_REQUIRED") == "1":
            raise RuntimeError(f"{name} is not set, and PLIMSOLL_DOCKER_REQUIRED=1")
        raise unittest.SkipTest(f"{name} is not set; run through go test ./clients/python -run TestVerifiersRuntimeDocker")
    return value


class VerifiersOnDocker(unittest.TestCase):
    def test_plimsoll_sum_validates_and_its_records_check(self) -> None:
        url = _setting("PLIMSOLL_DOCKER_SESSIONS_URL")
        floor = os.environ.get("PLIMSOLL_DOCKER_FLOOR", "container")
        out = _setting("PLIMSOLL_VERIFIERS_OUT")
        log = os.path.join(out, "records.jsonl")
        validate = os.path.join(os.path.dirname(sys.executable), "vf-validate")
        argv = [
            validate,
            "plimsoll-sum",
            "--runtime.type", "custom",
            "--runtime.import_path", IMPORT_PATH,
            "--runtime.url", url,
            "--runtime.minimum_isolation", floor,
            "--runtime.record_log", log,
            "--no-rich",
            "-o", out,
        ]
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(["src", HERE])}
        proc = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=900)
        self.assertEqual(proc.returncode, 0, proc.stdout[-4000:] + proc.stderr[-4000:])
        results = glob.glob(os.path.join(out, "*", "results.jsonl"))
        self.assertEqual(len(results), 1, results)
        with open(results[0], encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual((row["valid"], row["reason"]), (True, "valid"), row)
        # Each check is a row of its own (verifiers/v1/cli/validate.py, 0.4.1.dev97): the gold
        # answer passes, and the untouched task, graded in a fresh sandbox after its output
        # was carried over, scores exactly 0.
        gold, noop = row["gold"], row["noop"]
        self.assertEqual((gold["valid"], gold["reason"], gold["error"]), (True, "valid", None), gold)
        self.assertEqual((noop["valid"], noop["reason"], noop["error"]), (True, "valid", None), noop)
        self.assertEqual((noop["reward"], noop["rewards"]), (0.0, {"correct": 0.0}), noop)

        summary = check_record_log(log, minimum_isolation=floor)
        # The gold check's sandbox, the untouched task's solver and its fresh grader.
        self.assertEqual(summary["sessions"], 3, summary)
        self.assertEqual(summary["closed"], 3, summary)
        self.assertEqual(summary["incomplete"], [], summary)
        self.assertEqual(set(summary["tiers"]), {floor}, summary)
        with open(log, encoding="utf-8") as f:
            entries = [json.loads(line) for line in f]
        ops = [e["op"] for e in entries if e["kind"] == "record"]
        for op in ("root", "run", "read", "write"):
            self.assertIn(op, ops)
        # The log holds digests and evidence, never a path or a file's content.
        self.assertNotIn("check.sh", json.dumps(entries))
        print(json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
