"""PlimsollExecutor on a real docker session (plimsoll/sandbox-python under the docker provider),
run by TestSmolagentsDocker in make docker-suite: a CodeAgent built by code_agent and driven by
a scripted model (no model is called) runs three steps in the session's Python interpreter. The
first sets a variable, the second reads it, the third calls final_answer, whose value ends the
run, and executor.records holds each cell's checked record, the session's chain in order. A
second run's first step prints past the sandbox's output limit, so its result is lost and the
model is told, and the run goes on.

Not a test_*.py, so the framework suite (TestPythonFrameworks, a session faked in memory) never
collects it."""

from __future__ import annotations

import os
import sys
import unittest

from smolagents.memory import ActionStep
from smolagents.monitoring import LogLevel

from frameworks.smolagents.test_smolagents import LOG, Scripted
from plimsoll_client import Client, SessionEndedError
from plimsoll_client.smolagents import PlimsollExecutor, code_agent
from plimsoll_client.types import meets

URL = os.environ.get("PLIMSOLL_DOCKER_SESSIONS_URL", "")
# The tier the daemon's docker runtime gives: container under runc, kernel under runsc.
FLOOR = os.environ.get("PLIMSOLL_DOCKER_FLOOR", "container")

if not URL:
    sys.exit("PLIMSOLL_DOCKER_SESSIONS_URL is not set: run through TestSmolagentsDocker (make docker-suite)")


class CodeAgentOnASession(unittest.TestCase):
    def test_a_variable_set_in_one_step_is_read_in_the_next_and_final_answer_ends_the_run(self) -> None:
        model = Scripted(
            "import sys\nx = 6\nprint('set', x, 'in Python', sys.version.split()[0])",
            "y = x * 7\nprint('read', x, y)",
            "final_answer(y)",
        )
        executor = PlimsollExecutor([], LOG, client=Client(URL), minimum_isolation=FLOOR)
        self.assertTrue(meets(executor.session.isolation, FLOOR), executor.session.isolation)
        with code_agent(executor, tools=[], model=model, max_steps=3, verbosity_level=LogLevel.OFF) as agent:
            answer = agent.run("go")
        self.assertIsNone(executor.fatal_error, executor.fatal_error)
        self.assertEqual(answer, 42)
        self.assertEqual(model.calls, 3, "one model call per step, and no final-answer call at max_steps")

        actions = [s for s in agent.memory.steps if isinstance(s, ActionStep)]
        for s in actions:
            print(f"\nstep {s.step_number}: error {s.error!r}, final {s.is_final_answer}, observations {s.observations!r}")
        self.assertEqual(len(actions), 3)
        self.assertTrue(all(s.error is None for s in actions), [s.error for s in actions])
        self.assertIn("set 6 in Python 3.", actions[0].observations or "")
        self.assertIn("read 6 42", actions[1].observations or "")
        self.assertEqual([s.is_final_answer for s in actions], [False, False, True])
        self.assertEqual(actions[2].action_output, 42)

        # What plimsoll stated about each cell, as the daemon signed it: the setup cell, the
        # tools' definitions and the three steps, the session's chain in order.
        records = executor.records
        self.assertEqual(len(records), 5)
        self.assertEqual(len(records), executor.session.calls)
        self.assertEqual([r.record.sequence for r in records], [1, 2, 3, 4, 5])
        self.assertEqual([r.record.previous_sha256 for r in records], [""] + [r.record_sha256 for r in records[:-1]])
        self.assertEqual(records[-1].record_sha256, executor.session.last_record_sha256)
        self.assertTrue(all(meets(r.isolation, FLOOR) and r.outcome == "completed" for r in records), records)
        self.assertTrue(all(r.record.session == executor.session.fingerprint for r in records))
        print(f"\nrecords: {[(r.record.sequence, r.isolation, r.outcome, r.record_sha256[:12]) for r in records]}")

        # Leaving the agent's with block closed the session: nothing more can be sent.
        with self.assertRaises(SessionEndedError):
            executor.session.run_cell("1", "python")

    def test_a_step_past_the_output_limit_loses_its_result_and_the_run_goes_on(self) -> None:
        # The step prints a terminal control sequence (a new window title), then more than the
        # docker provider's output limit (64 KiB by default): the sandbox cuts the output, so the
        # record at its end is lost, and the model is shown that, with the control character
        # escaped. The interpreter lives on: the next step answers.
        model = Scripted("print('\\x1b]0;PWNED\\x07' + 'x' * 300000)\nkept = 7", "final_answer(kept * 6)")
        executor = PlimsollExecutor([], LOG, client=Client(URL), minimum_isolation=FLOOR)
        with code_agent(executor, tools=[], model=model, max_steps=3, verbosity_level=LogLevel.OFF) as agent:
            answer = agent.run("go")
        self.assertIsNone(executor.fatal_error, executor.fatal_error)
        self.assertEqual(answer, 42)
        actions = [s for s in agent.memory.steps if isinstance(s, ActionStep)]
        error = str(actions[0].error)
        print(f"\nstep 1: error {error[:120]!r}...{error[-200:]!r}")
        self.assertIn("its output passed the sandbox's limit and was cut", error)
        self.assertIn("\\x1b]0;PWNED\\x07x", error)
        self.assertNotIn("\x1b", error)
        self.assertIsNone(actions[1].error)


if __name__ == "__main__":
    unittest.main()
