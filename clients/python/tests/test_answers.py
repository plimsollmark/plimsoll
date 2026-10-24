"""The daemon answers in protocol/testdata/answers.json, which the Go and TypeScript
clients read too: this client must read each the way the file says (review D5,
2026-10-23: the accept and reject logic was ported three times, with vectors for the
digests alone)."""

from __future__ import annotations

import json
import pathlib
import unittest

from plimsoll_client import SessionEndedError
from plimsoll_client._wire import error_from_wire

ANSWERS = json.loads((pathlib.Path(__file__).resolve().parents[3] / "protocol" / "testdata" / "answers.json").read_text())


class SharedAnswers(unittest.TestCase):
    def test_every_answer_reads_as_the_file_says(self) -> None:
        self.assertGreaterEqual(len(ANSWERS["answers"]), 10)
        for a in ANSWERS["answers"]:
            with self.subTest(a["name"]):
                e = error_from_wire(a["status"], a["body"].encode(), bound=a["echo"] == "match", mark=a.get("mark") or None)
                end = e.reason if isinstance(e, SessionEndedError) else ""
                got = {"code": e.code, "notDispatched": e.not_dispatched or "", "sessionEnded": end,
                       "answerNotBound": e.answer_not_bound}
                self.assertEqual(got, a["expect"])


if __name__ == "__main__":
    unittest.main()
