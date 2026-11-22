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

from ._cases import verdict

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
                verdict("answers/" + a["name"], "error-answer", got)
                self.assertEqual(got, a["expect"])

    def test_an_answer_with_a_null_detail_is_believed_in_nothing(self) -> None:
        # Finding release-88: the Go client panicked on a null in the details list. Every
        # client reads such an answer as one it cannot read: the HTTP status's code, no
        # mark (the header's included), no session end, no unanswered call's record.
        nulls = [a for a in ANSWERS["answers"] if "null" in a["name"]]
        self.assertGreaterEqual(len(nulls), 4)
        for a in nulls:
            with self.subTest(a["name"]):
                e = error_from_wire(a["status"], a["body"].encode(), bound=True, mark=a.get("mark") or None)
                self.assertIsNone(e.not_dispatched)
                self.assertIsNone(e.unanswered)
                self.assertNotIsInstance(e, SessionEndedError)
        for body in ('{"code":"internal","details":[5,{"type":"plimsoll.v1.NotDispatched","value":"CAE"}]}',
                     '{"code":"internal","details":[[],{"type":"plimsoll.v1.NotDispatched","value":"CAE"}]}'):
            with self.subTest(body):
                e = error_from_wire(503, body.encode(), bound=True, mark="capacity")
                self.assertEqual((e.code, e.not_dispatched), ("unavailable", None))


if __name__ == "__main__":
    unittest.main()
