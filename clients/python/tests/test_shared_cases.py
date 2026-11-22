"""The record cases of internal/clientcases/testdata/records.json, which the Go and
TypeScript clients run too, on the two paths this client has for them: the record an
unanswered session call's error carries (check_unanswered, which the session calls), and
the lost call's record an attach answer returns (_lost_record, which the attach calls,
refusing every problem it states as a broken chain). Each verdict is asserted here and
written down for the judge of the shared cases (tests/_cases.py)."""

from __future__ import annotations

import json
import unittest
from typing import Optional

from plimsoll_client import ChainError, PlimsollError, SessionCheckpoint
from plimsoll_client._record import check_unanswered
from plimsoll_client._wire import Msg
from plimsoll_client.client import _lost_record

from ._cases import ROOT, says_of, verdict

CASES = json.loads((ROOT / "internal" / "clientcases" / "testdata" / "records.json").read_text())["cases"]


class SharedRecordCases(unittest.TestCase):
    def test_every_record_case_on_every_path(self) -> None:
        self.assertTrue(CASES, "no record cases")
        for c in CASES:
            inp = c["input"]
            for path in c["paths"]:
                err: Optional[PlimsollError] = None
                if path == "session-unanswered":
                    try:
                        check_unanswered(inp["requestSha256"], inp["floor"], None, Msg(inp["record"], "unanswered"))
                    except PlimsollError as e:
                        err = e
                elif path == "attach-lost":
                    cp = SessionCheckpoint.from_json(inp["checkpoint"])
                    _, problem = _lost_record(cp, inp["lost"], Msg(inp["record"], "lostRecord"))
                    if problem:
                        err = ChainError(f"plimsoll: the daemon's answer to the attach {problem}")
                else:
                    continue  # a path this client does not have (stored is Go's)
                with self.subTest(c["id"], path=path):
                    got = says_of(err)
                    verdict(c["id"], path, got)
                    self.assertEqual(got, c["expect"][path], err)


if __name__ == "__main__":
    unittest.main()
