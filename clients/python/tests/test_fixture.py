"""Digests the Go record package computed, over messages Go's protobuf JSON encoder
wrote: the fixture client_test.go writes before it runs this suite."""

from __future__ import annotations

import unittest

from plimsoll_client._record import record_digest, record_from_wire, request_digest, result_digest, session_fingerprint
from plimsoll_client._wire import Msg, loads

from ._env import setting


class GoDigests(unittest.TestCase):
    fixture: dict

    @classmethod
    def setUpClass(cls) -> None:
        # The client's own JSON reader, as an answer would be read: the standard
        # one would turn the encoder's "-0" into an integer zero.
        with open(setting("PLIMSOLL_DIGEST_FIXTURE"), "rb") as f:
            cls.fixture = loads(f.read())

    def test_requests(self) -> None:
        self.assertGreater(len(self.fixture["requests"]), 0)
        for case in self.fixture["requests"]:
            with self.subTest(case["name"]):
                self.assertEqual(request_digest(case["message"]), case["digest"])

    def test_results(self) -> None:
        self.assertGreater(len(self.fixture["results"]), 0)
        for case in self.fixture["results"]:
            with self.subTest(case["name"]):
                self.assertEqual(result_digest(Msg(case["message"], "fixture")), case["digest"])

    def test_records(self) -> None:
        self.assertGreater(len(self.fixture["records"]), 0)
        for case in self.fixture["records"]:
            with self.subTest(case["name"]):
                self.assertEqual(record_digest(record_from_wire(Msg(case["message"], "fixture"))), case["digest"])

    def test_fingerprints(self) -> None:
        for case in self.fixture["fingerprints"]:
            with self.subTest(case["id"]):
                self.assertEqual(session_fingerprint(case["id"]), case["digest"])


if __name__ == "__main__":
    unittest.main()
