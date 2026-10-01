"""Run-record digests and checks.

The golden vectors are record/testdata/golden.json, the file the Go record package
and the TypeScript client test against too. A change to any of them is a change to
docs/run-records.md. The Go test beside this package (client_test.go)
also hands this suite a fixture of digests the Go package computed over JSON the
Go encoder wrote (test_fixture.py), so the two implementations are compared on
more than these vectors.
"""

from __future__ import annotations

import base64
import copy
import json
import pathlib
import unittest

from plimsoll_client import (
    NoRecordError,
    RecordMismatchError,
    RecordVersionError,
    RunRecord,
    SoftwareRule,
)
from plimsoll_client._record import (
    check,
    check_single,
    record_digest,
    record_from_wire,
    request_digest,
    result_digest,
    session_fingerprint,
)
from plimsoll_client._wire import Msg


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# record/testdata/golden.json: the vectors' inputs in their JSON wire form and the
# digests they must produce. The Go record package and the TypeScript client read
# the same file.
GOLDEN = json.loads((pathlib.Path(__file__).resolve().parents[3] / "record" / "testdata" / "golden.json").read_text())


def golden_input(name: str) -> dict:
    for group, field in (("requests", "request"), ("results", "response"), ("records", "record")):
        for v in GOLDEN[group]:
            if v["name"] == name:
                return copy.deepcopy(v[field])
    raise KeyError(name)


def js_request() -> dict:
    return golden_input("version 1 javascript request")


def project_request() -> dict:
    return golden_input("version 1 project request")


def module_request() -> dict:
    return golden_input("version 1 module request")


def cell_request() -> dict:
    return golden_input("cell request")


def cell_response() -> dict:
    return golden_input("cell result")


APPROVED = ["oci-manifest:linux/amd64@sha256:" + "a" * 64, "oci-manifest:linux/amd64@sha256:" + "b" * 64]


def version_two(base: dict) -> dict:
    out = copy.deepcopy(base)
    out["protocol"] = 2
    out["softwareRule"] = {"mode": "approved", "identities": list(APPROVED)}
    return out


def js_response() -> dict:
    return golden_input("javascript result")


def project_response() -> dict:
    return golden_input("project result")


def module_response() -> dict:
    return golden_input("module result")


def golden_record() -> RunRecord:
    return record_from_wire(Msg(golden_input("record"), "record"))


def wire_record(r: RunRecord) -> dict:
    return {
        "version": r.version,
        "requestSha256": r.request_sha256,
        "resultSha256": r.result_sha256,
        "provider": r.provider,
        "isolation": r.isolation,
        "environment": r.environment,
        "policy": r.policy,
        "softwareIdentity": r.software_identity,
        "softwareRuleId": r.software_rule_id,
        "startedUnixMs": str(r.started_unix_ms),
        "endedUnixMs": str(r.ended_unix_ms),
        "session": r.session,
        "sequence": str(r.sequence),
        "previousSha256": r.previous_sha256,
        "recordSha256": r.sha256,
    }


def stamped(req: dict, resp: dict, rule: "SoftwareRule | None" = None) -> dict:
    """resp with the record a daemon states for req (record.Stamp)."""
    out = copy.deepcopy(resp)
    m = Msg(out, "r")
    r = RunRecord(
        version=2,
        request_sha256=request_digest(req),
        result_sha256=result_digest(m),
        provider=m.get_str("sandbox"),
        isolation=m.get_str("isolation"),
        environment=m.get_str("environment"),
        policy="",
        software_identity=m.get_str("softwareIdentity"),
        software_rule_id=rule.rule_id() if rule else "",
        started_unix_ms=1790000000000,
        ended_unix_ms=1790000000812,
        session="",
        sequence=0,
        previous_sha256="",
        sha256="",
    )
    r = RunRecord(**{**r.__dict__, "sha256": record_digest(r)})
    out["record"] = wire_record(r)
    return out


class GoldenVectors(unittest.TestCase):
    # Every vector of record/testdata/golden.json.
    def test_vectors(self) -> None:
        n = 0
        for v in GOLDEN["requests"]:
            with self.subTest(v["name"]):
                self.assertEqual(request_digest(copy.deepcopy(v["request"])), v["sha256"])
            n += 1
        for v in GOLDEN["results"]:
            with self.subTest(v["name"]):
                self.assertEqual(result_digest(Msg(v["response"], "r")), v["sha256"])
            n += 1
        for v in GOLDEN["records"]:
            with self.subTest(v["name"]):
                self.assertEqual(record_digest(record_from_wire(Msg(v["record"], "record"))), v["sha256"])
            n += 1
        for v in GOLDEN["sessionFingerprints"]:
            with self.subTest(v["name"]):
                self.assertEqual(session_fingerprint(v["sessionId"]), v["sha256"])
            n += 1
        self.assertGreaterEqual(n, 13, "a vector was dropped from the golden file")

    def test_snake_case_field_names_digest_the_same(self) -> None:
        # protobuf's JSON parser accepts the original field names too.
        snake = {
            "protocol": 1,
            "minimum_isolation": "container",
            "timeout_ms": 5000,
            "javascript": {"code": "console.log(1+1)"},
        }
        self.assertEqual(request_digest(snake), request_digest(js_request()))


class DigestCoverage(unittest.TestCase):
    def test_request_digest_covers_what_was_sent(self) -> None:
        changes = [
            ("protocol", js_request, lambda m: m.update(protocol=2)),
            ("floor", js_request, lambda m: m.update(minimumIsolation="vm")),
            ("timeout", js_request, lambda m: m.update(timeoutMs=5001)),
            ("code", js_request, lambda m: m["javascript"].update(code="console.log(1+1) ")),
            ("grant", js_request, lambda m: m["javascript"].update(grantProfile="p")),
            ("file order", project_request, lambda m: m["project"]["files"].reverse()),
            (
                "path and content boundary",
                project_request,
                lambda m: m["project"]["files"].__setitem__(1, {"path": "lib.jsm", "content": "odule.exports = 42"}),
            ),
            ("two steps become one", project_request, lambda m: m["project"].update(steps=["node main.js > out.txtcat out.txt"])),
            ("artifact", project_request, lambda m: m["project"].update(artifacts=[])),
            ("row value", module_request, lambda m: m["module"]["rows"][1].update(values=[0.5, -3.0000000000000004])),
            ("rows regrouped", module_request, lambda m: m["module"].update(rows=[{"values": [1]}, {"values": [2, 0.5, -3]}])),
            ("software identity order", lambda: version_two(js_request()), lambda m: m["softwareRule"]["identities"].reverse()),
        ]
        for name, base, apply in changes:
            with self.subTest(name):
                changed = base()
                apply(changed)
                self.assertNotEqual(request_digest(changed), request_digest(base()))
        same = js_request()
        same["traceId"] = "another-trace"
        same["sessionId"] = "a-session"
        self.assertEqual(request_digest(same), request_digest(js_request()), "the trace and session IDs moved the digest")

    def test_negative_zero_is_not_zero(self) -> None:
        a = module_request()
        b = copy.deepcopy(a)
        b["module"]["rows"][0]["values"] = [-0.0, 2]
        a["module"]["rows"][0]["values"] = [0.0, 2]
        self.assertNotEqual(request_digest(a), request_digest(b))

    def test_result_digest_ignores_duration_advice_and_evidence(self) -> None:
        same = project_response()
        same["durationMs"] = "1"
        same["sandbox"], same["isolation"] = "docker", "kernel"
        same["project"]["steps"][0]["durationMs"] = "7"
        same["project"]["advice"] = [{"pattern": "fan_out"}]
        self.assertEqual(result_digest(Msg(same, "r")), result_digest(Msg(project_response(), "r")))
        changed = js_response()
        changed["javascript"]["stderr"] = b64(b"\xfex")
        self.assertNotEqual(result_digest(Msg(changed, "r")), result_digest(Msg(js_response(), "r")))

    def test_outcome_by_name_or_number(self) -> None:
        by_number = project_response()
        by_number["project"]["outcome"] = 1
        self.assertEqual(result_digest(Msg(by_number, "r")), result_digest(Msg(project_response(), "r")))

    def test_rule_ids(self) -> None:
        a, b = APPROVED
        self.assertEqual(SoftwareRule.exact(a).rule_id(), "exact:" + a)
        self.assertEqual(SoftwareRule.approved(a).rule_id(), "exact:" + a)
        self.assertEqual(SoftwareRule.approved(a, b).rule_id(), SoftwareRule.approved(b, a).rule_id())
        self.assertTrue(SoftwareRule.approved(a, b).rule_id().startswith("approved:sha256:"))
        self.assertFalse(SoftwareRule.exact(a).allows(""))


class Check(unittest.TestCase):
    def test_a_matching_record_checks(self) -> None:
        req = js_request()
        req["protocol"] = 2
        r = check_single(request_digest(req), 2, None, Msg(stamped(req, js_response()), "r"))
        self.assertEqual(r.provider, "docker")
        self.assertEqual(r.sha256, record_digest(r))

    def test_tampering_is_a_mismatch(self) -> None:
        req = js_request()
        req["protocol"] = 2
        good = stamped(req, js_response())

        def code_changed(q, _):
            q["javascript"]["code"] = "console.log(3)"

        def output_changed(_, s):
            s["javascript"]["stdout"] = b64(b"4\n")

        def provider_changed(_, s):
            s["sandbox"] = "e2b"

        def tier_changed(_, s):
            s["isolation"] = "vm"

        def environment_changed(_, s):
            s["environment"] = "docker-image:sha256:other"

        def time_changed(_, s):
            s["record"]["endedUnixMs"] = "1790000000813"

        def digest_changed(_, s):
            s["record"]["recordSha256"] = "00"

        for tamper in (code_changed, output_changed, provider_changed, tier_changed, environment_changed, time_changed, digest_changed):
            with self.subTest(tamper.__name__):
                q, s = copy.deepcopy(req), copy.deepcopy(good)
                tamper(q, s)
                with self.assertRaises(RecordMismatchError):
                    check_single(request_digest(q), 2, None, Msg(s, "r"))

    def test_a_single_run_claiming_a_session_is_a_mismatch(self) -> None:
        req = js_request()
        req["protocol"] = 2
        s = stamped(req, js_response())
        rec = Msg(s["record"], "r")
        from plimsoll_client._record import record_from_wire

        r = record_from_wire(rec)
        r = RunRecord(**{**r.__dict__, "sequence": 1})
        r = RunRecord(**{**r.__dict__, "sha256": record_digest(r)})
        s["record"] = wire_record(r)
        check(request_digest(req), 2, None, Msg(s, "r"))  # a session call's check accepts it
        with self.assertRaises(RecordMismatchError):
            check_single(request_digest(req), 2, None, Msg(s, "r"))

    def test_no_record_and_versions(self) -> None:
        req = js_request()
        req["protocol"] = 2
        with self.assertRaises(NoRecordError):
            check_single(request_digest(req), 2, None, Msg(js_response(), "r"))
        future = stamped(req, js_response())
        future["record"]["version"] = 3
        with self.assertRaises(RecordVersionError):
            check_single(request_digest(req), 2, None, Msg(future, "r"))

    def test_version_one_records_remain_verifiable_for_protocol_one(self) -> None:
        req = js_request()
        resp = js_response()
        m = Msg(resp, "r")
        r = RunRecord(
            version=1, request_sha256=request_digest(req), result_sha256=result_digest(m),
            provider="docker", isolation="container", environment="", policy="", software_identity="",
            software_rule_id="", started_unix_ms=1, ended_unix_ms=2, session="", sequence=0,
            previous_sha256="", sha256="",
        )
        r = RunRecord(**{**r.__dict__, "sha256": record_digest(r)})
        resp["record"] = wire_record(r)
        check_single(request_digest(req), 1, None, Msg(resp, "r"))
        with self.assertRaises(RecordVersionError):
            check_single(request_digest(req), 2, None, Msg(resp, "r"))

    def test_software_rule_binds_record_request_and_response(self) -> None:
        ident = APPROVED[0]
        rule = SoftwareRule.exact(ident)
        req = {"protocol": 2, "softwareRule": {"mode": "exact", "identities": [ident]}, "javascript": {"code": "1"}}
        resp = {"sandbox": "docker", "isolation": "kernel", "environment": "docker-image:sha256:outer",
                "softwareIdentity": ident, "javascript": {}}
        good = stamped(req, resp, rule)
        check_single(request_digest(req), 2, rule, Msg(good, "r"))
        tampered = copy.deepcopy(good)
        tampered["softwareIdentity"] = ""
        with self.assertRaises(RecordMismatchError):
            check_single(request_digest(req), 2, rule, Msg(tampered, "r"))
        with self.assertRaises(RecordMismatchError):  # the rule the caller holds differs from the record's
            check_single(request_digest(req), 2, SoftwareRule.exact(APPROVED[1]), Msg(good, "r"))


if __name__ == "__main__":
    unittest.main()
