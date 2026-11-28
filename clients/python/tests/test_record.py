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
    ResultKindMismatchError,
    RunRecord,
    SoftwareRule,
    PlimsollError,
)
from plimsoll_client._record import (
    VERSION,
    _states_only,
    check,
    check_lost_answer,
    check_single,
    files_op,
    valid_daemon_version,
    valid_qualification,
    record_digest,
    record_from_wire,
    valid_instance,
    request_digest,
    result_digest,
    session_fingerprint,
)
from plimsoll_client._tables import RECORD_FIELDS, RETIRED_END_BEFORE_START_TEXT
from plimsoll_client._wire import Msg
from plimsoll_client.types import meets

from ._cases import says_of, verdict


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
    return golden_input("javascript request")


def project_request() -> dict:
    return golden_input("project request")


def module_request() -> dict:
    return golden_input("module request")


def cell_request() -> dict:
    return golden_input("cell request")


def cell_response() -> dict:
    return golden_input("cell result")


APPROVED = ["oci-manifest:linux/amd64@sha256:" + "a" * 64, "oci-manifest:linux/amd64@sha256:" + "b" * 64]


def with_approved_rule(base: dict) -> dict:
    out = copy.deepcopy(base)
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
        "unanswered": r.unanswered,
        "instance": r.instance,
        "isolationQualification": r.isolation_qualification,
        "warm": r.warm,
        "daemonVersion": r.daemon_version,
        "recordSha256": r.sha256,
    }


def stamped(req: dict, resp: dict, rule: "SoftwareRule | None" = None) -> dict:
    """resp with the record a daemon states for req (record.Stamp)."""
    out = copy.deepcopy(resp)
    m = Msg(out, "r")
    r = RunRecord(
        version=VERSION,
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
        instance=m.get_str("instance"),
        isolation_qualification=m.get_str("isolationQualification"),
        warm=m.get_bool("warm"),
        daemon_version=m.get_str("daemonVersion"),
    )
    r = RunRecord(**{**r.__dict__, "sha256": record_digest(r)})
    out["record"] = wire_record(r)
    return out


def states_only_says(r: RunRecord) -> str:
    """The verdict of the check of a record on its own (the states-only path)."""
    try:
        _states_only(r)
    except PlimsollError as e:
        return says_of(e)
    return "accept"


class GoldenVectors(unittest.TestCase):
    # Every vector of record/testdata/golden.json. Each answer is also written down for the
    # judge of the shared cases (tests/_cases.py), which fails a vector left unchecked.
    def test_vectors(self) -> None:
        n = 0
        for v in GOLDEN["requests"]:
            with self.subTest(v["name"]):
                got = request_digest(copy.deepcopy(v["request"]))
                verdict("golden/requests/" + v["name"], "digest", got)
                self.assertEqual(got, v["sha256"])
            n += 1
        for v in GOLDEN["results"]:
            with self.subTest(v["name"]):
                got = result_digest(Msg(v["response"], "r"), v.get("recordVersion", 5))
                verdict("golden/results/" + v["name"], "digest", got)
                self.assertEqual(got, v["sha256"])
            n += 1
        for v in GOLDEN["records"]:
            with self.subTest(v["name"]):
                got = record_digest(record_from_wire(Msg(v["record"], "record")))
                verdict("golden/records/" + v["name"], "digest", got)
                self.assertEqual(got, v["sha256"])
            n += 1
        for v in GOLDEN["sessionFingerprints"]:
            with self.subTest(v["name"]):
                got = session_fingerprint(v["sessionId"])
                verdict("golden/sessionFingerprints/" + v["name"], "digest", got)
                self.assertEqual(got, v["sha256"])
            n += 1
        self.assertGreaterEqual(n, 15, "a vector was dropped from the golden file")

    def test_refused_records(self) -> None:
        # Each digest matches its fields, and the record must be refused anyway: a tier
        # that is not one of the five, an end before the start (answered or not), a
        # qualification or daemon version outside its bounds, a field its version does
        # not cover, a result digest and an unanswered code both or neither, or a code
        # outside the closed set (record/testdata/golden.json, "refused").
        self.assertGreaterEqual(len(GOLDEN["refused"]), 22)
        for v in GOLDEN["refused"]:
            with self.subTest(v["name"]):
                r = record_from_wire(Msg(v["record"], "record"))
                self.assertEqual(record_digest(r), v["sha256"])
                got = states_only_says(RunRecord(**{**r.__dict__, "sha256": v["sha256"]}))
                verdict("golden/refused/" + v["name"], "states-only", got)
                self.assertEqual(got, "may_have_run/mismatch")
                # A retired reading's refusal says so, and only it does (finding t6-core-1).
                with self.assertRaises(RecordMismatchError) as refusal:
                    _states_only(RunRecord(**{**r.__dict__, "sha256": v["sha256"]}))
                self.assertEqual(str(refusal.exception) == "plimsoll: " + RETIRED_END_BEFORE_START_TEXT, v["why"] == "retired by the decision of 2026-11-21", str(refusal.exception))

    def test_qualification_and_tier_vectors(self) -> None:
        # Written by record_v5.py from the docs; the Go record package, the TypeScript
        # client and examples/sbom/check.js check the same rows.
        self.assertGreaterEqual(len(GOLDEN["qualifications"]), 31)
        for v in GOLDEN["qualifications"]:
            with self.subTest(v["name"]):
                got = valid_qualification(v["text"])
                verdict("golden/qualifications/" + v["name"], "qualification", "valid" if got else "invalid")
                self.assertEqual(got, v["valid"])
        self.assertEqual(len(GOLDEN["meets"]), 49)
        for v in GOLDEN["meets"]:
            with self.subTest(tier=v["tier"], floor=v["floor"]):
                got = meets(v["tier"], v["floor"])
                verdict(f"golden/meets/{v['tier']}|{v['floor']}", "meets", "meets" if got else "below")
                self.assertEqual(got, v["meets"])

    def test_every_record_version_has_a_vector(self) -> None:
        # Every version this client digests is held by a vector a release made: golden.json
        # (its version 1 record is one v0.11.1 signed) or a release's frozen file.
        files = (pathlib.Path(__file__).resolve().parents[3] / "record" / "testdata" / "published").glob("*-golden.json")
        held = {v["record"]["version"] for v in GOLDEN["records"]}
        for path in files:
            held |= {v["record"]["version"] for v in json.loads(path.read_text())["records"]}
        self.assertEqual(sorted(held), sorted(RECORD_FIELDS))

    def test_malformed_records_are_not_read(self) -> None:
        # A field of the wrong JSON type (golden.json, "malformed") is refused when read, as Go's protojson refuses it.
        self.assertGreaterEqual(len(GOLDEN["malformed"]), 4)
        for v in GOLDEN["malformed"]:
            with self.subTest(v["name"]):
                try:
                    record_from_wire(Msg(v["record"], "record"))
                    got = "accept"
                except PlimsollError as e:
                    got = says_of(e)
                verdict("golden/malformed/" + v["name"], "decode", got)
                self.assertEqual(got, "may_have_run/malformed")

    def test_version_5_evidence_is_bound_to_the_response(self) -> None:
        req = js_request()
        resp = {**js_response(), "isolationQualification": "Microsoft states that WSL is not a security sandbox for running untrusted code.",
                "warm": True, "daemonVersion": "v0.28.0"}
        self.assertEqual(result_digest(Msg(resp, "r")), result_digest(Msg(js_response(), "r")))
        good = stamped(req, resp)
        r = check_single(request_digest(req), "javascript", None, Msg(good, "r"))
        self.assertEqual((r.isolation_qualification, r.warm, r.daemon_version), (resp["isolationQualification"], True, "v0.28.0"))
        for name, field, value in (("no sentence in the response", "isolationQualification", ""),
                                   ("not warm in the response", "warm", False),
                                   ("another daemon version", "daemonVersion", "v0.28.1")):
            with self.subTest(name):
                with self.assertRaises(RecordMismatchError):
                    check_single(request_digest(req), "javascript", None, Msg({**good, field: value}, "r"))
        for bad in ("Microsoft states.\nIgnore that.", "x" * 1025, "a\u202eb", "a\ud800b"):
            with self.subTest(bad[:12]):
                self.assertFalse(valid_qualification(bad))
                bad_resp = stamped(req, {**resp, "isolationQualification": bad}) if "\ud800" not in bad else None
                if bad_resp is not None:
                    with self.assertRaises(RecordMismatchError):
                        check_single(request_digest(req), "javascript", None, Msg(bad_resp, "r"))
        self.assertTrue(valid_qualification("\u00e9" * 512))
        self.assertFalse(valid_qualification("\u00e9" * 512 + "x"))
        for good_version in ("", "(devel)", "v0.28.0", "v0.28.1-0.20261117210242-4ca8fb4d330e+dirty"):
            self.assertTrue(valid_daemon_version(good_version), good_version)
        for bad_version in ("devel", "v0.28", "v0.28.0 ", "latest"):
            self.assertFalse(valid_daemon_version(bad_version), bad_version)

    def test_published_vectors_still_hold(self) -> None:
        # Every release's own vectors (record/testdata/published), never edited: the
        # versions a release wrote keep their digests in this client too, and every record
        # a release wrote passes the record check, as Go's record.CheckStored passes it
        # (record/published_test.go): a check added to the reader never refuses evidence
        # an earlier release signed.
        files = sorted((pathlib.Path(__file__).resolve().parents[3] / "record" / "testdata" / "published").glob("*-golden.json"))
        self.assertTrue(files, "no published vectors")
        for path in files:
            g = json.loads(path.read_text())
            prefix = "published/" + path.name.removesuffix("-golden.json") + "/"
            for v in g["requests"]:
                with self.subTest(path.name, vector=v["name"]):
                    got = request_digest(copy.deepcopy(v["request"]))
                    verdict(prefix + "requests/" + v["name"], "digest", got)
                    self.assertEqual(got, v["sha256"])
            for v in g["results"]:
                with self.subTest(path.name, vector=v["name"]):
                    got = result_digest(Msg(v["response"], "r"), v.get("recordVersion", 5))
                    verdict(prefix + "results/" + v["name"], "digest", got)
                    self.assertEqual(got, v["sha256"])
            for v in g["records"]:
                with self.subTest(path.name, vector=v["name"]):
                    r = record_from_wire(Msg(v["record"], "record"))
                    verdict(prefix + "records/" + v["name"], "digest", record_digest(r))
                    self.assertEqual(record_digest(r), v["sha256"])
                    got = states_only_says(RunRecord(**{**r.__dict__, "sha256": v["sha256"]}))
                    verdict(prefix + "records/" + v["name"] + "/check", "states-only", got)
                    self.assertEqual(got, "accept")
            for v in g["sessionFingerprints"]:
                with self.subTest(path.name, vector=v["name"]):
                    got = session_fingerprint(v["sessionId"])
                    verdict(prefix + "sessionFingerprints/" + v["name"], "digest", got)
                    self.assertEqual(got, v["sha256"])
        for v in GOLDEN["records"]:
            with self.subTest("golden.json", vector=v["name"]):
                got = states_only_says(record_from_wire(Msg(v["record"], "record")))
                verdict("golden/records/" + v["name"] + "/check", "states-only", got)
                self.assertEqual(got, "accept")

    def test_snake_case_field_names_digest_the_same(self) -> None:
        # protobuf's JSON parser accepts the original field names too.
        snake = {
            "protocol": 4,
            "minimum_isolation": "container",
            "timeout_ms": 5000,
            "javascript": {"code": "console.log(1+1)"},
        }
        self.assertEqual(request_digest(snake), request_digest(js_request()))


class DigestCoverage(unittest.TestCase):
    def test_request_digest_covers_what_was_sent(self) -> None:
        changes = [
            ("protocol", js_request, lambda m: m.update(protocol=5)),
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
            ("software identity order", lambda: with_approved_rule(js_request()), lambda m: m["softwareRule"]["identities"].reverse()),
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
        r = check_single(request_digest(req), "javascript", None, Msg(stamped(req, js_response()), "r"))
        self.assertEqual(r.provider, "docker")
        self.assertEqual(r.sha256, record_digest(r))

    def test_tampering_is_a_mismatch(self) -> None:
        req = js_request()
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

        def unanswered_stated(_, s):
            s["record"]["unanswered"] = "unknown"  # an answered call's record names no code

        def instance_changed(_, s):
            s["instance"] = "k8s-pod-uid:another"

        for tamper in (code_changed, output_changed, provider_changed, tier_changed, environment_changed, time_changed, digest_changed, unanswered_stated, instance_changed):
            with self.subTest(tamper.__name__):
                q, s = copy.deepcopy(req), copy.deepcopy(good)
                tamper(q, s)
                with self.assertRaises(RecordMismatchError):
                    check_single(request_digest(q), "javascript", None, Msg(s, "r"))

    def test_a_single_run_claiming_a_session_is_a_mismatch(self) -> None:
        req = js_request()
        s = stamped(req, js_response())
        rec = Msg(s["record"], "r")
        from plimsoll_client._record import record_from_wire

        r = record_from_wire(rec)
        r = RunRecord(**{**r.__dict__, "sequence": 1})
        r = RunRecord(**{**r.__dict__, "sha256": record_digest(r)})
        s["record"] = wire_record(r)
        check(request_digest(req), "javascript", None, Msg(s, "r"))  # a session call's check accepts it
        with self.assertRaises(RecordMismatchError):
            check_single(request_digest(req), "javascript", None, Msg(s, "r"))

    def test_no_record_and_versions(self) -> None:
        req = js_request()
        with self.assertRaises(NoRecordError):
            check_single(request_digest(req), "javascript", None, Msg(js_response(), "r"))
        future = stamped(req, js_response())
        future["record"]["version"] = VERSION + 1
        with self.assertRaises(RecordVersionError):
            check_single(request_digest(req), "javascript", None, Msg(future, "r"))

    def test_earlier_versions_are_refused(self) -> None:
        req = js_request()
        for v in (1, 2, 3, 4, 5):
            with self.subTest(v):
                resp = stamped(req, js_response())
                r = record_from_wire(Msg(resp["record"], "r"))
                r = RunRecord(**{**r.__dict__, "version": v})
                resp["record"] = wire_record(RunRecord(**{**r.__dict__, "sha256": record_digest(r)}))
                with self.assertRaises(RecordVersionError):
                    check_single(request_digest(req), "javascript", None, Msg(resp, "r"))

    def test_instance_is_bound_to_the_response_and_typed(self) -> None:
        req = js_request()
        resp = js_response()
        resp["instance"] = "k8s-pod-uid:7f3e9c2a-5b1d-4e8f-9a0c-2d6b8e4f1a37"
        self.assertEqual(result_digest(Msg(resp, "r")), result_digest(Msg(js_response(), "r")))
        good = stamped(req, resp)
        self.assertEqual(check_single(request_digest(req), "javascript", None, Msg(good, "r")).instance, resp["instance"])
        bad = stamped(req, {**resp, "instance": "/var/run/pod"})
        with self.assertRaises(RecordMismatchError):
            check_single(request_digest(req), "javascript", None, Msg(bad, "r"))
        for s in ("", "k8s-pod-uid:a-b", "x:y"):
            self.assertTrue(valid_instance(s), s)
        for s in ("k8s-pod-uid:", "K8S:x", "a/b:c", "no-colon", "k8s-pod-uid:a/b"):
            self.assertFalse(valid_instance(s), s)

    def test_software_rule_binds_record_request_and_response(self) -> None:
        ident = APPROVED[0]
        rule = SoftwareRule.exact(ident)
        req = {"protocol": 4, "softwareRule": {"mode": "exact", "identities": [ident]}, "javascript": {"code": "1"}}
        resp = {"sandbox": "docker", "isolation": "kernel", "environment": "docker-image:sha256:outer",
                "softwareIdentity": ident, "javascript": {}}
        good = stamped(req, resp, rule)
        check_single(request_digest(req), "javascript", rule, Msg(good, "r"))
        tampered = copy.deepcopy(good)
        tampered["softwareIdentity"] = ""
        with self.assertRaises(RecordMismatchError):
            check_single(request_digest(req), "javascript", rule, Msg(tampered, "r"))
        with self.assertRaises(RecordMismatchError):  # the rule the caller holds differs from the record's
            check_single(request_digest(req), "javascript", SoftwareRule.exact(APPROVED[1]), Msg(good, "r"))


if __name__ == "__main__":
    unittest.main()


class KindAndTimes(unittest.TestCase):
    """The record check itself refuses a result of another kind than the request's, or
    none, and a record that ends before it starts, as Go's record.check does since
    2026-10-26: in a session that is before the chain moves on."""

    def test_a_result_of_another_kind_or_none_is_refused(self) -> None:
        req = js_request()
        good = stamped(req, js_response())
        with self.assertRaises(ResultKindMismatchError):
            check_single(request_digest(req), "project", None, Msg(good, "r"))
        none = copy.deepcopy(good)
        del none["javascript"]
        with self.assertRaises(ResultKindMismatchError):
            check_single(request_digest(req), "javascript", None, Msg(none, "r"))

    def test_a_record_that_ends_before_it_starts_is_refused(self) -> None:
        req = js_request()
        s = stamped(req, js_response())
        s["record"]["endedUnixMs"] = str(int(s["record"]["startedUnixMs"]) - 1)
        with self.assertRaises(RecordMismatchError):
            check_single(request_digest(req), "javascript", None, Msg(s, "r"))


def _sealed(**fields: object) -> RunRecord:
    """A record of the given fields over the golden one, its own digest recomputed."""
    r = RunRecord(**{**golden_record().__dict__, **fields})
    return RunRecord(**{**r.__dict__, "sha256": record_digest(r)})


class PerVersionKinds(unittest.TestCase):
    # Finding release-85: which calls a record version records, as Go's record.statesOnly
    # holds it (record.published's answered and unanswered flags): versions 1 and 2 record
    # answered calls only, version 3 unanswered session calls only.
    def test_a_version_records_only_its_kinds_of_call(self) -> None:
        v3_fields = {"instance": "", "isolation_qualification": "", "warm": False, "daemon_version": ""}
        answered_v3 = _sealed(version=3, unanswered="", **v3_fields)
        with self.assertRaisesRegex(RecordMismatchError, "a version 3 record records only an unanswered call"):
            _states_only(answered_v3)
        _states_only(_sealed(version=3, unanswered="unavailable", result_sha256="", **v3_fields))
        unanswered_v2 = _sealed(version=2, unanswered="unavailable", result_sha256="", **v3_fields)
        with self.assertRaisesRegex(RecordMismatchError, "a version 2 record cannot record an unanswered call"):
            _states_only(unanswered_v2)
        _states_only(_sealed(version=2, **v3_fields))
        self.assertEqual(states_only_says(_sealed(unanswered="unavailable", result_sha256="")), "accept", "version 5 records both")


class WholeDecimals(unittest.TestCase):
    # Finding release-90 and Go's record.UnmarshalJSON: an integer written in a string is an
    # optional minus and decimal digits with no leading zero; anything else is refused when
    # read, never read from its leading digits.
    def test_an_integer_string_is_one_whole_decimal(self) -> None:
        int64 = (-(1 << 63), (1 << 63) - 1)
        for text in ("5 6", "5,", "5\x00", "5.0", "5e0", "05", "-05", " 5", "5 ", "+5", "٥", "5_0", ""):
            with self.subTest(text=text), self.assertRaises(PlimsollError):
                Msg({"startedUnixMs": text}, "record").get_int("startedUnixMs", int64)
        for text, n in (("0", 0), ("-0", 0), ("5", 5), ("-12", -12), ("1790000000000", 1790000000000)):
            with self.subTest(text=text):
                self.assertEqual(Msg({"startedUnixMs": text}, "record").get_int("startedUnixMs", int64), n)


class LostAnswer(unittest.TestCase):
    # record.CheckLostAnswer's rules, on check_lost_answer: the attach liar's forgeries
    # (tests/test_reattach.py) drive the same checks through a whole attach.
    def setUp(self) -> None:
        self.resp = stamped(js_request(), js_response())
        self.lost = record_from_wire(Msg(self.resp["record"], "record"))

    def test_the_honest_answer_checks(self) -> None:
        self.assertEqual(check_lost_answer(Msg(self.resp, "lostAnswer"), self.lost), self.lost)

    def test_each_forged_answer_is_refused(self) -> None:
        def output(s: dict) -> None:
            s["javascript"]["stdout"] = b64(b"forged\n")

        def no_record(s: dict) -> None:
            del s["record"]

        def other_record(s: dict) -> None:
            s["record"]["endedUnixMs"] = str(int(s["record"]["endedUnixMs"]) + 1)

        def two_results(s: dict) -> None:
            s["cell"] = {"exitCode": 0}

        def evidence(s: dict) -> None:
            s["instance"] = "k8s-pod-uid:0d7f1c52-2d4c-4f1e-9a4b-3c2f6e1d8a90"

        for name, forge in (("output", output), ("no record", no_record), ("another record", other_record),
                            ("two results", two_results), ("other evidence", evidence)):
            with self.subTest(name):
                s = copy.deepcopy(self.resp)
                forge(s)
                with self.assertRaises(PlimsollError):
                    check_lost_answer(Msg(s, "lostAnswer"), self.lost)

    def test_an_answer_for_an_unanswered_record_or_a_module_is_refused(self) -> None:
        unanswered = RunRecord(**{**self.lost.__dict__, "unanswered": "unavailable", "result_sha256": ""})
        with self.assertRaisesRegex(RecordMismatchError, "ended unanswered"):
            check_lost_answer(Msg({**self.resp, "record": wire_record(unanswered)}, "lostAnswer"), unanswered)
        module = stamped(js_request(), module_response())
        with self.assertRaisesRegex(RecordMismatchError, "session call's kind"):
            check_lost_answer(Msg(module, "lostAnswer"), record_from_wire(Msg(module["record"], "record")))


def golden_named(name: str) -> dict:
    for kind in ("requests", "results"):
        for v in GOLDEN[kind]:
            if v["name"] == name:
                return copy.deepcopy(v["request"] if kind == "requests" else v["response"])
    raise KeyError(name)


class RecordVersion6(unittest.TestCase):
    # Record version 6 and protocol 9 (docs/run-records.md): the record's version fixes the
    # result domain, and the files kind is in both new domains.

    def test_a_version_6_record_of_a_result_hashed_under_v1_is_refused(self) -> None:
        req, resp = js_request(), js_response()
        v1, v2 = result_digest(Msg(resp, "r"), 5), result_digest(Msg(resp, "r"), 6)
        self.assertNotEqual(v1, v2)
        self.assertEqual(result_digest(Msg(resp, "r")), v2)
        good = stamped(req, resp)
        check_single(request_digest(req), "javascript", None, Msg(good, "r"))
        forged = copy.deepcopy(good)
        r = record_from_wire(Msg(forged["record"], "record"))
        r = RunRecord(**{**r.__dict__, "result_sha256": v1})
        r = RunRecord(**{**r.__dict__, "sha256": record_digest(r)})
        forged["record"] = wire_record(r)
        with self.assertRaises(RecordMismatchError):
            check_single(request_digest(req), "javascript", None, Msg(forged, "r"))

    def test_a_live_version_5_record_is_refused_as_a_version(self) -> None:
        req, resp = js_request(), js_response()
        good = stamped(req, resp)
        r = record_from_wire(Msg(good["record"], "record"))
        r = RunRecord(**{**r.__dict__, "version": 5, "result_sha256": result_digest(Msg(resp, "r"), 5)})
        r = RunRecord(**{**r.__dict__, "sha256": record_digest(r)})
        old = dict(good, record=wire_record(r))
        with self.assertRaises(RecordVersionError):
            check_single(request_digest(req), "javascript", None, Msg(old, "r"))

    def test_every_file_call_checks_as_a_session_call(self) -> None:
        for op in ("stat", "read", "write", "list", "read_many", "make_dir", "remove", "rename"):
            with self.subTest(op):
                req = golden_named("files " + op + " request")
                resp = golden_named("files " + op + " result")
                self.assertEqual(req["protocol"], 9)
                answer = stamped(req, resp)
                self.assertEqual(files_op(Msg(req["files"], "files")), op)
                r = check(request_digest(req), "files", None, Msg(answer, "r"), op)
                self.assertEqual(r.result_sha256, result_digest(Msg(resp, "r"), 6))
                check_lost_answer(Msg(answer, "r"), r)
                # The answer of another kind than the request's is refused, and so is the
                # answer of another operation, or of one the caller did not name.
                with self.assertRaises(PlimsollError):
                    check(request_digest(req), "project", None, Msg(answer, "r"))
                for other in ("", "remove" if op != "remove" else "stat"):
                    with self.assertRaises(RecordMismatchError):
                        check(request_digest(req), "files", None, Msg(answer, "r"), other)

    def test_a_files_payload_is_no_kind_before_its_domains(self) -> None:
        req = golden_named("files request stating protocol 8")
        empty = {k: v for k, v in req.items() if k != "files"}
        self.assertEqual(request_digest(req), request_digest(empty))
        at9 = dict(req, protocol=9)
        self.assertNotEqual(request_digest(at9), request_digest(dict(empty, protocol=9)))
        resp = golden_named("files stat result")
        none = {k: v for k, v in resp.items() if k != "files"}
        self.assertEqual(result_digest(Msg(resp, "r"), 5), result_digest(Msg(none, "r"), 5))
        self.assertNotEqual(result_digest(Msg(resp, "r"), 6), result_digest(Msg(none, "r"), 6))
