"""Record version 6 golden vectors, computed from docs/run-records.md.

A second implementation in Python, written from the page alone: the layouts below are its
"Record" section, and request_digest and result_digest its "Request" and "Result" sections,
read from the proto3 JSON form of each message. Run from the repository's root:
python3 record/testdata/record_v6.py
First it reproduces every request, result and record vector v0.29.0, v0.27.1 and v0.22.0
published (record/testdata/published, never edited; record versions 2 to 5), and every
version 1 record v0.11.1 signed in its bundle; then it computes the version 6 vectors
(protocol 9 requests under plimsoll.run-request.v3, results under plimsoll.run-result.v2,
the files kind in both), the refused cases, the qualification sentences each reader must
accept or refuse and the tier comparison table, and writes them into
record/testdata/golden.json. It replaces record_v5.py, which wrote version 5's on
2026-11-17; version 5's vectors are now the frozen copy of v0.29.0's file.
"""
import base64, hashlib, json, struct, sys

V5 = ["request_sha256", "result_sha256", "unanswered", "provider", "isolation",
      "isolation_qualification", "environment", "policy", "software_identity",
      "software_rule_id", "instance", "warm", "daemon_version", "started_unix_ms",
      "ended_unix_ms", "session", "sequence", "previous_sha256"]
LAYOUTS = {
    1: ["request_sha256", "result_sha256", "provider", "isolation", "environment", "policy",
        "started_unix_ms", "ended_unix_ms", "session", "sequence", "previous_sha256"],
    2: ["request_sha256", "result_sha256", "provider", "isolation", "environment", "policy",
        "software_identity", "software_rule_id", "started_unix_ms", "ended_unix_ms", "session",
        "sequence", "previous_sha256"],
    3: ["request_sha256", "result_sha256", "unanswered", "provider", "isolation", "environment",
        "policy", "software_identity", "software_rule_id", "started_unix_ms", "ended_unix_ms",
        "session", "sequence", "previous_sha256"],
    4: ["request_sha256", "result_sha256", "unanswered", "provider", "isolation", "environment",
        "policy", "software_identity", "software_rule_id", "instance", "started_unix_ms",
        "ended_unix_ms", "session", "sequence", "previous_sha256"],
    5: V5,
    6: V5,  # the same fields; its results are hashed under plimsoll.run-result.v2
}


def camel(name):
    head, *rest = name.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def encode(field, rec):
    v = rec.get(camel(field))
    if field == "warm":
        return b"true" if v else b"false"
    if field in ("started_unix_ms", "ended_unix_ms", "sequence"):
        return str(int(v or 0)).encode()
    return (v or "").encode("utf-8")


class Enc:
    """A digest: SHA-256 over the domain, then each field's name and content, every value
    preceded by its length as an unsigned 64-bit big-endian integer."""

    def __init__(self, domain):
        self.h = hashlib.sha256()
        self.value(domain.encode())

    def value(self, b):
        self.h.update(struct.pack(">Q", len(b)))
        self.h.update(b)

    def put(self, name, b):
        self.value(name.encode())
        self.value(b)

    def s(self, name, v):  # a string: its UTF-8 bytes
        self.put(name, (v or "").encode("utf-8"))

    def b(self, name, v):  # bytes: base64 in proto3 JSON, the raw bytes here
        self.put(name, base64.b64decode(v or ""))

    def i(self, name, v):  # an integer: decimal ASCII (proto3 JSON writes 64-bit ones as strings)
        self.put(name, str(int(v or 0)).encode())

    def t(self, name, v):  # a boolean
        self.put(name, b"true" if v else b"false")

    def f(self, name, vs):  # floats: each IEEE 754 binary64, big-endian
        self.put(name, b"".join(struct.pack(">d", float(v)) for v in vs))

    def hex(self):
        return self.h.hexdigest()


def digest(rec):
    version = int(rec["version"])
    e = Enc("plimsoll.run-record.v%d" % version)
    for f in LAYOUTS[version]:
        e.put(f, encode(f, rec))
    return e.hex()


# The enums a digest covers by number, from proto/plimsoll/v1/sandbox.proto.
OUTCOME = {"PROJECT_OUTCOME_" + n: i for i, n in enumerate(
    ["UNSPECIFIED", "COMPLETED", "SETUP_FAILED", "TIMED_OUT", "PROTOCOL_ERROR", "RUNNER_FAILED"])}
SCOPE = {"FILES_SCOPE_" + n: i for i, n in enumerate(["UNSPECIFIED", "WORK", "SANDBOX"])}
WRITE_MODE = {"FILES_WRITE_MODE_" + n: i for i, n in enumerate(["UNSPECIFIED", "REPLACE", "CREATE_ONLY", "APPEND"])}
ERROR = {"FILES_ERROR_" + n: i for i, n in enumerate(
    ["UNSPECIFIED", "NOT_FOUND", "IS_DIR", "NOT_DIR", "EXISTS", "SYMLINK", "NOT_REGULAR", "PERMISSION_DENIED",
     "TOO_LARGE", "NO_SPACE", "READ_ONLY", "NOT_EMPTY", "SCAN_LIMIT", "OTHER"])}
ENTRY_TYPE = {"FILES_ENTRY_TYPE_" + n: i for i, n in enumerate(["UNSPECIFIED", "FILE", "DIR", "LINK", "OTHER"])}


def enum(table, v):
    return table[v] if isinstance(v, str) else int(v or 0)


def request_domain(protocol):
    if protocol < 2:
        return "plimsoll.run-request.v1"
    if protocol < 9:
        return "plimsoll.run-request.v2"
    return "plimsoll.run-request.v3"


def request_digest(req):
    """The "Request" section: protocol, floor, timeout, the software rule (from protocol 2),
    then the kind and its fields. The trace ID and the session ID are left out."""
    protocol = int(req.get("protocol", 0))
    domain = request_domain(protocol)
    e = Enc(domain)
    e.i("protocol", protocol)
    e.s("minimum_isolation", req.get("minimumIsolation"))
    e.i("timeout_ms", req.get("timeoutMs"))
    if domain != "plimsoll.run-request.v1":
        rule = req.get("softwareRule") or {}
        e.s("software_mode", rule.get("mode"))
        ids = rule.get("identities") or []
        e.i("software_identities", len(ids))
        for x in ids:
            e.s("software_identity", x)

    def files(fs):
        e.i("files", len(fs or []))
        for f in fs or []:
            e.s("file_path", f.get("path"))
            e.s("file_content", f.get("content"))

    if "javascript" in req:
        j = req["javascript"]
        e.s("kind", "javascript")
        e.s("code", j.get("code"))
        e.s("grant_profile", j.get("grantProfile"))
    elif "project" in req:
        p = req["project"]
        e.s("kind", "project")
        e.s("grant_profile", p.get("grantProfile"))
        files(p.get("files"))
        e.i("steps", len(p.get("steps") or []))
        for st in p.get("steps") or []:
            e.s("step_command", st)
        e.i("artifacts", len(p.get("artifacts") or []))
        for a in p.get("artifacts") or []:
            e.s("artifact_path", a)
    elif "module" in req:
        m = req["module"]
        e.s("kind", "module")
        e.s("model", m.get("model"))
        e.f("end_time", [m.get("endTime", 0)])
        e.f("step", [m.get("step", 0)])
        e.i("rows", len(m.get("rows") or []))
        for r in m.get("rows") or []:
            e.f("row_values", r.get("values") or [])
    elif "cell" in req:
        c = req["cell"]
        e.s("kind", "cell")
        e.s("language", c.get("language"))
        e.s("code", c.get("code"))
        files(c.get("files"))
    elif "files" in req and domain == "plimsoll.run-request.v3":
        f = req["files"]
        e.s("kind", "files")
        e.i("scope", enum(SCOPE, f.get("scope")))
        if "stat" in f:
            e.s("op", "stat")
            e.b("path", f["stat"].get("path"))
        elif "read" in f:
            o = f["read"]
            e.s("op", "read")
            e.b("path", o.get("path"))
            e.i("offset", o.get("offset"))
            e.i("max_bytes", o.get("maxBytes"))
        elif "write" in f:
            o = f["write"]
            e.s("op", "write")
            e.b("path", o.get("path"))
            e.b("content", o.get("content"))
            e.i("write_mode", enum(WRITE_MODE, o.get("mode")))
            e.t("make_parents", o.get("makeParents"))
        elif "list" in f:
            o = f["list"]
            e.s("op", "list")
            e.b("path", o.get("path"))
            e.t("recursive", o.get("recursive"))
            e.b("match", o.get("match"))
            e.b("after", o.get("after"))
            e.i("budget_bytes", o.get("budgetBytes"))
        elif "readMany" in f:
            o = f["readMany"]
            e.s("op", "read_many")
            e.i("paths", len(o.get("paths") or []))
            for x in o.get("paths") or []:
                e.b("path", x)
            e.i("max_bytes_each", o.get("maxBytesEach"))
            e.i("budget_bytes", o.get("budgetBytes"))
        elif "makeDir" in f:
            e.s("op", "make_dir")
            e.b("path", f["makeDir"].get("path"))
            e.t("parents", f["makeDir"].get("parents"))
        elif "remove" in f:
            e.s("op", "remove")
            e.b("path", f["remove"].get("path"))
            e.t("dir", f["remove"].get("dir"))
        elif "rename" in f:
            o = f["rename"]
            e.s("op", "rename")
            e.b("from_path", o.get("fromPath"))
            e.b("to_path", o.get("toPath"))
            e.t("replace", o.get("replace"))
        else:
            e.s("op", "")
    else:
        e.s("kind", "")
    return e.hex()


def result_digest(resp, version):
    """The "Result" section, under the result domain the record version fixes: v1 for
    versions 1 to 5, v2 (which adds the files kind) from version 6."""
    v2 = version >= 6
    e = Enc("plimsoll.run-result.v2" if v2 else "plimsoll.run-result.v1")

    def output(o):
        e.i("exit_code", o.get("exitCode"))
        e.t("timed_out", o.get("timedOut"))
        e.b("stdout", o.get("stdout"))
        e.b("stderr", o.get("stderr"))
        e.t("stdout_truncated", o.get("stdoutTruncated"))
        e.t("stderr_truncated", o.get("stderrTruncated"))

    if "javascript" in resp:
        e.s("kind", "javascript")
        output(resp["javascript"])
    elif "project" in resp:
        p = resp["project"]
        e.s("kind", "project")
        e.i("outcome", enum(OUTCOME, p.get("outcome")))
        e.s("outcome_detail", p.get("outcomeDetail"))
        e.t("artifacts_truncated", p.get("artifactsTruncated"))
        e.i("steps", len(p.get("steps") or []))
        for st in p.get("steps") or []:
            e.s("step_command", st.get("command"))
            e.i("step_exit_code", st.get("exitCode"))
            e.t("step_timed_out", st.get("timedOut"))
            e.b("step_stdout", st.get("stdout"))
            e.b("step_stderr", st.get("stderr"))
            e.t("step_stdout_truncated", st.get("stdoutTruncated"))
            e.t("step_stderr_truncated", st.get("stderrTruncated"))
        e.i("artifacts", len(p.get("artifacts") or []))
        for a in p.get("artifacts") or []:
            e.s("artifact_path", a.get("path"))
            e.b("artifact_content", a.get("content"))
    elif "module" in resp:
        m = resp["module"]
        e.s("kind", "module")
        e.i("outcome", enum(OUTCOME, m.get("outcome")))
        e.s("outcome_detail", m.get("outcomeDetail"))
        e.i("width", m.get("width"))
        e.b("stdout", m.get("stdout"))
        e.b("stderr", m.get("stderr"))
        e.i("runs", len(m.get("runs") or []))
        for r in m.get("runs") or []:
            e.i("run_status", r.get("status"))
            e.f("run_outputs", r.get("outputs") or [])
    elif "cell" in resp:
        c = resp["cell"]
        e.s("kind", "cell")
        output(c)
        e.t("interpreter_started", c.get("interpreterStarted"))
        e.t("interpreter_ended", c.get("interpreterEnded"))
    elif "files" in resp and v2:
        f = resp["files"]
        e.s("kind", "files")
        e.i("outcome", enum(OUTCOME, f.get("outcome")))
        e.i("error", enum(ERROR, f.get("error")))
        e.s("errno", f.get("errno"))
        if "stat" in f:
            o = f["stat"]
            e.s("op", "stat")
            e.i("type", enum(ENTRY_TYPE, o.get("type")))
            e.i("size", o.get("size"))
            e.i("mode", o.get("mode"))
        elif "read" in f:
            e.s("op", "read")
            e.b("content", f["read"].get("content"))
            e.i("size_at_open", f["read"].get("sizeAtOpen"))
        elif "write" in f:
            e.s("op", "write")
            e.i("written", f["write"].get("written"))
        elif "list" in f:
            o = f["list"]
            e.s("op", "list")
            e.i("entries", len(o.get("entries") or []))
            for en in o.get("entries") or []:
                e.b("entry_path", en.get("path"))
                e.i("entry_type", enum(ENTRY_TYPE, en.get("type")))
                e.i("entry_size", en.get("size"))
            e.t("more", o.get("more"))
        elif "readMany" in f:
            o = f["readMany"]
            e.s("op", "read_many")
            e.i("items", len(o.get("items") or []))
            for it in o.get("items") or []:
                e.i("item_error", enum(ERROR, it.get("error")))
                e.s("item_errno", it.get("errno"))
                e.b("item_content", it.get("content"))
                e.i("item_size_at_open", it.get("sizeAtOpen"))
            e.t("more", o.get("more"))
        elif "makeDir" in f:
            e.s("op", "make_dir")
        elif "remove" in f:
            e.s("op", "remove")
        elif "rename" in f:
            e.s("op", "rename")
        else:
            e.s("op", "")
    else:
        e.s("kind", "")
    return e.hex()


def session_fingerprint(sid):
    return hashlib.sha256(sid.encode()).hexdigest()


def reproduce(path):
    """Every vector a release published. A result vector names the record version whose
    result domain hashed it (recordVersion); one without it is from a file written before
    version 6, whose results are all plimsoll.run-result.v1."""
    g = json.load(open(path))
    for r in g["requests"]:
        if request_digest(r["request"]) != r["sha256"]:
            sys.exit("%s: %s: request %s, published %s" % (path, r["name"], request_digest(r["request"]), r["sha256"]))
    for r in g["results"]:
        got = result_digest(r["response"], r.get("recordVersion", 5))
        if got != r["sha256"]:
            sys.exit("%s: %s: result %s, published %s" % (path, r["name"], got, r["sha256"]))
    for r in g["records"]:
        if digest(r["record"]) != r["sha256"]:
            sys.exit("%s: %s: %s, published %s" % (path, r["name"], digest(r["record"]), r["sha256"]))
    for r in g["sessionFingerprints"]:
        if session_fingerprint(r["sessionId"]) != r["sha256"]:
            sys.exit("%s: %s: the session fingerprint differs" % (path, r["name"]))
    return sum(len(g[k]) for k in ("requests", "results", "records", "sessionFingerprints"))


n = sum(reproduce("record/testdata/published/%s-golden.json" % v) for v in ("v0.29.0", "v0.27.1", "v0.22.0"))
print("reproduced", n, "published vectors")


def signed_records(path):
    """The records a release's bundle signed: each record line's envelope states its record and, as
    the statement's subject, the digest the release computed for it. The record is in the
    signed form (snake_case names, numbers as JSON numbers); it is returned in the wire form
    the other vectors use."""
    out = []
    for line in open(path):
        statement = json.loads(base64.b64decode(json.loads(line)["envelope"]["payload"]))
        if not statement["predicateType"].endswith("/run-record/v1"):
            continue  # the session's close
        p = statement["predicate"]
        rec = {"version": p["version"]}
        for f in LAYOUTS[p["version"]]:
            v = p.get(f, "")
            rec[camel(f)] = str(v) if f in ("started_unix_ms", "ended_unix_ms", "sequence") else v
        sha = statement["subject"][0]["digest"]["sha256"]
        if digest(rec) != sha or p.get("record_sha256") != sha:
            sys.exit("%s: a version %d record digests to %s, the release signed %s" % (path, p["version"], digest(rec), sha))
        out.append((rec, sha))
    return out


# v0.11.1 signed version 1 records only: its bundle is the one release-made source of them.
V1 = signed_records("attest/testdata/published/v0.11.1-sessions/bundle.jsonl")
print("reproduced", len(V1), "version 1 records v0.11.1 signed")

PER_RUN = ("Hyper-V VM per run (one WSLC session per run). Microsoft states that WSL is not a "
           "security sandbox for running untrusted code; the VM wall is Hyper-V's, and the Windows "
           "components around it (network relay, shares, interop) run with the user's rights.")
SESSION = "5947d7c33d783f94b3b4c1a96ebc8991ed28f1b069b71e03376cba8caa98a720"
base = {
    "requestSha256": "894bec2baf1b52612c2f060ba2aa9080273294e737bae5f3a65ff661b50481d0",
    "resultSha256": "bfb9756e0d38ac39c7ffd523278e5c32b63c5db76ec5162b7d1ffbe363d0ad6f",
    "provider": "openshell", "isolation": "container",
    "environment": "openshell-image:sha256:ab", "policy": "openshell-policy:sha256:cd",
    "startedUnixMs": "1790000000000", "endedUnixMs": "1790000004210",
    "session": SESSION, "sequence": "2",
    "previousSha256": "0000000000000000000000000000000000000000000000000000000000000001",
}
records = [
    ("record", dict(base, version=6, instance="k8s-pod-uid:7f3e9c2a-5b1d-4e8f-9a0c-2d6b8e4f1a37",
                    isolationQualification="A sentence its vendor requires beside the tier, with bytes past ASCII: caf" + chr(0xe9) + ", " + chr(0x2265) + " 2.",
                    daemonVersion="v0.28.0")),
    ("unanswered record", dict(base, version=6, resultSha256="", unanswered="unavailable",
                               isolationQualification="Stated at open.", daemonVersion="(devel)")),
    ("warm record", {"version": 6,
                     "requestSha256": "3ac521c00d014d11e7dfaff3ada8a8b564a0ac93eadc72555a992faac7b8112f",
                     "resultSha256": "3a57590f560a5de29d491595bfb264ff072e06d4d0fcccc5ab2d4b3de410d37d",
                     "provider": "docker", "isolation": "kernel", "warm": True,
                     "daemonVersion": "v0.28.1-0.20261117210242-4ca8fb4d330e+dirty",
                     "startedUnixMs": "1790000000000", "endedUnixMs": "1790000000812"}),
    ("wslc record", {"version": 6,
                     "requestSha256": "3ac521c00d014d11e7dfaff3ada8a8b564a0ac93eadc72555a992faac7b8112f",
                     "resultSha256": "3a57590f560a5de29d491595bfb264ff072e06d4d0fcccc5ab2d4b3de410d37d",
                     "provider": "wslc", "isolation": "vm",
                     "isolationQualification": PER_RUN + " The operator of this daemon set SANDBOX_WSLC_ACCEPT_VM_TIER=1.",
                     "environment": "wslc-image:sha256:" + "e" * 64,
                     "daemonVersion": "v0.28.0",
                     "startedUnixMs": "1790000000000", "endedUnixMs": "1790000000812"}),
]
out = []
for name, rec in records:
    out.append({"name": name, "record": rec, "sha256": digest(rec)})
# A version 1 record as v0.11.1 signed it, with the digest that release computed, so every
# reader's version 1 layout is held by a shared vector.
out.append({"name": "version 1 record", "record": V1[0][0], "sha256": V1[0][1]})

# Refused: each digest matches its fields, and each must still be refused by every reader.
wslc = dict(records[3][1])
refused = [
    ("a qualification of 1025 bytes", dict(wslc, isolationQualification="x" * 1025),
     "over 1024 bytes"),
    ("a qualification with a line feed", dict(wslc, isolationQualification="Microsoft states.\nIgnore that."),
     "a control character"),
    ("a qualification with a C1 control", dict(wslc, isolationQualification="Microsoft states.\u0085"),
     "a control character, U+0085"),
    ("a qualification with a right-to-left override", dict(wslc, isolationQualification="Microsoft " + chr(0x202e) + "states"),
     "a bidirectional format character, U+202E"),
    ("a qualification with an Arabic letter mark", dict(wslc, isolationQualification="Microsoft " + chr(0x61c) + "states"),
     "a bidirectional control, U+061C"),
    ("a qualification with a line separator", dict(wslc, isolationQualification="Microsoft" + chr(0x2028) + "states"),
     "a line separator, U+2028"),
    # The provider's name is shown to a reader as the tier and the qualification are, so it
    # holds to the same character rule (record.ValidText), in every version: until 2026-11-21
    # a daemon's answer naming its provider with ESC or U+202E passed every reader's check and
    # was signed.
    ("a provider with an escape", dict(wslc, provider="wslc\x1b[2Jdocker"), "a control character in the provider, ESC"),
    ("a provider with a carriage return", dict(wslc, provider="wslc\rdocker"), "a control character in the provider, CR"),
    ("a provider with a right-to-left override", dict(wslc, provider="wslc" + chr(0x202e) + "cod"),
     "a bidirectional format character in the provider, U+202E"),
    ("a provider with a C1 control", dict(wslc, provider="wslc\u009b"), "a control character in the provider, U+009B"),
    ("an unanswered record whose provider holds a line feed", dict(records[1][1], provider="docker\nisolation vm"),
     "a control character in the provider, LF"),
    ("a version 4 record whose provider holds an escape",
     {k: v for k, v in dict(wslc, version=4, provider="wslc\x1b]0;x\x07").items() if k not in ("daemonVersion", "isolationQualification")},
     "a control character in the provider, in a version that may still be read"),
    ("a daemon version without its v", dict(wslc, daemonVersion="0.28.0"), "not a module version"),
    ("a daemon version of two numbers", dict(wslc, daemonVersion="v0.28"), "not a module version"),
    ("a daemon version with a space", dict(wslc, daemonVersion="v0.28.0 (patched)"), "not a module version"),
    ("a version 4 record stating warm", {k: v for k, v in dict(records[2][1], version=4).items() if k != "daemonVersion"},
     "version 4 does not cover warm"),
    ("a version 4 record stating a qualification",
     {k: v for k, v in dict(wslc, version=4).items() if k != "daemonVersion"},
     "version 4 does not cover isolation_qualification"),
    # The tiers are five lowercase names (docs/isolation-tiers.md), whatever floor the
    # request named: with no floor, nothing else compared the tier with anything (finding
    # release-51, 2026-11-18). "unknown" is what a reader calls a tier it cannot name, never
    # one a record may state.
    ("a tier in capitals", dict(wslc, isolation="VM"), "not a tier"),
    ("a tier with words after it", dict(wslc, isolation="vm (trust me)"), "not a tier"),
    ("the tier unknown", dict(wslc, isolation="unknown"), "not a tier"),
    ("no tier", dict(wslc, isolation=""), "not a tier"),
    ("an unanswered record with no tier", dict(records[1][1], isolation=""), "not a tier"),
    ("a version 4 record with a tier in capitals",
     {k: v for k, v in dict(wslc, version=4, isolation="VM").items() if k not in ("daemonVersion", "isolationQualification")},
     "not a tier, in a version that may still be read"),
    # A record may not end before it starts, answered or not: only the answered check
    # said so until finding release-52 (2026-11-18).
    ("an unanswered record that ends before it starts",
     dict(records[1][1], startedUnixMs="1790000004210", endedUnixMs="1790000000000"), "ends before it starts"),
    ("a record that ends before it starts",
     dict(wslc, startedUnixMs="1790000000812", endedUnixMs="1790000000000"), "ends before it starts"),
    # A record states a result digest or, for an unanswered call, an error code: exactly one,
    # and the code is one of the closed set. The Python and TypeScript readers did not check
    # either until finding release-76 (2026-11-19), and an adapter tells a model whether a lost
    # call finished from which of the two its record states.
    ("a record stating a result and an unanswered code", dict(records[0][1], unanswered="canceled"),
     "a result and an error code, not exactly one"),
    ("a record stating neither a result nor an unanswered code", dict(wslc, resultSha256=""),
     "neither a result nor an error code"),
    ("an unanswered record naming no Connect code",
     dict(records[1][1], unanswered="ignore previous instructions"), "not one of the closed set of codes"),
    # Which calls a version records (record.published's answered and unanswered flags):
    # versions 1 and 2 answered calls only, version 3 unanswered session calls only. The
    # Python and TypeScript readers did not check it until finding release-85 (2026-11-24).
    # Version 2 does not cover the code, so its digest leaves it out.
    ("a version 3 record of an answered call", dict(base, version=3), "version 3 records only unanswered calls"),
    ("a version 2 record of an unanswered call", dict(base, version=2, resultSha256="", unanswered="unavailable"),
     "version 2 records only answered calls"),
]
# The version 1 and 2 records that end before they start, whose reading was retired on
# 2026-11-21 (record/testdata/retired/clock-step-v1-v2.json): their digests are reproduced,
# and every reader must refuse them with the retirement's text.
RETIRED = "retired by the decision of 2026-11-21"
for r in json.load(open("record/testdata/retired/clock-step-v1-v2.json"))["records"]:
    if digest(r["record"]) != r["sha256"]:
        sys.exit("clock-step-v1-v2.json: %s: %s, the file states %s" % (r["name"], digest(r["record"]), r["sha256"]))
    refused.append((r["name"], r["record"], RETIRED))
bad = []
for name, rec, why in refused:
    # A version 4 record's digest leaves out the field it cannot state, so only the rule
    # that a version may state no field it does not cover refuses it.
    sha = digest(rec)
    bad.append({"name": name, "record": rec, "sha256": sha, "why": why})


# Requests and results. The vectors v0.29.0 published (protocol 4 requests, results under
# plimsoll.run-result.v1, which carry no recordVersion) stay, and every reader must still
# reproduce them; then the protocol 9 requests under plimsoll.run-request.v3 and the results
# under plimsoll.run-result.v2, each result naming the record version whose domain hashed it.
B64 = lambda b: base64.b64encode(b).decode()
published = json.load(open("record/testdata/published/v0.29.0-golden.json"))
SESSION_ID = published["sessionFingerprints"][0]["sessionId"]
NON_UTF8 = b"caf\xe9\nlist.txt"  # a name that is not UTF-8 and holds a line feed: paths are bytes


def files_request(name, op, scope="FILES_SCOPE_WORK", protocol=9):
    return {"name": name, "kind": "session", "request": {
        "protocol": protocol, "minimumIsolation": "container", "timeoutMs": 30000, "sessionId": SESSION_ID,
        "files": dict({"scope": scope}, **op)}}


new_requests = [
    {"name": "javascript request, protocol 9", "kind": "run", "request": dict(published["requests"][0]["request"], protocol=9)},
    files_request("files stat request", {"stat": {"path": B64(b"src/main.py")}}),
    files_request("files read request", {"read": {"path": B64(b"data/big.bin"), "offset": "8388608", "maxBytes": 8388608}}),
    files_request("files write request", {"write": {"path": B64(b"/tmp/out/" + NON_UTF8), "content": B64(b"\x00\xff line\n"),
                                                    "mode": "FILES_WRITE_MODE_CREATE_ONLY", "makeParents": True}},
                  scope="FILES_SCOPE_SANDBOX"),
    files_request("files list request", {"list": {"path": B64(b"."), "recursive": True, "match": B64(b"**/*.py"),
                                                  "after": B64(b"src/a.py"), "budgetBytes": 65536}}),
    files_request("files read_many request", {"readMany": {"paths": [B64(b"a.txt"), B64(NON_UTF8), B64(b"b/c.txt")],
                                                           "maxBytesEach": 1024, "budgetBytes": 4096}}),
    files_request("files make_dir request", {"makeDir": {"path": B64(b"out/logs"), "parents": True}}),
    files_request("files remove request", {"remove": {"path": B64(b"old"), "dir": True}}),
    files_request("files rename request", {"rename": {"fromPath": B64(b".tmp-1"), "toPath": B64(b"big.bin"), "replace": True}}),
    # Under plimsoll.run-request.v2 a files payload is no kind: every reader encodes it as the
    # empty kind, and refuses a record of it.
    files_request("files request stating protocol 8", {"stat": {"path": B64(b"src/main.py")}}, protocol=8),
]
for r in new_requests:
    r["sha256"] = request_digest(r["request"])


def files_result(name, files, version=6):
    return {"name": name, "recordVersion": version,
            "response": {"sandbox": "docker", "isolation": "kernel", "durationMs": "12", "files": files}}


DONE = {"outcome": "PROJECT_OUTCOME_COMPLETED"}
new_results = [dict(r, name=r["name"] + ", version 6", recordVersion=6) for r in published["results"]] + [
    files_result("files stat result", dict(DONE, stat={"type": "FILES_ENTRY_TYPE_FILE", "size": "1234", "mode": 420})),
    files_result("files read result", dict(DONE, read={"content": B64(b"\x00\x01\xfe\xff tail"), "sizeAtOpen": "9000000"})),
    files_result("files write result", dict(DONE, write={"written": "8"})),
    files_result("files list result", dict(DONE, list={"entries": [
        {"path": B64(b".hidden"), "type": "FILES_ENTRY_TYPE_FILE", "size": "3"},
        {"path": B64(NON_UTF8), "type": "FILES_ENTRY_TYPE_FILE"},
        {"path": B64(b"src"), "type": "FILES_ENTRY_TYPE_DIR", "size": "4096"},
        {"path": B64(b"src/link"), "type": "FILES_ENTRY_TYPE_LINK", "size": "8"},
    ], "more": True})),
    files_result("files read_many result", dict(DONE, readMany={"items": [
        {"content": B64(b"first\n"), "sizeAtOpen": "6"},
        {"error": "FILES_ERROR_NOT_FOUND", "errno": "ENOENT"},
        {"error": "FILES_ERROR_IS_DIR", "errno": "EISDIR"},
    ], "more": True})),
    files_result("files make_dir result", dict(DONE, makeDir={})),
    files_result("files remove result", dict(DONE, remove={})),
    files_result("files rename result", dict(DONE, rename={})),
    files_result("files error result", dict(DONE, error="FILES_ERROR_SYMLINK", errno="ELOOP")),
    files_result("files timed out result", {"outcome": "PROJECT_OUTCOME_TIMED_OUT"}),
    # Under plimsoll.run-result.v1 a files result is no kind: every reader encodes it as the
    # empty kind, and refuses a record of version 5 or earlier for it.
    files_result("files result under a version 5 record", dict(DONE, stat={"type": "FILES_ENTRY_TYPE_FILE", "size": "1234", "mode": 420}),
                 version=5),
]
for r in new_results:
    r["sha256"] = result_digest(r["response"], r["recordVersion"])


g = json.load(open("record/testdata/golden.json"))
g["requests"] = published["requests"] + new_requests
g["results"] = published["results"] + new_results
g["records"] = out
g["refused"] = bad
# Malformed: a field of the wrong JSON type. No digest is given: a reader refuses to read the record at all, as Go's
# protojson and Python's typed reads do, so none is computed from it.
g["malformed"] = [
    {"name": "warm as the string true", "record": dict(records[2][1], warm="true"), "why": "warm is a JSON boolean"},
    {"name": "warm as the number 1", "record": dict(records[2][1], warm=1), "why": "warm is a JSON boolean"},
    {"name": "a qualification that is a number", "record": dict(wslc, isolationQualification=5), "why": "the sentence is a JSON string"},
    {"name": "a daemon version that is a list", "record": dict(wslc, daemonVersion=["v0.28.0"]), "why": "the daemon version is a JSON string"},
    # A number in a string with text after it: Go's protojson reads each from its leading
    # digits, so a reader must refuse it or read the same value (Go's record.UnmarshalJSON
    # refuses it, as Python's int() and JavaScript's BigInt() do).
    {"name": "a start time with a second number after it", "record": dict(records[2][1], startedUnixMs="1790000000000 1"),
     "why": "an integer in a string is one whole decimal"},
    {"name": "a start time with a comma after it", "record": dict(records[2][1], startedUnixMs="1790000000000,"),
     "why": "an integer in a string is one whole decimal"},
    {"name": "a start time with a zero byte after it", "record": dict(records[2][1], startedUnixMs="1790000000000\u0000"),
     "why": "an integer in a string is one whole decimal"},
    {"name": "a version with a second number after it", "record": dict(records[2][1], version="5 6"),
     "why": "an integer in a string is one whole decimal"},
    # A decimal point or an exponent: protojson reads "5.0" and "5e0" as 5 (outside fact
    # protojson-integer-string-leading-digits), and JavaScript's Number reads both forms.
    {"name": "a start time with a decimal point", "record": dict(records[2][1], startedUnixMs="1790000000000.0"),
     "why": "an integer in a string is one whole decimal"},
    {"name": "a start time with an exponent", "record": dict(records[2][1], startedUnixMs="179e10"),
     "why": "an integer in a string is one whole decimal"},
]
# Qualification sentences every reader must accept or refuse (docs/run-records.md, the
# isolation_qualification row): both ends of each forbidden range and each forbidden code
# point, the code points beside them, which pass, and the byte bound.
FORBIDDEN = [(0x00, 0x1f), (0x7f, 0x9f), (0x61c, 0x61c), (0x200e, 0x200e), (0x200f, 0x200f),
             (0x2028, 0x2028), (0x2029, 0x2029), (0x202a, 0x202e), (0x2066, 0x2069)]
forbidden = lambda c: any(lo <= c <= hi for lo, hi in FORBIDDEN)
points = sorted({c for lo, hi in FORBIDDEN for c in (lo - 1, lo, hi, hi + 1) if c >= 0} | {0x200b, 0xa0, 0xe9})
quals = [{"name": "U+%04X%s" % (c, " (refused)" if forbidden(c) else ""), "text": "Microsoft " + chr(c) + "states.",
          "valid": not forbidden(c)} for c in points]
quals += [
    {"name": "empty", "text": "", "valid": True},
    {"name": "1024 bytes", "text": "x" * 1024, "valid": True},
    {"name": "1025 bytes", "text": "x" * 1025, "valid": False},
    {"name": "512 two-byte characters", "text": chr(0xe9) * 512, "valid": True},
    {"name": "512 two-byte characters and one more byte", "text": chr(0xe9) * 512 + "x", "valid": False},
]
g["qualifications"] = quals

# Tier comparison: whether a tier meets a floor. The tiers weakest first, as
# docs/isolation-tiers.md ranks them; a tier this table does not name ("" or "unknown")
# meets nothing and is met by nothing. A floor of "none" is met by every tier: every tier is
# at least as strong as no wall. Whether a request may state "none" as its floor is the
# request check's question (it may not), not this one's.
TIERS = ["none", "process", "container", "kernel", "vm"]
names = TIERS + ["", "unknown"]
g["meets"] = [{"tier": a, "floor": f, "meets": a in TIERS and f in TIERS and TIERS.index(a) >= TIERS.index(f)}
              for a in names for f in names]

about = g["about"]
lines = [
    "Record version 6 and protocol 9 (2026-11-26): every vector was computed by",
    "record/testdata/record_v6.py, a second implementation in Python written from",
    "docs/run-records.md, which first reproduced every request, result and record vector v0.29.0,",
    "v0.27.1 and v0.22.0 published. Requests of protocol 9 are hashed under plimsoll.run-request.v3",
    "and the others as before; a result vector names the record version whose result domain hashed",
    "it (recordVersion: plimsoll.run-result.v2 from version 6), and one without it, as in every file",
    "published before version 6, is under plimsoll.run-result.v1. The files kind is in both new",
    "domains, its paths and contents bytes. The version 5 records, written by record_v5.py on",
    "2026-11-17, are frozen in record/testdata/published/v0.29.0-golden.json. Each refused record's",
    "digest matches its fields; every reader must refuse it anyway, for the reason it gives. The",
    "version 1 record is one v0.11.1 signed in its bundle (attest/testdata/published/v0.11.1-sessions),",
    "with the digest that release computed. qualifications: sentences every reader's qualification",
    "check must accept or refuse (both ends of each forbidden range, their neighbors, the byte bound).",
    "meets: whether a tier meets a floor, for every pair of the five tiers, the empty string and an",
    "unknown name.",
]
cut = next((i for i, a in enumerate(about) if a.startswith(("Record version 5", "Record version 6"))), len(about))
g["about"] = about[:cut] + lines
with open("record/testdata/golden.json", "w") as f:
    json.dump(g, f, indent=2)
    f.write("\n")
for r in new_requests + new_results + out:
    print(r["name"], r["sha256"])
print(len(bad), "refused records")
