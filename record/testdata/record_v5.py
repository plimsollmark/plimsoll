"""Record version 5 golden vectors, computed from docs/run-records.md.

A second implementation in Python: the layout below is the page's "Record" section. Run from
the repository's root: python3 record/testdata/record_v5.py
First it reproduces every record vector v0.27.1 published (version 4) and the version 2 and
3 vectors v0.22.0 published, and every version 1 record v0.11.1 signed in its bundle; then it
computes the version 5 vectors, the refused cases, the qualification sentences each reader
must accept or refuse and the tier comparison table, and writes them into
record/testdata/golden.json.
"""
import base64, hashlib, json, struct, sys

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
    5: ["request_sha256", "result_sha256", "unanswered", "provider", "isolation",
        "isolation_qualification", "environment", "policy", "software_identity",
        "software_rule_id", "instance", "warm", "daemon_version", "started_unix_ms",
        "ended_unix_ms", "session", "sequence", "previous_sha256"],
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

def digest(rec):
    version = int(rec["version"])
    h = hashlib.sha256()
    def value(b):
        h.update(struct.pack(">Q", len(b)))
        h.update(b)
    value(("plimsoll.run-record.v%d" % version).encode())
    for f in LAYOUTS[version]:
        value(f.encode())
        value(encode(f, rec))
    return h.hexdigest()

def reproduce(path):
    g = json.load(open(path))
    for r in g["records"]:
        got = digest(r["record"])
        if got != r["sha256"]:
            sys.exit("%s: %s: %s, published %s" % (path, r["name"], got, r["sha256"]))
    return len(g["records"])

n = reproduce("record/testdata/published/v0.27.1-golden.json")
n += reproduce("record/testdata/published/v0.22.0-golden.json")
print("reproduced", n, "published record vectors")


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
    ("record", dict(base, version=5, instance="k8s-pod-uid:7f3e9c2a-5b1d-4e8f-9a0c-2d6b8e4f1a37",
                    isolationQualification="A sentence its vendor requires beside the tier, with bytes past ASCII: caf" + chr(0xe9) + ", " + chr(0x2265) + " 2.",
                    daemonVersion="v0.28.0")),
    ("unanswered record", dict(base, version=5, resultSha256="", unanswered="unavailable",
                               isolationQualification="Stated at open.", daemonVersion="(devel)")),
    ("warm record", {"version": 5,
                     "requestSha256": "3ac521c00d014d11e7dfaff3ada8a8b564a0ac93eadc72555a992faac7b8112f",
                     "resultSha256": "3a57590f560a5de29d491595bfb264ff072e06d4d0fcccc5ab2d4b3de410d37d",
                     "provider": "docker", "isolation": "kernel", "warm": True,
                     "daemonVersion": "v0.28.1-0.20261117210242-4ca8fb4d330e+dirty",
                     "startedUnixMs": "1790000000000", "endedUnixMs": "1790000000812"}),
    ("wslc record", {"version": 5,
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

g = json.load(open("record/testdata/golden.json"))
g["records"] = out
g["refused"] = bad
# Malformed: a field of the wrong JSON type. No digest is given: a reader refuses to read the record at all, as Go's
# protojson and Python's typed reads do, so none is computed from it.
g["malformed"] = [
    {"name": "warm as the string true", "record": dict(records[2][1], warm="true"), "why": "warm is a JSON boolean"},
    {"name": "warm as the number 1", "record": dict(records[2][1], warm=1), "why": "warm is a JSON boolean"},
    {"name": "a qualification that is a number", "record": dict(wslc, isolationQualification=5), "why": "the sentence is a JSON string"},
    {"name": "a daemon version that is a list", "record": dict(wslc, daemonVersion=["v0.28.0"]), "why": "the daemon version is a JSON string"},
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
    "Record version 5 and protocol 6 (2026-11-17): the version 5 records and the refused records",
    "were computed by record/testdata/record_v5.py, a second implementation in Python written from",
    "docs/run-records.md, which first reproduced every record vector v0.27.1 and v0.22.0 published.",
    "Each refused record's digest matches its fields; every reader must refuse it anyway, for the",
    "reason it gives. The version 1 record is one v0.11.1 signed in its bundle",
    "(attest/testdata/published/v0.11.1-sessions), with the digest that release computed.",
    "qualifications: sentences every reader's qualification check must accept or refuse (both ends",
    "of each forbidden range, their neighbors, the byte bound). meets: whether a tier meets a floor,",
    "for every pair of the five tiers, the empty string and an unknown name.",
]
cut = next((i for i, a in enumerate(about) if a.startswith("Record version 5")), len(about))
g["about"] = about[:cut] + lines
with open("record/testdata/golden.json", "w") as f:
    json.dump(g, f, indent=2)
    f.write("\n")
for r in out:
    print(r["name"], r["sha256"])
print(len(bad), "refused records")
