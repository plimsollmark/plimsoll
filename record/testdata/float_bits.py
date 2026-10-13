"""Write float-bits.json: vectors for how the result digest encodes a float.

Computed from docs/run-records.md alone, with the standard library, and checked against
the Go implementation by record/float_bits_test.go. Each float is handled as its 64-bit
pattern and never passes through a Python float, so a NaN keeps its payload.

Run from the repository root: python3 -I record/testdata/float_bits.py
"""

import hashlib
import json
import pathlib
import struct

DOMAIN = "plimsoll.run-result.v1"
SPEC = "docs/run-records.md: The encoding; Result: domain plimsoll.run-result.v1, module"


def value(b: bytes) -> bytes:
    return struct.pack(">Q", len(b)) + b


def module_result(outputs: bytes) -> bytes:
    """The pre-image of a completed module result with one row of width 1."""
    out = value(DOMAIN.encode())
    for name, v in [
        ("kind", b"module"),
        ("outcome", b"1"),  # PROJECT_OUTCOME_COMPLETED
        ("outcome_detail", b""),
        ("width", b"1"),
        ("stdout", b""),
        ("stderr", b""),
        ("runs", b"1"),
        ("run_status", b"1"),
        ("run_outputs", outputs),
    ]:
        out += value(name.encode()) + value(v)
    return out


def vector(vid, description, bits, pre_image, failure_reason=None):
    v = {
        "id": vid,
        "description": description,
        "domain": DOMAIN,
        "spec_ref": SPEC,
        "must_fail": failure_reason is not None,
    }
    if failure_reason is not None:
        v["failure_reason"] = failure_reason
    v["input"] = {
        "kind": "module",
        "outcome": 1,
        "outcome_detail": "",
        "width": 1,
        "stdout_hex": "",
        "stderr_hex": "",
        "runs": [{"status": 1, "outputs_bits_hex": [bits]}],
    }
    v["pre_image_bytes_hex"] = pre_image.hex()
    v["digest"] = hashlib.sha256(pre_image).hexdigest()
    return v


def bits(h: str) -> bytes:
    return bytes.fromhex(h)


POS_ZERO, NEG_ZERO, TENTH = "0000000000000000", "8000000000000000", "3fb999999999999a"
NAN, NAN_PAYLOAD = "7ff8000000000000", "7ff8000000000001"

VECTORS = [
    vector("plimsoll-float-pass-01", "PASS: one output of +0.", POS_ZERO, module_result(bits(POS_ZERO))),
    vector(
        "plimsoll-float-pass-02",
        "PASS: one output of -0. Differs from pass-01 in the sign bit alone, and so does its "
        "digest; RFC 8785 serializes both zeros as 0, so a jcs digest cannot tell them apart.",
        NEG_ZERO,
        module_result(bits(NEG_ZERO)),
    ),
    vector(
        "plimsoll-float-pass-03",
        "PASS: one output of 0.1, the double nearest it, as its eight octets.",
        TENTH,
        module_result(bits(TENTH)),
    ),
    vector(
        "plimsoll-float-pass-04",
        "PASS: one output of the quiet NaN with no sign or payload, the one NaN the daemon sends.",
        NAN,
        module_result(bits(NAN)),
    ),
    vector(
        "plimsoll-float-pass-05",
        "PASS: one output of a NaN with payload 1. Differs from pass-04 in its last bit alone, "
        "and so does its digest. The daemon never sends this NaN; the vector tests the encoding.",
        NAN_PAYLOAD,
        module_result(bits(NAN_PAYLOAD)),
    ),
    vector(
        "plimsoll-float-fail-01",
        "MUST-FAIL: the -0 output of pass-02 hashed with its sign dropped, as a JSON mapping "
        "followed by RFC 8785 would.",
        NEG_ZERO,
        module_result(bits(POS_ZERO)),
        "float_sign_dropped",
    ),
    vector(
        "plimsoll-float-fail-02",
        "MUST-FAIL: the payload NaN of pass-05 hashed as the NaN without a payload, as a JSON "
        "mapping that writes every NaN as \"NaN\" would.",
        NAN_PAYLOAD,
        module_result(bits(NAN)),
        "nan_payload_collapsed",
    ),
    vector(
        "plimsoll-float-fail-03",
        "MUST-FAIL: the 0.1 output of pass-03 hashed as the decimal text 0.1 instead of its "
        "eight octets.",
        TENTH,
        module_result(b"0.1"),
        "float_as_decimal_text",
    ),
]

ABOUT = [
    "Float-bit vectors for the result digest (docs/run-records.md). Each input is a completed",
    "module result with one row holding one output, given as its 64-bit pattern in hex. A",
    "PASS vector's digest is what a conforming implementation produces from its input. A",
    "MUST-FAIL vector's pre-image and digest are a wrong computation from its input, which a",
    "conforming implementation must not reproduce. Written by float_bits.py from the",
    "specification alone; record/float_bits_test.go checks every vector against the Go",
    "implementation. Changing a digest here changes the encoding: change docs/run-records.md",
    "first.",
]

if __name__ == "__main__":
    out = pathlib.Path(__file__).with_name("float-bits.json")
    out.write_text(json.dumps({"about": ABOUT, "vectors": VECTORS}, indent=2) + "\n")
