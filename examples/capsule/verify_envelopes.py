"""Check the capsule signatures with the capsule project's own Python verifier.

verify_producer_envelope (agent-action-capsule, with its "envelope" extra) checks a
COSE_Sign1 Producer Envelope through scitt-cose, which implements COSE_Sign1 from
scratch rather than wrapping a COSE library. The capsules were signed in Go with
go-cose, so this check shares no COSE code with the signer.

    python verify_envelopes.py DIR

DIR holds envelopes.jsonl and producer.pub as the Go program writes them. Prints one
JSON object: every envelope's result, and two copies broken on purpose, which must be
refused. Exits 0 whatever the results; the Go program judges them.
"""
import base64
import json
import sys

from cryptography.hazmat.primitives import serialization

from agent_action_capsule.producer_envelope import verify_producer_envelope


def codes(result):
    return [f.code for f in result.findings]


def main(directory):
    with open(f"{directory}/producer.pub", "rb") as f:
        producer = serialization.load_pem_public_key(f.read()).public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with open(f"{directory}/envelopes.jsonl") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    accepted = 0
    for row in rows:
        result = verify_producer_envelope(row["capsule_id"], base64.b64decode(row["cose_sign1"]))
        if result.ok and result.public_key == producer:
            accepted += 1

    mid = len(rows) // 2
    flipped = bytearray(base64.b64decode(rows[mid]["cose_sign1"]))
    flipped[-1] ^= 1
    bit = verify_producer_envelope(rows[mid]["capsule_id"], bytes(flipped))
    moved = verify_producer_envelope(rows[(mid + 1) % len(rows)]["capsule_id"],
                                     base64.b64decode(rows[mid]["cose_sign1"]))
    json.dump({
        "envelopes": len(rows),
        "accepted_with_producer_key": accepted,
        "flipped_bit": {"ok": bit.ok, "codes": codes(bit)},
        "moved": {"ok": moved.ok, "codes": codes(moved)},
    }, sys.stdout)


if __name__ == "__main__":
    main(sys.argv[1])
