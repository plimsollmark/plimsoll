"""Scripted policies for the attempt: what a model might do on each task, written down as a
script. Each is a function of the conversation so far (see ``scripted_model``) and decides
its next turn by counting its own earlier turns and reading the last tool result. None of
them is a model, and nothing they score says anything about a model's skill: they exist to
drive real tool calls through a real harness, interception server and runtime.

- ``gold``: solves the task the way its instructions say, using both tools (``bash``, and
  ``edit`` to fill in a value it computed), then answers in text.
- ``wrong``: writes a wrong answer and stops, so the grader's 0 is seen to be possible.
- ``slow``: starts a command that runs for five minutes, for the cancellation measurement.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from ..scripted_model import assistant, last_tool_result, tool_call

Policy = Callable[[List[Dict[str, Any]]], Dict[str, Any]]

__all__ = ["POLICIES"]


def _turn(messages: List[Dict[str, Any]]) -> int:
    """How many answers this policy has given so far."""
    return sum(1 for m in messages if m.get("role") == "assistant")


def _script(*steps: Callable[[List[Dict[str, Any]]], Dict[str, Any]]) -> Policy:
    def policy(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        n = _turn(messages)
        return steps[n](messages) if n < len(steps) else assistant("Done.")

    return policy


def _last_line(messages: List[Dict[str, Any]]) -> str:
    lines = last_tool_result(messages).strip().splitlines()
    return lines[-1].strip() if lines else ""


# plimsoll-sum (clients/python/frameworks/verifiers/plimsoll_sum): sum input.txt into
# output/answer.txt, graded in a fresh sandbox.
PLIMSOLL_SUM = {
    "gold": _script(
        lambda m: assistant(None, tool_call("bash", command="cat input.txt; awk '{ s += $1 } END { print s }' input.txt")),
        lambda m: assistant(None, tool_call("bash", command="printf PENDING > output/answer.txt && cat output/answer.txt")),
        lambda m: assistant(None, tool_call("edit", path="output/answer.txt", old_str="PENDING", new_str=_sum_from(m))),
        lambda m: assistant(None, tool_call("bash", command="cat output/answer.txt")),
        lambda m: assistant(f"The sum is {_last_line(m)}; it is in output/answer.txt."),
    ),
    "wrong": _script(
        lambda m: assistant(None, tool_call("bash", command="printf 7 > output/answer.txt")),
        lambda m: assistant("I wrote 7."),
    ),
}


def _sum_from(messages: List[Dict[str, Any]]) -> str:
    # The first tool result was the file, then the sum on its own last line.
    first = [x for x in messages if x.get("role") == "tool"][0]
    content = first.get("content")
    text = content if isinstance(content, str) else "".join(p.get("text", "") for p in content or [])
    return text.strip().splitlines()[-1].strip()


# prime-envs uuid_ctf, preset extra_easy (the task's own curriculum hint: start at the
# recovery index, run the extractor it names, then compute the derived UUID and write the
# answer). The reducer is the one the index states: sha256 of the domain separator and the
# five UUIDs' bytes, its first 16 bytes as a UUID.
_UUID_CTF_COMPUTE = """python3 - <<'PY'
import hashlib, json, uuid
r = json.load(open('/workspace/recovered_sources.json'))
payload = r['domain_separator'].encode('utf-8') + b''.join(uuid.UUID(u).bytes for u in r['source_uuids'])
derived = str(uuid.UUID(bytes=hashlib.sha256(payload).digest()[:16]))
answer = {'result_uuid': 'PENDING', 'source_uuids': r['source_uuids'], 'evidence_paths': r['evidence_paths']}
open('/workspace/answer.json', 'w').write(json.dumps(answer, indent=2) + '\\n')
print(derived)
PY"""

UUID_CTF = {
    "gold": _script(
        lambda m: assistant(None, tool_call("bash", command="ls /workspace; cat /workspace/corpus/ops/recovery_index.json")),
        lambda m: assistant(None, tool_call("bash", command="python3 /workspace/corpus/ops/extract_recovery_sources.py")),
        lambda m: assistant(None, tool_call("bash", command=_UUID_CTF_COMPUTE)),
        lambda m: assistant(None, tool_call("edit", path="/workspace/answer.json", old_str="PENDING", new_str=_last_line(m))),
        lambda m: assistant(None, tool_call("bash", command="cat /workspace/answer.json")),
        lambda m: assistant("The recovery token is in /workspace/answer.json."),
    ),
    "wrong": _script(
        lambda m: assistant(
            None,
            tool_call("bash", command="""printf '{"result_uuid": "00000000-0000-4000-8000-000000000000"}\\n' > /workspace/answer.json"""),
        ),
        lambda m: assistant("I wrote a guess."),
    ),
}

SLOW = _script(lambda m: assistant(None, tool_call("bash", command="sleep 300; echo finished")))

POLICIES: Dict[str, Dict[str, Policy]] = {
    "plimsoll-sum": {**PLIMSOLL_SUM, "slow": SLOW},
    "uuid-ctf": {**UUID_CTF, "slow": SLOW},
}
