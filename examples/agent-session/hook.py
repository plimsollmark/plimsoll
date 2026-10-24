"""Tie every plimsoll run a coding agent makes to the coding session it came from.

A coding agent's host (Claude Code, Codex) runs this as a PreToolUse hook on plimsoll's
`run_code` tool. The host hands the hook the session's ID; the hook makes sure the run
carries it as its `trace`, which plimsoll's MCP server signs into the run's receipt with
the request. `main.go` (in this directory) then gathers runs carrying that trace from the
receipts into one signed statement.

Two modes, chosen by PLIMSOLL_HOOK_MODE:

- rewrite (the default; Claude Code): the hook sets `trace` itself, replacing whatever the
  model sent, and allows the call. Claude Code applies a hook's rewritten input only
  together with an allow or ask decision; allow skips the approval prompt for this one
  tool (a run in plimsoll's sandbox), and the user's deny and ask rules still apply.
- require (any host whose hooks can deny but not rewrite, such as Codex): a call whose
  `trace` is already the session's passes untouched, through the host's usual approval;
  any other call is denied with a reason that names the trace to send, so the agent sends
  it again with that trace.

Either way a run that reaches plimsoll through this hook carries the session's ID, whatever
the model wrote. Without the hook, `trace` is whatever the model chose to send.

The trace is the session ID itself when it fits plimsoll's rule for a trace (1 to 64
letters, digits or . _ : -) and does not itself begin `session-sha256:`; otherwise it is
`session-sha256:` and the first 48 hex digits of the ID's SHA-256, which anyone holding the ID
can recompute. An ID that begins with the prefix is always hashed, so no literal ID can take
the trace another session's ID hashes to.

  python3 -I hook.py < hook-input.json
"""
import hashlib
import json
import os
import re
import sys

TRACE_FORM = re.compile(r'[A-Za-z0-9._:-]{1,64}')
HASHED_PREFIX = 'session-sha256:'


def trace_for(session_id):
    """The trace a session's runs carry."""
    if TRACE_FORM.fullmatch(session_id) and not session_id.startswith(HASHED_PREFIX):
        return session_id
    return HASHED_PREFIX + hashlib.sha256(session_id.encode()).hexdigest()[:48]


def decide(event, mode):
    """The hook's JSON answer for one PreToolUse event, or None to let the call through
    the host's usual approval unchanged."""
    session_id = event.get('session_id')
    tool_input = event.get('tool_input')
    if not isinstance(tool_input, dict):
        return deny('the hook input holds no tool input to check')
    if not isinstance(session_id, str) or not session_id:
        return deny('the hook input names no session, so this run could not be tied to one')
    trace = trace_for(session_id)
    if mode == 'rewrite':
        return {'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'allow',
            'permissionDecisionReason': 'plimsoll run tagged with this coding session',
            'updatedInput': {**tool_input, 'trace': trace}}}
    if tool_input.get('trace') == trace:
        return None
    return deny(f'send this plimsoll run again with "trace": "{trace}", this coding session\'s ID, '
                'so its signed receipt names the session')


def deny(reason):
    return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
                                   'permissionDecisionReason': reason}}


def main():
    mode = os.environ.get('PLIMSOLL_HOOK_MODE', 'rewrite')
    if mode not in ('rewrite', 'require'):
        print(f'PLIMSOLL_HOOK_MODE must be rewrite or require, not {mode!r}', file=sys.stderr)
        sys.exit(2)  # a blocking error: the call does not go through untagged
    try:
        try:
            event = json.load(sys.stdin)
        except ValueError:
            answer = deny('the hook input is not JSON')
        else:
            answer = decide(event, mode) if isinstance(event, dict) else deny('the hook input is not a JSON object')
        if answer is not None:
            # Encode before writing so a serialization failure cannot leave half a decision.
            sys.stdout.write(json.dumps(answer)+'\n')
    except Exception:
        # PreToolUse exit 2 blocks the call; an ordinary crash can be non-blocking.
        # Do not echo the input or an exception that might include its contents.
        print('plimsoll hook could not validate this call; blocking it', file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
