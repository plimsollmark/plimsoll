# Where a coding agent's code ran, signed per session

A coding agent (Claude Code, Codex) that runs code through plimsoll's MCP server leaves a
signed receipt for every run when the server has `PLIMSOLL_SIGNING_KEY_FILE` and
`PLIMSOLL_RECEIPTS_DIR` set ([INTERNAL · MCP server →](../../clients/mcp/README.md)). This
example gathers runs carrying a coding session's trace into one
signed statement: which recorded runs carry that label, behind which isolation tier, on which
provider, and the weakest tier among them. The tier is configuration and provider evidence
plus startup checks, never hardware attestation.

The trace is a caller-supplied label, not authenticated session identity. Another
caller able to use the server can send the same trace and its runs will appear too.
The statement proves which verified records carry the label, not who originated
every call. Its isolation fields remain configuration and provider evidence.

## 1. Tag every run with the session: the hook

[INTERNAL · hook.py →](hook.py) is a PreToolUse hook on the `run_code` tool. The host hands it
the session's ID, and every run that reaches plimsoll through it carries that ID as its
`trace`, whatever the model wrote; the MCP server signs the trace into the run's receipt
with the request. The trace is the session ID itself when it is 1 to 64 letters, digits or
`. _ : -` and does not begin `session-sha256:`, and otherwise `session-sha256:` and the first
48 hex digits of the ID's SHA-256. An ID that begins with the prefix is always hashed, so no
session can take the trace another session's ID hashes to.

Claude Code, in `.claude/settings.json` (the matcher is `mcp__` plus the name you gave the
server, plus `__run_code`):

```json
{"hooks": {"PreToolUse": [{"matcher": "mcp__plimsoll__run_code",
  "hooks": [{"type": "command", "command": "python3 -I /path/to/examples/agent-session/hook.py", "onFailure": "block"}]}]}}
```

Here the hook rewrites the call's input and allows it. Claude Code applies a rewritten input
only with an allow or ask decision; allow skips the approval prompt for this one tool, a run
in plimsoll's sandbox, and your deny and ask rules still apply
([EXTERNAL · Claude Code hooks reference ↗](https://code.claude.com/docs/en/hooks)).
The explicit failure policy also blocks a crashed or timed-out hook. Unexpected
input errors exit 2 without echoing the input; the host must preserve that blocking
behavior. A direct script check does not establish every host's hook behavior.

Codex, in `.codex/hooks.json` (a hook runs only after you review and trust it there):

```json
{"hooks": {"PreToolUse": [{"matcher": "mcp__plimsoll__run_code",
  "hooks": [{"type": "command", "command": "PLIMSOLL_HOOK_MODE=require python3 -I /path/to/examples/agent-session/hook.py"}]}]}}
```

The Codex hooks documentation describes denying a call, not rewriting one
([EXTERNAL · Codex hooks documentation ↗](https://learn.chatgpt.com/docs/hooks)), so in
`require` mode a call already carrying the session's trace passes through the usual Codex
approval, and any other is denied with a reason that names the trace to send; the agent sends
it again with it.

## 2. Gather the session's runs: the statement

```sh
go run ./examples/agent-session -receipts RECEIPTS_DIR -pub harness.pub \
  -session SESSION_ID -key harness.key -out session.intoto.json
go run ./examples/agent-session -receipts RECEIPTS_DIR -pub harness.pub \
  -session SESSION_ID -check session.intoto.json
```

It reads every receipts file (`runs-*.jsonl`, `session-*.jsonl`), checks each whole against
the receipts key, keeps the runs whose signed request carries the session's trace, and signs
an in-toto statement (predicate type
`https://plimsollmark.github.io/plimsoll/agent-session-runs/v1`, one subject per run record)
with the receipts key: the trace, each run's record digest, file and line, tier, provider,
environment and times, the weakest tier, and every receipts file it read, by length and
SHA-256. A file that does not verify
whole (a sandbox still open, a segment a failed write ended) stops it; `-ignore-unverified`
skips such files and names them in the statement instead. `-check` confirms that every file the
statement read still begins with the bytes it read (receipts files only grow), that the runs
with the trace inside those bytes are exactly the statement's runs, as stated, so a statement
can neither add a run nor leave one out, and reports how many runs with the trace it does not
cover: added since, or in files it could not read.

## What it does not show

- Code the agent ran outside plimsoll (its own shell, another tool) leaves no receipt here; a
  statement lists the runs that carried the trace, not everything the session did.
- Without the hook, `trace` is whatever the model sent.
- The receipts are signed by the key of whoever runs the MCP server; a reader trusts that key
  or not.
