# Advisory telemetry: privacy and retention

The Prospector efficiency advisor (see the
[advisor trainer](trainers/advisor.html)) watches a run's brokered host-API traffic and
emits findings about wasteful call patterns. Because it observes real customer traffic,
its privacy properties are load-bearing. This doc states exactly what it records, what it
can never record, and how an operator controls retention. Every property here is enforced
in code, not a promise.

## Metadata only, by construction

The advisor reads only the run's **`CallTrace`**, the bounded, metadata-only record the
shared `brokerSession` builds for each `host.*` call, whether it arrived through
Docker's Unix socket or WASM's direct host function. Two structural facts make a
leak impossible rather than merely discouraged:

- The broker matches the request path against the profile's `Allow` list and records
  **only the matched route template** (`HostRoute.Path`, e.g. `GET /v1/lights/*`), never
  the concrete request path. Query strings are rejected outright, so an id or filter value
  cannot ride along in one.
- `CallRow` (`sandbox/calltrace.go`) has **no field** for a request body, a response body,
  or a credential. The broker reads bodies to proxy the call and injects the token itself,
  but neither is ever copied into the trace. Sizes are byte **counts**, not content.

So a concrete id, query value, request/response body, or bearer token cannot enter the
`CallTrace`, and every downstream artifact (findings, wire hints, audit records, metrics)
is derived from that trace plus the operator-configured `Allow` list. Findings are
templated from trusted inputs only: route templates from the profile, plus counts and
timings. No guest-controlled string is ever echoed, so a finding cannot become a
prompt-injection or covert channel. This is the same rule as the base audit log:
metadata yes, code and credentials never.

## plimsoll stores nothing: "retention" is about emission

plimsoll is **stateless per run**. It does not persist traces or findings to disk or a
database. The `CallTrace` lives on the in-memory `Result` and is discarded when the
response is sent. "Telemetry retention" therefore does not mean a dataset plimsoll
prunes; it means **what plimsoll writes to the operator's surfaces**, which the
operator's own log and metrics systems then keep for whatever period their policy sets.

There are three surfaces, governed independently:

| Surface | Contents | Governed by | Lifetime |
| --- | --- | --- | --- |
| Caller wire hint (`advice` field on the run result) | Agent-fixable findings only: route template, verb, one templated sentence, estimated saving | `advice: caller` | Ephemeral: returned to the caller that made the calls, then gone. Discloses nothing the caller did not already see in its own traffic. |
| `/metrics` aggregates | Bounded counters keyed by profile, pattern, severity, remedy (no route templates, no per-run records) | `advice: operator` or `caller` | The operator's metrics store (e.g. Prometheus) retains them per its own policy. Aggregate and non-identifying. |
| Durable audit log | The per-run advisory record on the `code run` line | **`advice_retention`** | The operator's log sink retains it per its own policy. |

Only the third surface can carry a per-route record, and it is the one the retention knob
gates.

## Configuring it: `advice` and `advice_retention`

Both live per profile in `PLIMSOLL_GRANTS_FILE` (see [internal/grants](../internal/grants/)),
both default off, and they compose orthogonally: `advice` decides **who can act** on a
finding, `advice_retention` decides **what durable record** the operator keeps.

```json
{
  "profiles": {
    "hue": {
      "base_url": "https://api.example.com",
      "allow": ["GET /v1/lights", "GET /v1/lights/*"],
      "allowed_callers": ["mcp-a"],
      "token": {"type": "static", "env": "HUE_TOKEN"},

      "advice": "caller",
      "advice_retention": "aggregate"
    }
  }
}
```

`advice`:

- `off` (default): no advice is computed. The profile's traffic is left unanalyzed.
- `operator`: findings drive the operator surfaces (`/metrics`, and the audit log subject
  to `advice_retention`). Nothing is returned to the caller.
- `caller`: additionally returns the agent-fixable subset in the run result, so a product
  may feed them to its model for self-correction. API-change findings (no better route
  exists) stay operator-only regardless.

`advice_retention` (governs the durable audit log only; no effect when `advice` is off):

- `none` (default): plimsoll writes **no** advisory record to the audit log. Advice can
  still drive the live caller hint and the `/metrics` aggregates; the durable log stays
  silent. This is the safe default, matching the rest of plimsoll: opt in to keep a
  durable record, do not opt out of one.
- `aggregate`: writes the per-run **totals** (finding count and total estimated extra
  calls, added latency, and bytes) but no per-finding, per-route record.
- `detailed`: additionally writes `advice_finding_details`, one metadata-only record per
  finding (pattern, severity, remedy, route template, cost). This is the stream the
  exported-audit HTML report ([cmd/prospector-report](../cmd/prospector-report)) renders,
  so choose it when you want the drill-down view, and set your log sink's retention window
  accordingly.

## Operator responsibilities

- **The log window is yours.** plimsoll declares the retention *level* (how much detail
  it emits); it cannot delete records from your log sink. Set your sink's TTL to match the
  sensitivity of the level you chose. `detailed` retains per-route templates for the
  customer's traffic (still metadata only, but a behavioral record of API usage shape).
- **Prefer the least detail that answers your question.** `/metrics` alone (with
  `advice_retention: none`) powers the Prospector dashboard without writing any per-run
  finding to the log. Use `aggregate` for per-run cost trends, and `detailed` only when
  the per-route drill-down is worth the retained record.
- **A finding never changes a run.** Advice is evidence attached post-dispatch, like the
  isolation tier. It cannot gate execution, alter output, or slow the run down. Turning
  any of this on is safe with respect to the run itself.
