# Telemetry and the efficiency advisor

Why the telemetry cannot carry payloads by construction, and what the shipped advisor does with the metadata it can carry.

Part of the [plimsoll README](../README.md).

Every property stated here is enforced in code rather than promised. Because the
advisor observes real customer traffic, its privacy properties are load-bearing.

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
  but neither is ever copied into the trace. Sizes are byte **counts**, not content. It
  does record whether the broker delivered the upstream response, so a capped or
  unanswered call is never read as a successful one; that is a broker fact, not guest
  content.

So a concrete id, query value, request/response body, or bearer token cannot enter the
`CallTrace`, and every downstream artifact (findings, wire hints, audit records, metrics)
is derived from that trace plus the operator-configured `Allow` list. Findings are
templated from trusted inputs only: route templates from the profile, plus counts and
timings. No guest-controlled string is ever echoed, so a finding cannot become a
prompt-injection or covert channel. This is the same rule as the base audit log:
metadata yes, code and credentials never.

### The correlation id is the honest form of the claim

The honest form of that claim is the correlation id. `trace_id` on a request is an
opaque join key that gets echoed onto the audit line and is never parsed, routed on,
or sent upstream. The sensitive payload lives in exactly one place, one layer up, in
your own log. This is the difference between "we record less" and "we record the part
that is ours."

Because that field is caller-controlled, it is validated as `[A-Za-z0-9._:-]{1,64}`
and a non-conforming id is **dropped whole** rather than truncated. A truncated id
would look joinable and join to nothing.

## Efficiency advisor

The broker is the one component that sees every call the agent's code makes and
holds none of the content, so it is also the place to notice waste. After a run
finishes, two deterministic detectors read its `CallTrace` and report where the call
pattern cost the API more than the question needed: **fan-out** (an N+1 loop over a
per-item route) and **repeated reads** of one fixed route (the same request, since a
route without a wildcard admits exactly one path, with same-size responses as evidence
the data did not change). Both count only calls the broker delivered with a 2xx
status; failed calls are named in the finding and never counted as records retrieved.
Each finding's sentence claims only what the trace can support: a per-item route is
never reported as a repeated read, because equal response sizes there cannot tell one
item fetched many times from many items of one size, and every remedy is stated as a
condition (a collection route helps only if it returns the same items; a cache helps
only if the data really was unchanged). Two earlier detectors, aggregate-in-code and
sequential calls, were removed because the trace cannot support them: it holds no
call start times and no guest content. A small router then asks one question of the
profile's allow list, for a GET fan-out only: does the collection route already
exist? If it does, the finding is **agent-fixable** and names the granted route to
switch to. If it does not, or the fan-out is a write (a collection write's semantics
cannot be read off its path), the finding is one of two further things, and the
second is not a verdict. When the profile declares a `catalog` (its full endpoint
list) and the catalog exposes the batch route the grant omits, the finding names that
route as the **one line to add to the allow list**: an operator action, carried on the
audit line as `grant_route`, and no API change. When no such route is known,
`insights.Prompt` renders a paste-ready prompt for the API owner's own AI that asks
for the smallest change that would remove the pattern **or a plain statement that
none is warranted**: one run's trace cannot show that the API forces the pattern on
every caller, the granted routes may be a subset of the API, and a profile need not
declare a catalog at all. For a read fan-out the prompt offers a server-side
aggregate as a conditional alternative. plimsoll never calls a model itself.

Who sees what is a per-profile setting. `advice: off | operator | caller` chooses the
audience: `caller` returns the agent-fixable subset on the run result, which the Go
client exposes as `Result.Advice`; findings with no granted route stay on operator
surfaces whatever the mode. `advice_retention: none | aggregate | detailed` chooses what
reaches the durable audit log, from nothing to one metadata-only record per finding,
which is the stream [prospector-report](../cmd/prospector-report) renders as HTML.
`/metrics` carries bounded counts by profile, pattern, severity and remedy.

Two constraints hold on every surface. Advice is **evidence, never authority**: it
is computed after dispatch over the already-final result, so a run with advice is
byte-identical in execution to one without, and it never gates admission or changes
an exit code, an output byte or the tier. And it is **metadata only**: findings are
templated from route templates and numbers, and no guest-controlled string is ever
copied through. It is off by default; a profile opts in.

Read the three numbers on a finding for what they are. `extra_calls` is the measured
call count minus one, and it is rigorous when a granted batch route is named. The
other two compare the measured pattern with an ideal that is never measured:
`added_latency_ms` is the summed round-trip time beyond one call, a model rather than
wall time lost, and `bytes_moved` is the gross bytes the flagged calls moved, not a
saving. Quote the first; treat the others as order-of-magnitude context.

`go run ./examples/advisor` shows the whole loop in one screen: the per-item loop, the
finding that comes back, the rewrite it suggests, and the API's own request and byte
counts beside the finding's predictions. Add `-report out.html` for the same run as a
self-contained page; one such run is published at
[plimsollmark.github.io/plimsoll/examples/advisor/report.html](https://plimsollmark.github.io/plimsoll/examples/advisor/report.html). The lesson
[API Efficiency Advisor](https://plimsollmark.github.io/plimsoll/trainers/advisor.html)
walks the same ground with a 128-call example.

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
  may feed them to its model for self-correction. A finding with no granted route stays
  operator-only regardless, whether its fix is an allow-list line (the catalog names the
  route) or unknown (nothing names one).

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
