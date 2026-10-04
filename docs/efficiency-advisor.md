# Telemetry and the efficiency advisor

Why the telemetry cannot carry payloads by construction, and what the shipped advisor does with the metadata it can carry.

Part of the [plimsoll README](../README.md).

Telemetry here means the records plimsoll writes out about each run's API calls. Every
property stated below is enforced in code, not just promised. That matters because the
advisor looks at real customer traffic.

## Metadata only, by construction

The advisor reads only the run's **`CallTrace`**: a size-limited record, holding metadata
only, with one row for each `host.*` call the sandboxed code made. The
<dfn>*broker*</dfn>, the part of plimsoll that makes each API call on the code's behalf,
builds it. Its per-run core, `brokerSession`, is shared, so the record is the same whether
the call arrived through Docker's Unix socket or through the function the daemon hands
directly to code running in-process on `wasm`. Two facts about the code's structure
make a leak impossible rather than merely discouraged:

- The broker checks each request path against the `Allow` list of the run's
  <dfn>*grant*</dfn> (the run's permission to call listed routes of one API, stored on the
  server as a profile) and records **only the route template that matched**
  (`HostRoute.Path`, e.g. `GET /v1/lights/*`, where `*` stands for one path segment),
  never the actual request path. Query strings are refused outright, so an id or filter
  value cannot ride along in one.
- `CallRow` (`sandbox/calltrace.go`), the type of one row, has **no field** for a request
  body, a response body, or a credential. The broker reads bodies to pass the call on and
  attaches the token itself, but neither is ever copied into the trace. Sizes are byte
  **counts**, not content. A row does record whether the broker delivered the API's
  response, so a call whose response was over the size cap, or never came, is never read
  as a successful one. That is a fact about the broker, not content from the
  <dfn>*guest*</dfn> (the code running in the sandbox).

So a concrete id, query value, request or response body, or bearer token cannot enter
the `CallTrace`, and everything built from it (findings, hints returned to the caller,
audit records, metrics) comes from that trace plus the `Allow` list the operator
configured. Findings are filled in from trusted inputs only: route templates from the
profile, plus counts and timings. No text the guest controls is ever copied into one, so
a finding cannot carry a <dfn>*prompt injection*</dfn> (instructions planted for whatever model reads
it) or become a hidden channel for data. This is the same rule as plimsoll's ordinary
audit log, which writes one line per run: metadata yes, code and credentials never. One
exception there: the audit line's `outcome_detail` can carry a project file path supplied
by the authenticated caller, which is that caller's own input rather than guest content.

### The correlation id is the honest form of the claim

`trace_id` on a request is an ID you choose, typically the one your own log already
uses, so the two logs can be joined on it. plimsoll copies it onto the audit line and
never parses it, routes on it, or sends it to the API. The sensitive request data then
lives in exactly one place, one layer up, in your own log. This is the difference between
"we record less" and "we record the part that is ours."

Because the caller controls that field, it is the one place a path could be slipped into
the log. So it must match `[A-Za-z0-9._:-]{1,64}`, and an id that does not is **dropped
whole** rather than cut short. A shortened id would look usable for joining and match
nothing.

## Efficiency advisor

The broker is the one component that sees every call the agent's code makes and keeps
none of the content, so it is also the place to notice waste. After a run finishes, two
detectors, fixed rules that give the same answer for the same trace, read its
`CallTrace` and report where the call pattern cost the API more than the question
needed:

- <dfn>*fan-out*</dfn>: calling a per-item route once for every item of a list (the N+1
  pattern);
- **repeated reads** of one fixed route: the same request each time, since a route
  without a `*` matches exactly one path and only calls that sent no body are counted
  (the trace records a body's size, not its bytes, so two GETs with bodies are not known
  to be the same request), with same-size responses as evidence the data did not change.

Both count only calls the broker delivered with a 2xx status; failed calls are named in
the finding and never counted as records retrieved. Each finding's sentence claims only
what the trace can support. A per-item route is never reported as a repeated read,
because equal response sizes there cannot tell one item fetched many times from many
items of the same size. Every remedy is stated as a condition: a collection route (one
call that returns the whole list) helps only if it returns the same items; a cache helps
only if the data really was unchanged. Two earlier detectors, aggregate-in-code and
sequential calls, were removed because the trace cannot support them: it holds no call
start times and no guest content.

Then a small router names, for a GET fan-out only, a route that could answer the calls in
one request, and says on what basis. The basis that counts is a declaration: the profile's
`batch_of` maps a batch route to the per-item routes one request to it replaces.

```json
"batch_of": {"GET /items": ["GET /items/*"]}
```

It is the operator's statement that `GET /items` returns what the `GET /items/*` calls
returned. plimsoll cannot check that: the trace has no bodies, so it cannot see whether
the route returns every page, the same fields, or the same scope. `plimsoll-specgen`
writes `batch_of` from an `x-plimsoll-batch-of` marker in the OpenAPI document
([worked example](examples/specgen/README.md)). Each finding lands in one of four classes,
and the last is not a verdict:

1. **Agent-fixable.** The profile declares a batch route for this route and grants it.
   The finding names that route, and it is the only route a finding ever hands the caller.
2. **One line for the operator.** The profile declares a batch route but does not grant
   it. The finding names it as the **one line to add to the allow list**, carried on the
   audit line as `grant_route`; no API change is needed.
3. **A candidate to check.** Nothing is declared, but the route's path suggests one: the
   collection (`/items` for `/items/*`) is granted, or is in the profile's `catalog` (the
   API's full list of routes). A path is not evidence that the route returns the same
   items, so the finding names it to the operator only (`candidate_route` on the audit
   line), who checks it and, if it holds, declares it.
4. **No route is known.** `insights.Prompt` renders a paste-ready prompt for the API
   owner's own AI that asks for the smallest change that would remove the pattern **or a
   plain statement that none is warranted**: one run's trace cannot show that the API
   forces the pattern on every caller, the granted routes may be only part of the API,
   and a profile need not declare a catalog at all. For a read fan-out the prompt offers
   a server-side aggregate (the API computing the answer itself) as a conditional
   alternative.

A fan-out that writes gets none of the first three classes: `batch_of` refuses a write,
and plimsoll never suggests a collection route for one, because what a collection write
does cannot be read off its path. plimsoll never calls a model itself.

Who sees what is set per profile. `advice: off | operator | caller` chooses the
audience: `caller` returns the agent-fixable findings on the run result, which the Go
client exposes as `Result.Advice`; findings with no declared, granted route stay on the operator's
side (metrics and logs) whatever the mode. `advice_retention: none | aggregate |
detailed` chooses what reaches the audit log the operator keeps, from nothing to one
metadata-only record per finding; those records are what
[prospector-report](../cmd/prospector-report) renders as HTML. `/metrics` carries counts
labelled only by profile, pattern, severity, remedy and whether the finding is agent-fixable, on the daemon's separate metrics
port (`PLIMSOLL_METRICS_ADDR`, reachable only from this machine by default).

Two rules hold everywhere advice appears. Advice is **evidence, never authority**: it
is computed after the run, over its already-final result, so a run with advice executes
byte for byte the same as one without. It never decides whether a run may start, and
never changes an exit code, an output byte or the run's <dfn>*isolation tier*</dfn> (how
strong the wall around the run was). And it is **metadata only**: findings are built
from route templates and numbers, and no text the guest controls is ever copied through.
It is off by default; a profile opts in.

Read the three numbers on a finding for what they are. `extra_calls` is the number of
successful calls minus one (failed calls are named, never counted), and it is rigorous when a granted batch route is named. The other
two compare the measured pattern with an ideal that is never measured:
`added_latency_ms` is the summed round-trip time beyond one call, an estimate rather
than clock time actually lost, and `bytes_moved` is the total bytes the flagged calls
moved, not a saving. Quote the first; treat the others as order-of-magnitude context.

`go run ./examples/advisor` shows the whole loop in one screen: the per-item loop, the
finding that comes back, the rewrite it suggests, and the API's own request and byte
counts beside the finding's predictions. Add `-report out.html` for the same run as a
self-contained page; one such run is published at
[plimsollmark.github.io/plimsoll/examples/advisor/report.html](https://plimsollmark.github.io/plimsoll/examples/advisor/report.html). The lesson
[API Efficiency Advisor](https://plimsollmark.github.io/plimsoll/trainers/advisor.html)
walks the same ground with a 128-call example.

## plimsoll stores nothing: "retention" is about emission

plimsoll **stores nothing**: it does not save traces or findings to disk or a
database. The `CallTrace` lives on the in-memory `Result` and is discarded when the
response is sent. So "telemetry retention" does not mean a dataset plimsoll prunes; it
means **what plimsoll writes out to the operator's systems**, which the operator's own
log and metrics systems then keep for whatever period their policy sets.

There are three places it can go, each controlled on its own:

| Where | Contents | Controlled by | How long it lasts |
| --- | --- | --- | --- |
| Hint to the caller (`advice` field on the run result) | Agent-fixable findings only: route template, verb, one sentence filled in from a template, estimated saving | `advice: caller` | Not kept: returned to the caller that made the calls, then gone. Discloses nothing the caller did not already see in its own traffic. |
| `/metrics` totals | Counters labelled only by profile, pattern, severity, remedy and agent-fixable (no route templates, no record per run) | `advice: operator` or `caller` | The operator's metrics store (e.g. Prometheus) keeps them per its own policy. Aggregate and non-identifying. |
| Audit log (kept) | The per-run advisory record on the `code run` line | **`advice_retention`** | Wherever the operator's logs are stored keeps it per its own policy. |

Only the third can carry a per-route record, and it is the one `advice_retention`
controls.

## Configuring it: `advice` and `advice_retention`

Both are set per profile in `PLIMSOLL_GRANTS_FILE` (see
[internal/grants](../internal/grants/)), both default to off, and they are independent
of each other: `advice` decides **who can act** on a finding, `advice_retention` decides
**what lasting record** the operator keeps.

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
- `operator`: findings go to the operator's side only (`/metrics`, and the audit log as
  far as `advice_retention` allows). Nothing is returned to the caller.
- `caller`: additionally returns the agent-fixable findings in the run result, so a
  product may feed them to its model for self-correction. A finding with no declared,
  granted route stays operator-only regardless, whether its fix is an allow-list line (a
  declared route is not granted), a check (a candidate the path suggests) or unknown
  (nothing names one). A repeated-read finding also stays operator-only: one fixed
  route read again and again is often a loop waiting for a change, where "cache the
  result" would break the loop, and the trace cannot tell the two apart.

`advice_retention` (controls the kept audit log only; no effect when `advice` is off):

- `none` (default): plimsoll writes **no** advisory record to the audit log. Advice can
  still produce the live hint to the caller and the `/metrics` totals; the kept log stays
  silent. This is the safe default, matching the rest of plimsoll: opt in to keep a
  lasting record, do not opt out of one.
- `aggregate`: writes the per-run **totals** (finding count and total estimated extra
  calls, added latency, and bytes) but no per-finding, per-route record.
- `detailed`: additionally writes `advice_finding_details`, one metadata-only record per
  finding (pattern, severity, remedy, route template, cost). These records are what the
  HTML report built from the exported audit log
  ([cmd/prospector-report](../cmd/prospector-report)) renders, so choose it when you want
  that per-route view, and set how long your log storage keeps records accordingly.

## Operator responsibilities

- **How long logs are kept is up to you.** plimsoll sets the retention *level* (how much
  detail it writes out); it cannot delete records from wherever your logs are stored. Set
  that storage's expiry time to match the sensitivity of the level you chose. `detailed`
  keeps per-route templates for the customer's traffic (still metadata only, but a record
  of how that customer uses the API).
- **Prefer the least detail that answers your question.** `/metrics` alone (with
  `advice_retention: none`) powers the Prospector dashboard, the advisor's metrics
  dashboard in `docs/dashboards`, without writing any per-run finding to the log. Use
  `aggregate` for per-run cost trends, and `detailed` only when the per-route detail is
  worth the kept record.
- **A finding never changes a run.** Advice is evidence attached after the run, like
  the isolation tier. It cannot decide whether a run happens, alter output, or slow the run down. Turning
  any of this on is safe for the run itself.
