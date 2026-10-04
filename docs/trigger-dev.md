# Trigger.dev code tool

Give a Trigger.dev chat agent one `executeCode` tool for Python or JavaScript. The
tool joins three properties in every answer:

| Property | What the agent receives | What enforces it |
|---|---|---|
| Persistent cells | `stateKept`, `filesPersist`, `freshInterpreter`, `freshSandbox` | A plimsoll session keeps an interpreter and work directory for calls under one verified conversation key. |
| Isolation floor | `isolation` | The caller sends `minimumIsolation`; the daemon checks before dispatch and the client checks the answer. The tier is provider and configuration evidence, not an attestation of an unbroken boundary. |
| Checked run record | `recordSha256` | The client recomputes the request, result and record digests before returning the tool result. The digest identifies the checked record; it is not a signature. |

Use the `record` on the lower-level client result when an application needs the
full record, or [sign and verify records](run-records.md) outside the daemon when
it needs a portable signed bundle. A successful record check proves consistency
between the call and the returned result. It cannot prove that the guest's
computation was honest or that the sandbox boundary was never breached.

The add-on follows [Trigger.dev's code sandbox recipe](https://trigger.dev/docs/ai-chat/patterns/code-sandbox):
`onTurnStart` warms the sandbox, calls under the same run use cells, and
`onChatSuspend` or `onComplete` closes it. The first call after a suspend starts
with `freshSandbox: true`; state survives calls while the session remains open,
not a suspend. Its idle close and the daemon's session lifetime also bound leaked
sessions after a worker crash.

## Deploy a task

The [plimsoll Trigger.dev starter](https://github.com/plimsollmark/plimsoll-trigger-starter)
is a separate deployable project. It pins a published client, shows a production
floor of `kernel`, has a scripted test (Trigger.dev's offline harness and a
scripted model, so no AI call) that runs against a daemon you name, and includes
a deployed trial task that makes two calls to the same Python interpreter. Its README gives the
daemon, TLS, caller token, Trigger.dev environment and deployment steps.
The [in-tree chat example](../examples/trigger-chat/README.md) remains a local
framework example; its `container` floor is for that example. Raise the floor
before using it with hostile code.

For production with code from untrusted tenants, require at least `kernel`
isolation. Docker reaches that tier only after the daemon verifies gVisor's
`runsc` runtime. If your threat model requires a VM boundary, require `vm` and
use a VM provider; current VM providers do not keep cells, so the tool reports
`stateKept: false` and `filesPersist: false`. Do not advertise persistence on a
provider that does not support it. See [isolation tiers](isolation-tiers.md),
[session tradeoffs](sessions.md#what-a-session-gives-up), and
[hardened mode](hardened-mode.md).

A deployed Trigger.dev worker needs a reachable `plimsolld` URL over TLS and a
caller token with `code:run`. `localhost` on the worker is the worker, not the
operator's daemon. Keep the daemon's listener private or behind an authenticated
TLS ingress where possible. Grant the task only its own caller token, and set
the daemon's session, concurrency, rate and resource caps before admitting
outside traffic. A public URL without the caller token still exposes an auth
surface, so monitor and rotate that token as an operational credential.
