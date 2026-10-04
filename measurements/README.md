# Measurements

Programs that time plimsoll's providers, each writing its raw samples and a page into
[docs/measurements](../docs/measurements/). The pages are published at
`https://plimsollmark.github.io/plimsoll/measurements/<name>/index.html`.

| Directory | What it times | Page |
|---|---|---|
| [session-latency](session-latency/) | what an agent's code tool pays per call: fresh runs, session calls, warm and first cells, a resume, keeping data loaded against reloading it; docker (runc and gVisor) and OpenShell | [session latency](https://plimsollmark.github.io/plimsoll/measurements/session-latency/index.html) |
| [warm-pool](warm-pool/) | a session's first call with and without a warm pool (`SANDBOX_SESSION_POOL`), language hints, and the probe that came before the pool | [warm pool](https://plimsollmark.github.io/plimsoll/measurements/warm-pool/index.html) |

They call the providers directly, not through plimsolld, and need the images
`make docker-images` builds; the gVisor runs need it installed
([docs/gvisor.md](../docs/gvisor.md)). Each page says how to rerun it. The numbers are one
machine's: what carries over is the ratios and where the time goes, not the milliseconds.
