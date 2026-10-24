# The `plimsoll` property names in CycloneDX

CycloneDX lets a document carry name and value pairs ("properties") whose names are
namespaced by whoever defines them. The bills of materials `examples/sbom` writes for a
plimsoll run use the `plimsoll` namespace, defined here. Every value is a string. A value
copied from a run record is exactly as the signed record states it; `examples/sbom -check`
confirms each one against that record, so a property is only as good as that check.

## On the document's metadata

| Name | Value |
|---|---|
| `plimsoll:bundle_sha256` | SHA-256 of the bundle (the signed file of runs) the document's run is a line of; the same digest is on the document's attestation reference |
| `plimsoll:bundle_line` | the run's line number in that bundle, from 1 |
| `plimsoll:emitter` | the program that wrote the document: `examples/sbom` |
| `plimsoll:qualification_sha256` | SHA-256 of the qualification file whose statement for this run the document carries; present only then |

## On the program that ran (the component holding the request's files)

| Name | Value |
|---|---|
| `plimsoll:request_sha256` | the run record's request digest |
| `plimsoll:result_sha256` | the run record's result digest (also on the workflow's output) |
| `plimsoll:record_sha256` | the run record's own digest |
| `plimsoll:trace_id` | the caller's correlation ID for the run, when the request carried one; opaque, 1 to 64 letters, digits or `. _ : -` |
| `plimsoll:author_kind` | who wrote the program, as the caller supplied it (`agent`); not verified |
| `plimsoll:author_kind_basis` | where `author_kind` came from; today always `supplied example context, unverified` |

## On each file of the request

| Name | Value |
|---|---|
| `plimsoll:bytes` | the file's length in bytes |

## On the workflow (how the run was done)

| Name | Value |
|---|---|
| `plimsoll:provider` | the sandbox provider that ran it, as the daemon reported (`docker`, `e2b`, `agentsandbox`, ...) |
| `plimsoll:isolation` | the isolation tier the daemon reported: `process`, `container`, `kernel` or `vm`; configuration and provider evidence plus a startup check, not hardware attestation |
| `plimsoll:minimum_isolation` | the lowest tier the request would accept |
| `plimsoll:timeout_ms` | the request's time limit in milliseconds |
| `plimsoll:grant` | the name of the server-side grant profile the run used, or `none` |
| `plimsoll:outcome` | how the run ended: `completed`, `setup_failed`, `timed_out`, `protocol_error` or `runner_failed` |
| `plimsoll:policy` | the daemon's policy identity for the run, when it stated one |
| `plimsoll:instance` | the sandbox instance that ran it, as the record states it: a typed reference such as `k8s-pod-uid:` and a pod's UID; present only when the record names one |

## On each executed step

| Name | Value |
|---|---|
| `plimsoll:exit_code` | the step's exit code |
| `plimsoll:duration_ms` | how long the step took, in milliseconds |
| `plimsoll:timed_out` | `true` when the step hit the time limit |
| `plimsoll:stdout_truncated`, `plimsoll:stderr_truncated` | `true` when that output was cut at the size limit |

## On the image the run executed in

| Name | Value |
|---|---|
| `plimsoll:environment` | the record's content-addressed identity of the environment (for docker, `docker-image:sha256:...`) |
| `plimsoll:software_identity` | the record's identity of the software the platform verified, when it stated one |

Evidence entries use two property names of the same namespace for what they hold:
`plimsoll:run_record` (the signed run record, its line of the bundle and a plain copy of the
request and result) and `plimsoll:qualification` (the platform's signed qualification
statement for the run).
