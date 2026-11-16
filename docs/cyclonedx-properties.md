# `plimsoll` CycloneDX Property Taxonomy

This is the `plimsoll` property namespace and name taxonomy for
[CycloneDX](https://cyclonedx.org/), for registration in the
[CycloneDX Property Taxonomy](https://github.com/CycloneDX/cyclonedx-property-taxonomy).
It is administered by the plimsoll maintainers
([github.com/plimsollmark](https://github.com/plimsollmark)) and follows that repository's
grammar: a top-level namespace, a colon, and a name.

Taxonomy version 1, 2026-11-16. Changes are listed under [Changes](#changes).

The key words "MUST", "MUST NOT", "SHOULD" and "MAY" are to be interpreted as described in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## What the namespace is for

[plimsoll](https://github.com/plimsollmark/plimsoll) runs code that an AI agent wrote inside
a sandbox, and returns with every run a *run record*: digests of what was asked and what came
back, plus which sandbox ran it and how strong its wall was. A separate program signs those
records. plimsoll's converter, `examples/sbom`, restates one signed run as a CycloneDX 1.6
BOM, so the run can be stored and read by tools that already read CycloneDX.

Most CycloneDX properties describe what a piece of software *is*. The `plimsoll` properties
describe what happened when one program *ran*: where it ran, behind what wall, how each step
ended, and the digests that tie each statement back to the signed record.

Two rules govern the namespace:

- **CycloneDX's own fields first.** The BOM states in CycloneDX's own fields
  everything CycloneDX can say: the writing tool (`metadata.tools`), the time
  (`metadata.timestamp`, the workflow's `timeStart` and `timeEnd`), the program and each of
  its files with SHA-256 hashes, the image as a `container` component with a `pkg:oci` purl,
  hashes and a link to the image's own BOM, the steps as `formulation` tasks, and what the
  BOM claims, with its evidence and confidence, in `declarations`. The properties below carry
  what none of those fields can, and repeat five values a field already holds, so a reader can
  find them by name: `plimsoll:emitter` (the tool in `metadata.tools`), `plimsoll:bundle_sha256`
  and `plimsoll:qualification_sha256` (the hashes on their external references),
  `plimsoll:record_sha256` (the workflow's `uid`) and `plimsoll:result_sha256` (written on both
  the program and the workflow's output).
- **Copied facts, not judgments.** Every value is copied from the signed run record, from the
  stored request and response, or from the signed bundle, except `plimsoll:author_kind` and
  `plimsoll:author_kind_basis`, which are marked as unverified. The record's digests cover the
  stored request and response except two fields the record leaves out on purpose, the trace ID
  and the step durations; those two are bound only by the harness's signed link over the
  stored bytes. `examples/sbom -check` (and the same check in the browser, on the
  [example page](https://plimsollmark.github.io/plimsoll/examples/sbom/)) confirms each copied
  value against the signed record and the stored bytes the harness's link signs. Anyone can
  write a `plimsoll` property into a BOM, so a reader MUST NOT rely on one that this check has
  not confirmed.

One program writes these names today: `examples/sbom`. It maps an answered single project run
(not a snippet, and not a call in a session) whose record names the image it ran in, which
today means a run on the `docker`, `dockercloud` or `agentsandbox` provider, and it refuses any
other run. The values listed below are the ones it can write; a later version of this taxonomy
may add values when a writer maps more runs.

## Terms

| Term | Meaning |
|---|---|
| run | One call that executes code. A BOM restates a *project* run: files, then build, lint and run steps, stopping at the first failure. |
| daemon | `plimsolld`, the server that accepts runs and hands each one to a provider. |
| provider | The backend that actually runs the code, such as a locked-down `docker run` or a hosted microVM. |
| isolation tier | How strong the wall between the code and the host is, as the daemon reports it: one of four levels, defined under `plimsoll:isolation`. A reported tier is the provider's configuration and evidence plus a check the daemon runs at startup; it is not a hardware attestation. |
| floor | The weakest isolation tier the caller accepts. A daemon that cannot meet it refuses the run before any code starts. |
| run record | The facts the daemon states about one run: the request digest, the result digest, the provider, the isolation tier, the environment, the times, and the record's own digest. The daemon holds no signing key. [Run records](run-records.md) defines every field. |
| request digest, result digest, record digest | Lowercase hexadecimal SHA-256 over the request as sent, the result as sent, and every field of the record, each over a byte layout defined in [Run records](run-records.md). |
| harness, bundle | The harness is a program outside the daemon that keeps a file of runs (the *bundle*, one run per line), signs each run's record and links each line to the one before it, so a line cannot be removed or reordered unseen. |
| step | One command of a project, with its own exit code. |
| outcome | The stable classification of how a project run ended, defined under `plimsoll:outcome`. |
| grant profile | A named permission, configured on the server, for a run to reach one host API through plimsoll's broker. A run with no grant profile is given no network route by plimsoll; that is the provider's configuration, not something the run record measures. |
| environment | The exact image selected for the run, as a typed digest such as `docker-image:sha256:...`. |
| software identity | The manifest of the executable image selected, with its platform, such as `oci-manifest:linux/amd64@sha256:...`. |
| qualification statement | A signed verdict from a platform's own judge on whether the code a run executed did its job, decided from evidence that code could not write. Its subject is the run's record. |
| caller | The program that sent the run to the daemon. |

## Value formats

Every CycloneDX property value is a string. Within it:

- _Digest_: 64 lowercase hexadecimal characters, a SHA-256 value, with no prefix.
- _Integer_: a base-10 number with no leading zeros and no unit in the value; the unit is in
  the name (`_ms` for milliseconds). A value is negative only where its row says it can be.
- _Boolean_: `true` or `false`, case sensitive. A boolean property is always written, never
  omitted to mean `false`.
- _Enumeration_: exactly one of the values listed for the property, case sensitive.
- _Typed reference_: a kind (lowercase letters, digits and `-`), a colon, and a value, as
  the run record states it, for example `docker-image:sha256:<digest>` or `k8s-pod-uid:<UID>`.
  A reader MUST treat a kind it does not know as opaque, not as an error.

A property listed as written "exactly once" on an element appears there once, with an empty
value when the run record states none, as noted per property. A property listed as "at most
once" is omitted when it has no value.

## Where the properties go

| Element (JSON path) | What it is | Properties |
|---|---|---|
| `$.properties` | The BOM as a whole | `bundle_sha256`, `bundle_line`, `emitter`, `qualification_sha256` |
| `$.metadata.component` | The program that ran (a component of type `application` holding the request's files) | `request_sha256`, `result_sha256`, `record_sha256`, `trace_id`, `author_kind`, `author_kind_basis` |
| `$.metadata.component.components[]` | Each file of the request (type `file`) | `bytes` |
| `$.formulation[].workflows[]` | How the run was done (the workflow ran the program; its output is the run's result, not a built artifact) | `provider`, `isolation`, `minimum_isolation`, `timeout_ms`, `grant`, `outcome`, `policy`, `instance` |
| `$.formulation[].workflows[].outputs[]` | The run's result | `result_sha256` |
| `$.formulation[].workflows[].tasks[].steps[].commands[]` | Each executed step | `exit_code`, `duration_ms`, `timed_out`, `stdout_truncated`, `stderr_truncated` |
| `$.components[]`, the component with `bom-ref` `image` | The image the run executed in (type `container`) | `environment`, `software_identity` |
| `$.declarations.evidence[].propertyName` | Evidence entries | `run_record`, `qualification` |

A `plimsoll` property MUST NOT be used on an element other than the one listed for it here.

## The BOM as a whole: `$.properties`

| Property | Description |
|---|---|
| `plimsoll:bundle_sha256` | SHA-256 of the complete bundle file the run is a line of; the program component's `attestation` external reference, which links the bundle, carries the same digest. _Digest_. MUST appear exactly once. |
| `plimsoll:bundle_line` | The run's line number in that bundle, counting from 1, as the harness's signed link states it. _Integer_. MUST appear exactly once. |
| `plimsoll:emitter` | The program that wrote the BOM. Today the only value is `examples/sbom`. MUST appear exactly once. |
| `plimsoll:qualification_sha256` | SHA-256 of the qualification file whose statement for this run the BOM carries as evidence. _Digest_. MAY appear at most once; present only when the BOM carries a qualification statement. |

## The program that ran: `$.metadata.component`

| Property | Description |
|---|---|
| `plimsoll:request_sha256` | The run record's request digest: SHA-256 over the protocol number, the floor, the time limit, the software rule and the payload. _Digest_. MUST appear exactly once. |
| `plimsoll:result_sha256` | The run record's result digest: SHA-256 over the result as sent (the outcome, the steps with their exit codes and output, the truncation flags, the artifacts). _Digest_. MUST appear exactly once. The workflow's output carries the same value. |
| `plimsoll:record_sha256` | The run record's own digest, over every field of the record. _Digest_. MUST appear exactly once. |
| `plimsoll:trace_id` | The caller's correlation ID for the run, an opaque key into the caller's own log, exactly as the caller sent it in the request. The daemon's audit log accepts only 1 to 64 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `:` and `-` and drops any other ID whole, but the stored request keeps what the caller sent, so this value MAY not conform. Not covered by the run record's digests: bound only by the harness's signed link over the stored request. MAY appear at most once; present only when the request carried one. |
| `plimsoll:author_kind` | Who wrote the program, as the caller supplied it. Today the only value is `agent`. **Not verified**: the run record does not establish authorship. MUST appear exactly once. |
| `plimsoll:author_kind_basis` | Where `plimsoll:author_kind` came from, in words. Today always `supplied example context, unverified`. MUST appear exactly once. |

## Each file of the request: `$.metadata.component.components[]`

| Property | Description |
|---|---|
| `plimsoll:bytes` | The file's length in bytes. _Integer_. MUST appear exactly once on each file component. The file's SHA-256 is in the component's `hashes`. |

## How the run was done: `$.formulation[].workflows[]`

| Property | Description |
|---|---|
| `plimsoll:provider` | The provider that ran the code, as the daemon reported it. _Enumeration_: `docker` (a locked-down `docker run`), `dockercloud` (a Docker Cloud Sandboxes microVM), `agentsandbox` (a Kubernetes agent-sandbox pod). MUST appear exactly once. |
| `plimsoll:isolation` | The isolation tier the daemon reported for the run, weakest first. _Enumeration_: `process` (the code runs inside the daemon's own process, behind a WebAssembly engine only), `container` (an operating-system container sharing the host's kernel), `kernel` (a container whose system calls are answered by a separate kernel in user space, gVisor's `runsc`, not by the host's kernel), `vm` (a virtual machine with its own kernel, separated by the processor's hardware virtualization). The tier is the provider's configuration and evidence plus a check the daemon runs at startup, not a hardware attestation and not a measurement of this run. `process` is the tier of the `wasm` provider, which runs no projects, so it does not appear here. The meaning of each tier, and what each provider's tier rests on, is in [Isolation tiers](isolation-tiers.md). MUST appear exactly once. |
| `plimsoll:minimum_isolation` | The floor the request set: the weakest tier it accepts. _Enumeration_: one of the `plimsoll:isolation` values, or empty when the request set no floor. MUST appear exactly once. |
| `plimsoll:timeout_ms` | The time limit the request asked for, in milliseconds, as the caller sent it; `0` or a negative value leaves the limit to the provider's default. The daemon also caps it at its own ceiling, and the limit actually in force is not in the run record. _Integer_, MAY be negative. MUST appear exactly once. |
| `plimsoll:grant` | The name of the grant profile the request named, or `none` when it named none; a daemon refuses to load a profile named `none`, so the two cannot be confused. Whether the run could reach a network is the provider's configuration, not something the run record measures. MUST appear exactly once. |
| `plimsoll:outcome` | How the project run ended. _Enumeration_: `completed` (every step ran; each step's exit code says whether it passed), `setup_failed` (preparing the project failed before any step began), `timed_out` (the run exceeded its time limit), `protocol_error` (the program inside the sandbox that runs the steps and the daemon disagreed), `runner_failed` (that program, or a hosted provider's command service, failed after a step began). [Run results](run-results.md) defines each. MUST appear exactly once. |
| `plimsoll:policy` | The sandbox policy the provider applied, as the run record states it. _Typed reference_, one of: `seccomp:sha256:<digest>` (the system-call filter a docker run applied, the profile file named by the SHA-256 of its bytes), `seccomp:docker-default` (docker's own built-in filter), `seccomp:unconfined` (no system-call filter at all), `seccomp:skipped:runsc` (a run under gVisor's `runsc`, where no host filter is applied and gVisor's own kernel answers the code's system calls). A present policy is not by itself evidence that a filter was applied. MAY appear at most once; present only when the run record states one. |
| `plimsoll:instance` | The sandbox instance that ran the code, such as `k8s-pod-uid:` and the UID the Kubernetes API server gave the pod: an opaque join key to evidence kept outside plimsoll, never a name or a path. _Typed reference_, at most 160 bytes. MAY appear at most once; present only when the run record states one. |

## The run's result: `$.formulation[].workflows[].outputs[]`

| Property | Description |
|---|---|
| `plimsoll:result_sha256` | The run record's result digest, the same value as on the program component. _Digest_. MUST appear exactly once on the output. |

## Each executed step: `$.formulation[].workflows[].tasks[].steps[].commands[]`

| Property | Description |
|---|---|
| `plimsoll:exit_code` | The step's exit code. A non-zero exit code is a normal result, not a failure of the run; `-1` means the step ended with neither an exit status nor a signal. _Integer_. MUST appear exactly once. |
| `plimsoll:duration_ms` | How long the step took, in milliseconds. Not covered by the run record's digests: bound only by the harness's signed link over the stored response. _Integer_. MUST appear exactly once. |
| `plimsoll:timed_out` | Whether the step hit the time limit. _Boolean_. MUST appear exactly once. |
| `plimsoll:stdout_truncated` | Whether the step's standard output was cut at the size limit. _Boolean_. MUST appear exactly once. |
| `plimsoll:stderr_truncated` | Whether the step's standard error was cut at the size limit. _Boolean_. MUST appear exactly once. |

## The image the run executed in: the `image` component of `$.components[]`

| Property | Description |
|---|---|
| `plimsoll:environment` | The run record's identity of the image selected for the run: `docker-image:sha256:<digest>`, `dockercloud-image:sha256:<digest>` or `agentsandbox-image:sha256:<digest>`. _Typed reference_. MUST appear exactly once. |
| `plimsoll:software_identity` | The run record's identity of the executable image selected, with its platform, such as `oci-manifest:linux/amd64@sha256:<digest>`. _Typed reference_. MUST appear exactly once: `oci-manifest:<platform>@sha256:<digest>` for a docker run, and empty for a Docker Cloud or agent-sandbox run, whose records state none. |

## Evidence property names

CycloneDX evidence entries (`$.declarations.evidence[]`) carry no free-form properties.
Each names the property it substantiates in `propertyName`, and the BOM uses two names of
this namespace there:

| Name | What the evidence entry holds |
|---|---|
| `plimsoll:run_record` | The signed run record (a DSSE envelope holding an in-toto statement), the harness's public key, the run's line of the bundle exactly as stored (the binary request and response, the record's envelope and the harness's signed link placing the line), and a plain JSON copy of the request and result checked against those bytes. MUST appear exactly once. |
| `plimsoll:qualification` | The platform's signed qualification statement for the run (a DSSE envelope); its subject is this run's record. MAY appear at most once; present only with `plimsoll:qualification_sha256`. |

The BOM itself is not signed today; the signed run record inside it is. If you need the BOM signed, open an
[issue](https://github.com/plimsollmark/plimsoll/issues).

## Example

An abridged BOM from the [example page](https://plimsollmark.github.io/plimsoll/examples/sbom/),
which publishes complete ones beside the signed bundle they restate:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "properties": [
    {"name": "plimsoll:bundle_sha256", "value": "3f7028e3e5d367770ac721306548d7d741a9eeb284f8bbd4441320f76076e772"},
    {"name": "plimsoll:bundle_line", "value": "3"},
    {"name": "plimsoll:emitter", "value": "examples/sbom"}
  ],
  "metadata": {
    "component": {
      "type": "application", "bom-ref": "program",
      "properties": [
        {"name": "plimsoll:request_sha256", "value": "b5386b8a32215a20f843fddccc796543ab45ff0bf7fa63d38ca87855d201a7e1"},
        {"name": "plimsoll:record_sha256", "value": "29c2e7b07429f25bbedda4f4572b4720837437bbf1f6e924a75d7d44739509d6"},
        {"name": "plimsoll:trace_id", "value": "manifest-poc-run-2"}
      ]
    }
  },
  "formulation": [{"workflows": [{
    "properties": [
      {"name": "plimsoll:provider", "value": "docker"},
      {"name": "plimsoll:isolation", "value": "kernel"},
      {"name": "plimsoll:minimum_isolation", "value": "kernel"},
      {"name": "plimsoll:grant", "value": "none"},
      {"name": "plimsoll:outcome", "value": "completed"}
    ],
    "tasks": [{"steps": [{"commands": [{
      "properties": [
        {"name": "plimsoll:exit_code", "value": "3"},
        {"name": "plimsoll:timed_out", "value": "false"}
      ]
    }]}]}]
  }]}]
}
```

## Changes

A name's meaning never changes in place. A different meaning gets a new name; a name that is
no longer written is listed here as retired and is never reused. New names and new
enumeration values may be added in a later version. A reader SHOULD ignore a `plimsoll` name
it does not know.

| Version | Date | Change |
|---|---|---|
| 1 | 2026-11-16 | First versioned taxonomy: value formats, placement and how often each property appears. Names unchanged from the unversioned list. |

Questions and requests: [plimsoll's issues](https://github.com/plimsollmark/plimsoll/issues).
