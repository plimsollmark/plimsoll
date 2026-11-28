# Vendored OpenShell protos

Upstream: https://github.com/ai-openshell/openshell (formerly NVIDIA/OpenShell), tag
`v0.1.10`, commit `152c59d3178039e3fbb4a5595f9fff7216a6be92`, directory `proto/`.
Licensed under Apache-2.0 by NVIDIA CORPORATION & AFFILIATES; the upstream license is
`LICENSE` beside this file (copied from the same tag), and each `.proto` keeps its SPDX
header. Upstream ships no NOTICE file (its `THIRD-PARTY-NOTICES` covers its own
dependencies, which these files do not include). plimsoll is an independent project,
not affiliated with or endorsed by NVIDIA.

Files, copied byte for byte (SHA-256):

| file | sha256 |
|---|---|
| `proto/openshell.proto` | `fd8f78f439506a5264fcd960c6fcfd8eb7443780f03d879eaec5bcf3fc640970` |
| `proto/datamodel.proto` | `e50bd875a760f54b80269c65ee47984cae424fb623b7f59551ba62550c23e70b` |
| `proto/sandbox.proto` | `0c2525eed548930dd2245a005224f1988f78b03ff25be9b4dabdb8c123956519` |
| `proto/options.proto` | `8c14e8f255529165527e8e5a38068c965ad851db303f1926ed50ab184cbde65d` |

From v0.1.2 (commit `6648bd0`, vendored 2026-09-28) to v0.1.10 every change to these
files is an addition (`buf breaking` against the v0.1.2 copy, default and `WIRE` rules:
none), so the client reads a v0.1.2 gateway's answers as before. The provider's
read-back refuses a field this copy does not define, so a newer gateway that adds one
to a sandbox's spec or configuration is refused until this copy is updated.

`openshell.proto` defines the `openshell.v1.OpenShell` service (sandbox lifecycle,
`ExecSandbox`, `ExecSandboxInteractive`, `GetSandboxConfig`, `GetGatewayInfo`, and
the rest of the gateway API); the other three are its import closure. This is the
same set OpenShell's own Go SDK generates from.

Generated code: `gen/go/openshell/` (`make generate`, configured by `buf.gen.yaml`
here). The client speaks the gRPC protocol through connect-go
(`connect.WithGRPC()`), so no grpc-go or OpenShell SDK dependency is added.

To update: copy the four files from a new upstream tag, update the commit and the
hashes above, run `make generate`, and commit the protos and `gen/` together.
