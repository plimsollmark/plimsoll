# Vendored OpenShell protos

Upstream: https://github.com/NVIDIA/OpenShell, tag `v0.1.2`, commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`, directory `proto/`. Licensed under
Apache-2.0 by NVIDIA CORPORATION & AFFILIATES; the upstream license is `LICENSE`
beside this file, and each `.proto` keeps its SPDX header. Upstream ships no NOTICE
file. plimsoll is an independent project, not affiliated with or endorsed by NVIDIA.

Files, copied byte for byte (SHA-256):

| file | sha256 |
|---|---|
| `proto/openshell.proto` | `2e31d0faca652b91729f88bd4053447e5d162e74de7dbacdcc06327ed82e5b95` |
| `proto/datamodel.proto` | `e50bd875a760f54b80269c65ee47984cae424fb623b7f59551ba62550c23e70b` |
| `proto/sandbox.proto` | `ed3d2650c8d1c4cbb653259c6055adba2dba8a51498ab6a1b2cfc339997ab2b9` |
| `proto/options.proto` | `10c8a99b505047f759951285fdae6068afd267ef672d00a65385a91ee8d027ee` |

`openshell.proto` defines the `openshell.v1.OpenShell` service (sandbox lifecycle,
`ExecSandbox`, `ExecSandboxInteractive`, `GetSandboxConfig`, `GetGatewayInfo`, and
the rest of the gateway API); the other three are its import closure. This is the
same set OpenShell's own Go SDK generates from.

Generated code: `gen/go/openshell/` (`make generate`, configured by `buf.gen.yaml`
here). The client speaks the gRPC protocol through connect-go
(`connect.WithGRPC()`), so no grpc-go or OpenShell SDK dependency is added.

To update: copy the four files from a new upstream tag, update the commit and the
hashes above, run `make generate`, and commit the protos and `gen/` together.
