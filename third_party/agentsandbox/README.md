# Vendored agent-sandbox protos

Upstream: https://github.com/kubernetes-sigs/agent-sandbox, tag `v1.0.7`, commit
`807cc37107bd7c012115afac9fa9c3b77b8365c2`, file `packages/sandboxd/spec/process/v1/process.proto`.
Licensed under Apache-2.0 by The Kubernetes Authors; the upstream license is `LICENSE` beside
this file, and the `.proto` keeps its copyright header. Upstream ships no NOTICE file. plimsoll is
an independent project, not affiliated with or endorsed by the Kubernetes project.

Files, copied byte for byte (SHA-256):

| file | sha256 |
|---|---|
| `proto/process/v1/process.proto` | `d233a27fe9f63945984a52b74d47c6ffdf2f81ebbe61f954413bb933299cbfda` |

`process.proto` defines `process.v1.ProcessService`, which `sandboxd` (the runtime daemon in each
agent-sandbox pod) serves on its gRPC port: `Start` (a streamed process), `Execute`,
`WriteStdin`, `SendSignal` and `ResizeTTY`. Its one import is a protobuf well-known type.

Generated code: `gen/go/agentsandbox/` (`make generate`, configured by `buf.gen.yaml` here). The
client speaks the gRPC protocol through connect-go (`connect.WithGRPC()`), so no grpc-go or
agent-sandbox SDK dependency is added.

To update: copy the file from a new upstream tag, update the commit and the hash above, run
`make generate`, and commit the proto and `gen/` together.
