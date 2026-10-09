module github.com/plimsollmark/plimsoll

go 1.26.2

// The canonical build uses the security-patched 1.26.9 toolchain (govulncheck is
// clean there; earlier 1.26.x had stdlib advisories in the reverse-proxy and
// HTTP/2 paths this TCB calls). A `toolchain` line binds only this module's own
// build, not the version it requires of dependents, so build plimsolld with
// >= 1.26.9.
toolchain go1.26.9

require (
	connectrpc.com/connect v1.20.0
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/net v0.60.0
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/protobuf/cmd/protoc-gen-go
)
