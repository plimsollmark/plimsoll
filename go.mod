module github.com/plimsollmark/plimsoll

// The go line is the security floor, and a go install of a release obeys it: Go applies a
// toolchain line only to the module being worked in, so with the floor at 1.26.2 a user's
// older Go built plimsolld with itself (finding release-19). 1.26.11 is the first with
// govulncheck clean: 1.26.10 has GO-2026-6859, an HTTP/1 server panic when a handler that
// reads a MaxBytesReader body sets a header, and the RPC layer caps every body with one;
// 1.26.9 has GO-2026-6809 in crypto/x509; earlier 1.26.x had stdlib advisories in the
// reverse-proxy and HTTP/2 paths this TCB calls.
go 1.26.11

require (
	connectrpc.com/connect v1.20.0
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/net v0.62.0
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/protobuf/cmd/protoc-gen-go
)
