module github.com/plimsollmark/plimsoll/examples/capsule

go 1.27.0

replace github.com/plimsollmark/plimsoll => ../..

require (
	github.com/action-state-group/capsule-emit-go v0.2.0
	github.com/plimsollmark/plimsoll v0.0.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/action-state-group/agent-action-capsule/go v0.5.2-0.20260926235627-439dc02c05d1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/veraison/go-cose v1.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
