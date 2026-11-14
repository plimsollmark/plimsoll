module github.com/plimsollmark/plimsoll/examples/sbom

go 1.26.2

toolchain go1.26.11

require (
	github.com/CycloneDX/cyclonedx-go v0.12.0
	github.com/plimsollmark/plimsoll v0.0.0-00010101000000-000000000000
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/tetratelabs/wazero v1.12.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/plimsollmark/plimsoll => ../..
