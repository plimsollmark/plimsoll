module github.com/plimsollmark/plimsoll/clients/mcp

go 1.26.2

toolchain go1.26.10

require (
	connectrpc.com/connect v1.20.0
	github.com/fxamacker/cbor/v2 v2.9.4
	github.com/go-webauthn/webauthn v0.18.2
	github.com/google/jsonschema-go v0.4.3
	github.com/plimsollmark/plimsoll v0.0.0-00010101000000-000000000000
)

require (
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.57.0 // indirect
)

require (
	github.com/modelcontextprotocol/go-sdk v1.8.0
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/net v0.60.0
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/plimsollmark/plimsoll => ../..
