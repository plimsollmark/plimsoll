//go:build js && wasm

// Command verifier is plimsoll's bundle verification compiled to WebAssembly, so a page
// can recheck a signed bundle in the reader's own browser: every record's digests
// recomputed from the stored request and response, every signature, the links between
// lines and each session's chain. It exposes one function, plimsollVerify(bundle, publicKey),
// which returns a JSON report; nothing leaves the browser. Build it from the repository root:
//
//	GOOS=js GOARCH=wasm go build -trimpath -ldflags=-s -o docs/examples/nemotron-agent/verify.wasm ./examples/nemotron-agent/verifier
//	cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" docs/examples/nemotron-agent/
package main

import (
	"bytes"
	"encoding/json"
	"syscall/js"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/sandbox"
)

type report struct {
	OK       bool            `json:"ok"`
	Detail   string          `json:"detail"`
	Lines    int             `json:"lines"`
	Runs     int             `json:"runs"`
	Sessions []sessionReport `json:"sessions"`
	Records  []recordReport  `json:"records"`
	KeyID    string          `json:"keyId"`
}

type sessionReport struct {
	Fingerprint string `json:"fingerprint"`
	Calls       uint64 `json:"calls"`
}

type recordReport struct {
	Line      int    `json:"line"`
	SHA256    string `json:"sha256"`
	Provider  string `json:"provider"`
	Isolation string `json:"isolation"`
	Sequence  uint64 `json:"sequence"`
	Session   string `json:"session"`
}

// verify recomputes everything VerifyBundle checks and says what it found.
func verify(bundle, pubPEM string) report {
	pub, err := attest.ParsePublicKey([]byte(pubPEM))
	if err != nil {
		return report{Detail: "the public key did not parse: " + err.Error()}
	}
	r := report{KeyID: attest.KeyID(pub)}
	entries, err := attest.ReadBundle(bytes.NewReader([]byte(bundle)))
	if err != nil {
		r.Detail = "the bundle did not read: " + err.Error()
		return r
	}
	r.Lines = len(entries)
	v := attest.NewVerifier(pub)
	rep, err := attest.VerifyBundle(entries, v)
	if err != nil {
		r.Detail = "refused: " + err.Error()
		return r
	}
	r.OK, r.Runs = true, rep.Runs
	for _, s := range rep.Sessions {
		r.Sessions = append(r.Sessions, sessionReport{Fingerprint: s.Session, Calls: uint64(s.Calls)})
	}
	for i, e := range entries {
		if len(e.Request) == 0 && len(e.Response) == 0 {
			continue
		}
		rec, _, err := attest.VerifyEntry(v, e)
		if err != nil {
			continue
		}
		r.Records = append(r.Records, recordReport{Line: i + 1, SHA256: rec.SHA256, Provider: rec.Provider, Isolation: rec.Isolation, Sequence: rec.Sequence, Session: rec.Session})
	}
	r.Detail = "every signature, digest, link and chain recomputed"
	return r
}

var _ sandbox.RunRecord

func main() {
	js.Global().Set("plimsollVerify", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 2 {
			return `{"ok":false,"detail":"plimsollVerify takes the bundle text and the public key PEM"}`
		}
		b, _ := json.Marshal(verify(args[0].String(), args[1].String()))
		return string(b)
	}))
	select {}
}
