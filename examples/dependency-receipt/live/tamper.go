package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/receipt"
	"github.com/plimsollmark/plimsoll/examples/dependency-receipt/runsclog"
)

// The connection the network fixture's install script starts (fixtures/packages/network),
// which the tampered receipt leaves out and the changed log moves.
const (
	tamperAddr = "203.0.113.7"
	tamperPort = 443
)

// dropped says what the tampered receipt leaves out: the connection, and the side it was on.
type dropped struct {
	Side string       `json:"side"`
	Call runsclog.Net `json:"call"`
}

// dropConnection opens the signed receipt at path, deletes the network fixture's connection
// from it and signs the rest again with the same key: a signer who leaves a call out. The
// signature is good; the check must still fail, since the log shows the call.
func dropConnection(path string, s *attest.Signer, pub ed25519.PublicKey) ([]byte, dropped, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, dropped{}, err
	}
	var env attest.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, dropped{}, err
	}
	var p receipt.Predicate
	subjects, err := attest.NewVerifier(pub).OpenStatement(env, receipt.PredicateType, &p)
	if err != nil {
		return nil, dropped{}, err
	}
	var d dropped
	for _, side := range []struct {
		name string
		list *[]runsclog.Net
	}{{"effected", &p.Effected.Network}, {"attempted", &p.Attempted.Network}, {"undetermined", &p.Undetermined.Network}} {
		i := slices.IndexFunc(*side.list, func(n runsclog.Net) bool {
			return n.Kind == "connect" && n.Addr == tamperAddr && n.Port == tamperPort
		})
		if i >= 0 && d.Side == "" {
			d = dropped{Side: side.name, Call: (*side.list)[i]}
			*side.list = slices.Delete(*side.list, i, i+1)
		}
	}
	if d.Side == "" {
		return nil, dropped{}, fmt.Errorf("the receipt at %s states no connection to %s:%d", path, tamperAddr, tamperPort)
	}
	env2, err := receipt.Sign(s, p, subjects)
	if err != nil {
		return nil, dropped{}, err
	}
	out, err := json.Marshal(env2)
	return append(out, '\n'), d, err
}

// byteEdit is the one byte changed in the tampered log: where, from what, to what, and the
// text around it, as the page shows it.
type byteEdit struct {
	Offset int    `json:"offset"`
	Was    string `json:"was"`
	Now    string `json:"now"`
	Before string `json:"before"` // up to 60 bytes before the changed one
	After  string `json:"after"`  // up to 30 bytes after it
}

// oneByteEdit picks the byte to change in the network run's log: the last digit of the
// connection's address, the first time the log names it, so the changed log says the
// package connected somewhere else.
func oneByteEdit(raw []byte) (byteEdit, error) {
	needle := []byte("Addr: " + tamperAddr + ",")
	i := bytes.Index(raw, needle)
	if i < 0 {
		return byteEdit{}, errors.New("the log never names the connection's address")
	}
	off := i + len(needle) - 2 // the address's last digit
	if raw[off] != '7' {
		return byteEdit{}, fmt.Errorf("byte %d is %q, not the address's last digit", off, raw[off])
	}
	from, to := max(0, off-60), min(len(raw), off+31)
	return byteEdit{Offset: off, Was: "7", Now: "8", Before: string(raw[from:off]), After: string(raw[off+1 : to])}, nil
}

// applyEdit returns a copy of raw with e made, refusing an edit that does not fit raw.
func applyEdit(raw []byte, e byteEdit) ([]byte, error) {
	if e.Offset < 0 || e.Offset >= len(raw) || len(e.Was) != 1 || len(e.Now) != 1 || raw[e.Offset] != e.Was[0] || e.Was == e.Now {
		return nil, fmt.Errorf("the edit at byte %d does not fit the log", e.Offset)
	}
	if !bytes.HasSuffix(raw[:e.Offset], []byte(e.Before)) || !bytes.HasPrefix(raw[e.Offset+1:], []byte(e.After)) {
		return nil, fmt.Errorf("the text around byte %d is not what the edit states", e.Offset)
	}
	out := slices.Clone(raw)
	out[e.Offset] = e.Now[0]
	return out, nil
}
