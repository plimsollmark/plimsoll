package main

import (
	"encoding/json"
	"fmt"

	"github.com/plimsollmark/plimsoll/examples/sbom/cdxutil"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/record"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Plain JSON fields for the browser. Bytes remain base64; integers wider than
// JavaScript's exact range remain decimal strings. No protobuf decoder is shipped.
type exchangeJSON struct {
	Request  json.RawMessage `json:"request"`
	Response json.RawMessage `json:"response"`
}

// laterFields are the fields the protocol gained after the exchange format the published
// bills of materials were written in, by their place in the exchange. Every other field is
// written whatever its value (EmitUnpopulated); one of these only when it carries a value,
// so a run that never set it keeps the exchange, and the bill, its bundle reproduced
// before the field existed. TestExchangeFieldsAreTheFormatsOrLater fails when the
// protocol gains a field without a line here (or a decision to make every published
// bill again).
var laterFields = [][]string{
	{"request", "prefer_warm"}, // protocol 5: a Run cell may ask for a waiting pool member
	{"response", "warm"},       // protocol 5: whether one ran it
}

func exchangeBytes(s source) ([]byte, error) {
	m := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}
	req, err := m.Marshal(s.Request)
	if err != nil {
		return nil, err
	}
	resp, err := m.Marshal(s.Response)
	if err != nil {
		return nil, err
	}
	// encoding/json canonicalizes the protobuf JSON object's key order below.
	raw, err := json.Marshal(exchangeJSON{req, resp})
	if err != nil {
		return nil, err
	}
	var fields any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, path := range laterFields {
		dropUnset(fields, path)
	}
	return json.Marshal(fields)
}

// dropUnset deletes the member at path when it holds its field's zero value as
// EmitUnpopulated writes it (false, 0, "0", "", an empty list or object, null).
func dropUnset(v any, path []string) {
	for _, key := range path[:len(path)-1] {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		v = m[key]
	}
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	last := path[len(path)-1]
	switch x := m[last].(type) {
	case nil:
		delete(m, last)
	case bool:
		if !x {
			delete(m, last)
		}
	case float64:
		if x == 0 {
			delete(m, last)
		}
	case string:
		if x == "" || x == "0" {
			delete(m, last)
		}
	case []any:
		if len(x) == 0 {
			delete(m, last)
		}
	case map[string]any:
		if len(x) == 0 {
			delete(m, last)
		}
	}
}

func checkExchangeJSON(raw []byte, s source) error {
	if err := cdxutil.UniqueJSON(raw); err != nil {
		return err
	}
	var x exchangeJSON
	if err := json.Unmarshal(raw, &x); err != nil {
		return err
	}
	req, resp := new(plimsollv1.RunRequest), new(plimsollv1.RunResponse)
	if err := protojson.Unmarshal(x.Request, req); err != nil {
		return err
	}
	if err := protojson.Unmarshal(x.Response, resp); err != nil {
		return err
	}
	if _, err := record.CheckExchange(req, resp); err != nil {
		return fmt.Errorf("exchange.json digests: %w", err)
	}
	// Also bind fields not hashed by record (trace id, durations) to bundle bytes.
	if !proto.Equal(req, s.Request) || !proto.Equal(resp, s.Response) {
		return fmt.Errorf("exchange.json differs from the bundle's protobuf messages")
	}
	return nil
}
