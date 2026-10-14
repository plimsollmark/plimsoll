package main

import (
	"encoding/json"
	"fmt"

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
	return json.Marshal(fields)
}

func checkExchangeJSON(raw []byte, s source) error {
	if err := uniqueJSON(raw); err != nil {
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
