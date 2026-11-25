package record

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

// protojson reads an integer in a string from its leading digits; UnmarshalJSON refuses
// what it reads loosely, in a message nested in another too, and reads every whole
// decimal, and every string that is no integer's, as protojson does.
func TestUnmarshalJSONRefusesTextAfterANumber(t *testing.T) {
	record := func() proto.Message { return &plimsollv1.RunRecord{} }
	response := func() proto.Message { return &plimsollv1.RunResponse{} }
	for _, c := range []struct {
		json string
		into func() proto.Message
	}{
		{`{"sequence":"5 6"}`, record}, {`{"sequence":"5,"}`, record}, {`{"sequence":"5\u0000"}`, record},
		{`{"startedUnixMs":"1790000000000 1"}`, record}, {`{"version":"5 6"}`, record},
		{`{"cell":{"exitCode":"1 2"}}`, response},
	} {
		if err := protojson.Unmarshal([]byte(c.json), c.into()); err != nil {
			t.Fatalf("%s: protojson refuses it (%v), so this test no longer shows the loose read", c.json, err)
		}
		if err := UnmarshalJSON([]byte(c.json), c.into()); err == nil {
			t.Errorf("%s: read", c.json)
		}
	}
	for _, whole := range []string{
		`{"sequence":"5"}`, `{"sequence":5}`, `{"startedUnixMs":"-1"}`, `{"sequence":"0"}`,
		`{"isolationQualification":"5 6"}`, `{"provider":"5,"}`,
	} {
		if err := UnmarshalJSON([]byte(whole), &plimsollv1.RunRecord{}); err != nil {
			t.Errorf("%s: %v", whole, err)
		}
	}
}
