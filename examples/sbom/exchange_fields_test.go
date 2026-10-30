package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// exchangeFields is every field an exchange can hold, by its place in the exchange
// ("request.project.files.path"), as protojson names it.
func exchangeFields() []string {
	var out []string
	var walk func(prefix string, md protoreflect.MessageDescriptor, seen []protoreflect.FullName)
	walk = func(prefix string, md protoreflect.MessageDescriptor, seen []protoreflect.FullName) {
		if slices.Contains(seen, md.FullName()) {
			return
		}
		seen = append(seen, md.FullName())
		for i := 0; i < md.Fields().Len(); i++ {
			f := md.Fields().Get(i)
			p := prefix + "." + string(f.Name())
			out = append(out, p)
			if f.Message() != nil {
				walk(p, f.Message(), seen)
			}
		}
	}
	walk("request", (&plimsollv1.RunRequest{}).ProtoReflect().Descriptor(), nil)
	walk("response", (&plimsollv1.RunResponse{}).ProtoReflect().Descriptor(), nil)
	slices.Sort(out)
	return out
}

// Every field an exchange can hold is either one of the exchange format the published
// bills were written in (testdata/exchange-format-fields.txt) or one laterFields names,
// so a field the protocol gains cannot change a published bill unnoticed: a new field
// fails here until it is added to laterFields (written only when set) or every published
// bill is made again and the format file with it.
func TestExchangeFieldsAreTheFormatsOrLater(t *testing.T) {
	raw, err := os.ReadFile("testdata/exchange-format-fields.txt")
	if err != nil {
		t.Fatal(err)
	}
	format := strings.Fields(string(raw))
	later := make([]string, len(laterFields))
	for i, p := range laterFields {
		later[i] = strings.Join(p, ".")
	}
	have := exchangeFields()
	for _, f := range have {
		if !slices.Contains(format, f) && !slices.Contains(later, f) {
			t.Errorf("%s is in neither the published exchange format nor laterFields: add it to laterFields, or make every published bill again", f)
		}
	}
	for _, f := range append(format, later...) {
		if !slices.Contains(have, f) {
			t.Errorf("%s is listed but no exchange can hold it: delete it", f)
		}
	}
	for _, f := range later {
		if slices.Contains(format, f) {
			t.Errorf("%s is both in the format and a later field", f)
		}
	}
}

// A later field is written when it carries a value and left out when it does not, and a
// field of the format is written either way.
func TestLaterFieldsAreWrittenOnlyWhenSet(t *testing.T) {
	cell := &plimsollv1.RunRequest{Protocol: 5, Payload: &plimsollv1.RunRequest_Cell{Cell: &plimsollv1.CellRun{Language: "python", Code: "1"}}}
	for _, tc := range []struct {
		warm bool
		want bool
	}{{false, false}, {true, true}} {
		cell.PreferWarm = tc.warm
		x, err := exchangeBytes(source{Request: cell, Response: &plimsollv1.RunResponse{Warm: tc.warm}})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(x), `"prefer_warm"`); got != tc.want {
			t.Errorf("prefer_warm %v: written %v; want %v", tc.warm, got, tc.want)
		}
		if got := strings.Contains(string(x), `"warm"`); got != tc.want {
			t.Errorf("warm %v: written %v; want %v", tc.warm, got, tc.want)
		}
		if !strings.Contains(string(x), `"trace_id":""`) {
			t.Error("a format field holding its zero value was left out")
		}
	}
}
