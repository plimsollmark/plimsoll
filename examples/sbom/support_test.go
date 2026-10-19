package main

import (
	"testing"

	"github.com/plimsollmark/plimsoll/examples/sbom/cdxutil"
)

func TestVendoredSchema(t *testing.T) {
	if err := cdxutil.ValidateSchema([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := cdxutil.ValidateSchema([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"unexpected":true}`)); err == nil {
		t.Fatal("accepted unknown top-level field")
	}
}
