package main

import (
	"testing"
)

func TestVendoredSchema(t *testing.T) {
	if err := validateSchema([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := validateSchema([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"unexpected":true}`)); err == nil {
		t.Fatal("accepted unknown top-level field")
	}
}
