package specgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnlyNarrowsEveryArtifact: an operator who trims allow passes the trimmed list as
// Only, and the preamble, the description and Allow then name its routes alone, so a
// model is never described a route the broker refuses. A route the document has no
// generated operation for fails.
func TestOnlyNarrowsEveryArtifact(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("testdata", "smart-home.openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	keep, err := ParseOnly([]byte(`["GET /lights", "PATCH /lights/*"]`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Generate(spec, Options{Global: "home", Only: keep})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(res.AllowStrings(), ","); got != "GET /lights,PATCH /lights/*" {
		t.Errorf("allow = %s", got)
	}
	for _, name := range []string{"listLights", "updateLight"} {
		if !strings.Contains(res.Description, "home."+name+"(") || !strings.Contains(res.Preamble, `"`+name+`"`) {
			t.Errorf("%s is not in the description or the preamble", name)
		}
	}
	for _, gone := range []string{"createLight", "deleteLight", "setLight", "getLight", "listScenes", "getStatus", "listRoomLights"} {
		if strings.Contains(res.Description, gone) || strings.Contains(res.Preamble, gone) {
			t.Errorf("%s, outside the list, is still in the description or the preamble", gone)
		}
	}
	for _, bad := range []string{`["GET /doors"]`, `["GET /lights", "DELETE /scenes"]`, `[]`} {
		keep, err := ParseOnly([]byte(bad))
		if err == nil {
			_, err = Generate(spec, Options{Global: "home", Only: keep})
		}
		if err == nil {
			t.Errorf("Only %s was accepted", bad)
		}
	}
	for _, bad := range []string{`"GET /lights"`, `["get /lights"]`, `["GET"]`, `["GET lights"]`} {
		if _, err := ParseOnly([]byte(bad)); err == nil {
			t.Errorf("ParseOnly(%s) was accepted", bad)
		}
	}
	// Without Only, every operation stays: the golden test's surface is unchanged.
	all, err := Generate(spec, Options{Global: "home"})
	if err != nil || len(all.Operations) <= len(res.Operations) {
		t.Fatalf("without Only: %d operations, err %v", len(all.Operations), err)
	}
}
