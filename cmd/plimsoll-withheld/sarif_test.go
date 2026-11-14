package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/withheld"
)

// The SARIF 2.1.0 schema as OASIS publishes it (testdata/sarif-schema-2.1.0.NOTICE). The
// validator below reads the JSON Schema keywords that schema uses ($ref, type, enum,
// properties, required, additionalProperties, items, minItems, uniqueItems, minimum,
// maximum, pattern, format, anyOf, oneOf), so a report that passes it is valid SARIF, with
// no JSON Schema module added to a scanner that takes no dependency it can avoid.
const sarifSchemaFile = "testdata/sarif-schema-2.1.0.json"

type schemaValidator struct {
	defs map[string]any
}

func loadSARIFSchema(t *testing.T) *schemaValidator {
	t.Helper()
	raw, err := os.ReadFile(sarifSchemaFile)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	defs, _ := root["definitions"].(map[string]any)
	defs["#"] = root
	return &schemaValidator{defs: defs}
}

// check validates a SARIF document; every problem, or none.
func (v *schemaValidator) check(raw []byte) []string {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{err.Error()}
	}
	return v.validate("$", v.defs["#"].(map[string]any), doc)
}

func jsonType(x any) []string {
	switch x := x.(type) {
	case nil:
		return []string{"null"}
	case bool:
		return []string{"boolean"}
	case string:
		return []string{"string"}
	case float64:
		if x == math.Trunc(x) {
			return []string{"number", "integer"}
		}
		return []string{"number"}
	case []any:
		return []string{"array"}
	case map[string]any:
		return []string{"object"}
	}
	return nil
}

func (v *schemaValidator) validate(at string, s map[string]any, x any) []string {
	if ref, ok := s["$ref"].(string); ok { // draft-04: a $ref replaces its siblings
		def, ok := v.defs[strings.TrimPrefix(ref, "#/definitions/")].(map[string]any)
		if !ok {
			return []string{at + ": unknown $ref " + ref}
		}
		return v.validate(at, def, x)
	}
	var errs []string
	if t, ok := s["type"]; ok {
		want := []any{t}
		if list, ok := t.([]any); ok {
			want = list
		}
		match := false
		for _, w := range want {
			for _, got := range jsonType(x) {
				match = match || w == got
			}
		}
		if !match {
			return []string{fmt.Sprintf("%s: %v is not of type %v", at, x, t)}
		}
	}
	if enum, ok := s["enum"].([]any); ok {
		in := false
		for _, e := range enum {
			in = in || reflect.DeepEqual(e, x)
		}
		if !in {
			errs = append(errs, fmt.Sprintf("%s: %v is not one of %v", at, x, enum))
		}
	}
	switch x := x.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if _, ok := x[r.(string)]; !ok {
					errs = append(errs, at+": required property "+r.(string)+" is missing")
				}
			}
		}
		for k, val := range x {
			if ps, ok := props[k].(map[string]any); ok {
				errs = append(errs, v.validate(at+"."+k, ps, val)...)
				continue
			}
			switch ap := s["additionalProperties"].(type) {
			case bool:
				if !ap {
					errs = append(errs, at+": property "+k+" is not allowed")
				}
			case map[string]any:
				errs = append(errs, v.validate(at+"."+k, ap, val)...)
			}
		}
	case []any:
		if n, ok := s["minItems"].(float64); ok && float64(len(x)) < n {
			errs = append(errs, fmt.Sprintf("%s: %d items, fewer than %v", at, len(x), n))
		}
		if u, ok := s["uniqueItems"].(bool); ok && u {
			for i := range x {
				for j := i + 1; j < len(x); j++ {
					if reflect.DeepEqual(x[i], x[j]) {
						errs = append(errs, fmt.Sprintf("%s: items %d and %d are equal", at, i, j))
					}
				}
			}
		}
		if items, ok := s["items"].(map[string]any); ok {
			for i, it := range x {
				errs = append(errs, v.validate(fmt.Sprintf("%s[%d]", at, i), items, it)...)
			}
		}
	case string:
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(x) {
			errs = append(errs, fmt.Sprintf("%s: %q does not match %s", at, x, p))
		}
		switch s["format"] {
		case "uri":
			if u, err := url.Parse(x); err != nil || !u.IsAbs() {
				errs = append(errs, fmt.Sprintf("%s: %q is not an absolute URI", at, x))
			}
		case "uri-reference":
			if _, err := url.Parse(x); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %q is not a URI reference: %v", at, x, err))
			}
		case "date-time":
			if _, err := time.Parse(time.RFC3339, x); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %q is not a date-time", at, x))
			}
		}
	case float64:
		if m, ok := s["minimum"].(float64); ok && x < m {
			errs = append(errs, fmt.Sprintf("%s: %v is below %v", at, x, m))
		}
		if m, ok := s["maximum"].(float64); ok && x > m {
			errs = append(errs, fmt.Sprintf("%s: %v is above %v", at, x, m))
		}
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		alts, ok := s[key].([]any)
		if !ok {
			continue
		}
		passed := 0
		for _, alt := range alts {
			if len(v.validate(at, alt.(map[string]any), x)) == 0 {
				passed++
			}
		}
		if passed == 0 || (key == "oneOf" && passed > 1) {
			errs = append(errs, fmt.Sprintf("%s: %d of the %s alternatives hold", at, passed, key))
		}
	}
	return errs
}

func mustValidSARIF(t *testing.T, v *schemaValidator, raw []byte) map[string]any {
	t.Helper()
	if errs := v.check(raw); len(errs) > 0 {
		t.Fatalf("not valid SARIF 2.1.0:\n%s\n%s", strings.Join(errs, "\n"), raw)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// sarifResults is each result as "ruleId level uri[:line] | message".
func sarifResults(doc map[string]any) []string {
	var out []string
	run := doc["runs"].([]any)[0].(map[string]any)
	for _, r := range run["results"].([]any) {
		r := r.(map[string]any)
		pl := r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
		where := pl["artifactLocation"].(map[string]any)["uri"].(string)
		if reg, ok := pl["region"].(map[string]any); ok {
			where += fmt.Sprintf(":%v", reg["startLine"])
		}
		out = append(out, fmt.Sprintf("%s %s %s | %s", r["ruleId"], r["level"], where, r["message"].(map[string]any)["text"]))
	}
	return out
}

// The validator is not vacuous: a report missing what the schema requires, or holding
// what it forbids, fails it.
func TestSARIFValidatorRefusesInvalidReports(t *testing.T) {
	v := loadSARIFSchema(t)
	good := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"message":{"text":"m"},"level":"error"}]}]}`
	if errs := v.check([]byte(good)); len(errs) > 0 {
		t.Fatalf("a minimal valid report: %v", errs)
	}
	for _, bad := range []string{
		`{"runs":[]}`, // no version
		`{"version":"2.0.0","runs":[]}`,
		`{"version":"2.1.0","runs":[{"tool":{"driver":{}}}]}`, // a driver with no name
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"message":{"text":"m"},"level":"fatal"}]}]}`,
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"message":{"text":"m"},"locations":[{"physicalLocation":{"region":{"startLine":0}}}]}]}]}`,
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"surprise":1}]}`,
	} {
		if errs := v.check([]byte(bad)); len(errs) == 0 {
			t.Errorf("an invalid report passed: %s", bad)
		}
	}
}

// scan -format sarif: valid SARIF, one result per find and per file not read whole, the
// label and the path in each, the line of a value found in a line, the text output's exit
// status; and a path holding a value is not named.
func TestScanWritesSARIF(t *testing.T) {
	v := loadSARIFSchema(t)
	dir := t.TempDir()
	sim := "import numpy as np\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"
	write(t, filepath.Join(dir, "harness", "sim.py"), sim)
	write(t, filepath.Join(dir, "seeds.txt"), "731904\n")
	var set bytes.Buffer
	if code, err := run([]string{"build", "-mode", "refuse", "-values-mode", "audit", "-file", filepath.Join(dir, "harness"),
		"-values", filepath.Join(dir, "seeds.txt")}, &set, io.Discard); err != nil || code != 0 {
		t.Fatalf("build: %d, %v", code, err)
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())

	task := filepath.Join(dir, "task")
	write(t, filepath.Join(task, "helpers", "model.py"), sim)
	write(t, filepath.Join(task, "viewer.html"), "<p>a viewer</p>\n<a href=\"viewer.html?seed=731904&case=2\">example</a>\n")
	// Base64 wrapped at 76 columns: each line holds whole groups of 4, so it decodes on its
	// own, and the seed's bytes (101 to 106) sit in line 2's (57 to 113). In straddle.txt
	// they run across the line break (54 to 59), so only the whole file holds them.
	write(t, filepath.Join(task, "wrapped.txt"), wrapAt(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("padding ", 12)+"seed 731904 "+strings.Repeat("more ", 12))), 76)+"\n")
	write(t, filepath.Join(task, "straddle.txt"), wrapAt(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("padding ", 6)+"abcde 731904 "+strings.Repeat("more ", 12))), 76)+"\n")
	write(t, filepath.Join(task, "run_731904", "notes.txt"), "nothing here\n")
	flags := []byte{0x00, 0x04}
	xz := append([]byte("\xfd7zXZ\x00"), flags...)
	xz = binary.LittleEndian.AppendUint32(xz, crc32.ChecksumIEEE(flags))
	write(t, filepath.Join(task, "data.xz"), string(xz)+"the rest")

	var out bytes.Buffer
	code, err := run([]string{"scan", "-set", setPath, "-format", "sarif", task}, &out, io.Discard)
	if err != nil || code != 1 {
		t.Fatalf("scan: %d, %v\n%s", code, err, out.String())
	}
	if strings.Contains(out.String(), "731904") {
		t.Fatalf("the SARIF report holds the seed:\n%s", out.String())
	}
	doc := mustValidSARIF(t, v, out.Bytes())
	rel := filepath.ToSlash(task)
	got := sarifResults(doc)
	for _, want := range []string{
		"find error " + sarifURI(rel+"/helpers/model.py") + " | Withheld entry harness/sim.py (refuse mode) was found in this file.",
		"find error " + sarifURI(rel+"/viewer.html") + ":2 | Withheld entry seeds.txt:1 (audit mode) was found in this file.",
		"find error " + sarifURI(rel+"/wrapped.txt") + ":2 | Withheld entry seeds.txt:1 (audit mode) was found in this file.",
		"find error " + sarifURI(rel+"/straddle.txt") + " | Withheld entry seeds.txt:1 (audit mode) was found in this file.",
		"find error " + sarifURI(rel) + " | Withheld entry seeds.txt:1 (audit mode) is in the path of a file under this directory; that path is not named here, since it holds the entry.",
		"unreadable warning " + sarifURI(rel+"/data.xz") + " | This file was not read whole: an xz stream, a format the scan does not read.",
	} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("no result %q in:\n%s", want, strings.Join(got, "\n"))
		}
	}
	if len(got) != 6 {
		t.Errorf("%d results, want 6:\n%s", len(got), strings.Join(got, "\n"))
	}

	clean := filepath.Join(dir, "clean")
	write(t, filepath.Join(clean, "agent.py"), "print('hello')\n")
	out.Reset()
	if code, err := run([]string{"scan", "-set", setPath, "-format", "sarif", clean}, &out, io.Discard); err != nil || code != 0 {
		t.Fatalf("clean scan: %d, %v", code, err)
	}
	if got := sarifResults(mustValidSARIF(t, v, out.Bytes())); len(got) != 0 {
		t.Errorf("a clean scan's results: %v", got)
	}
	if code, err := run([]string{"scan", "-set", setPath, "-format", "html", clean}, io.Discard, io.Discard); code != 2 || err == nil {
		t.Errorf("-format html: %d, %v; want a usage error", code, err)
	}
}

// scan-image -format sarif: each file nested in its layer, nested in the image; the
// configuration a member of the archive; a layer file not read whole exits 3.
func TestScanImageWritesSARIF(t *testing.T) {
	v := loadSARIFSchema(t)
	dir := t.TempDir()
	sim := "import numpy as np\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"
	write(t, filepath.Join(dir, "harness", "sim.py"), sim)
	write(t, filepath.Join(dir, "seeds.txt"), "731904\n")
	var set bytes.Buffer
	if code, err := run([]string{"build", "-mode", "refuse", "-file", filepath.Join(dir, "harness"), "-values", filepath.Join(dir, "seeds.txt")}, &set, io.Discard); err != nil || code != 0 {
		t.Fatalf("build: %d, %v", code, err)
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())

	img := filepath.Join(dir, "image.tar")
	imageArchive(t, img, map[string]string{"app/main.py": "print(1)\n", "usr/src/harness/sim.py": sim}, `{"config":{"Env":["SEED=731904"]}}`)
	var out bytes.Buffer
	code, err := run([]string{"scan-image", "-set", setPath, "-format", "sarif", "-archive", img}, &out, io.Discard)
	if err != nil || code != 1 {
		t.Fatalf("scan-image: %d, %v\n%s", code, err, out.String())
	}
	doc := mustValidSARIF(t, v, out.Bytes())
	got := sarifResults(doc)
	want := []string{
		"find error usr/src/harness/sim.py | Withheld entry harness/sim.py (refuse mode) was found in this file of layer blobs/sha256/layer.",
		"find error blobs/sha256/config | Withheld entry seeds.txt:1 (refuse mode) was found in this file.",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("results:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	run0 := doc["runs"].([]any)[0].(map[string]any)
	arts := run0["artifacts"].([]any)
	var chain []string
	idx := run0["results"].([]any)[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["index"]
	for i, ok := idx.(float64); ok; i, ok = arts[int(i)].(map[string]any)["parentIndex"].(float64) {
		a := arts[int(i)].(map[string]any)
		if loc, ok := a["location"].(map[string]any); ok {
			chain = append(chain, loc["uri"].(string))
		} else {
			chain = append(chain, a["description"].(map[string]any)["text"].(string))
		}
	}
	if len(chain) != 3 || chain[0] != "usr/src/harness/sim.py" || chain[1] != "blobs/sha256/layer" || !strings.HasPrefix(chain[2], "archive ") {
		t.Errorf("the find's artifact chain: %q", chain)
	}

	flags := []byte{0x00, 0x04}
	xz := append([]byte("\xfd7zXZ\x00"), flags...)
	xz = binary.LittleEndian.AppendUint32(xz, crc32.ChecksumIEEE(flags))
	imageArchive(t, img, map[string]string{"opt/data.xz": string(xz) + "the rest"}, `{}`)
	out.Reset()
	if code, err = run([]string{"scan-image", "-set", setPath, "-format", "sarif", "-archive", img}, &out, io.Discard); err != nil || code != 3 {
		t.Fatalf("scan-image of an unreadable file: %d, %v", code, err)
	}
	got = sarifResults(mustValidSARIF(t, v, out.Bytes()))
	if len(got) != 1 || got[0] != "unreadable warning opt/data.xz | This file of layer blobs/sha256/layer was not read whole: an xz stream, a format the scan does not read." {
		t.Errorf("results: %q", got)
	}
}

func TestSARIFURI(t *testing.T) {
	for p, want := range map[string]string{
		"task/viewer.html":    "task/viewer.html",
		"a:b/c d.txt":         "a%3Ab/c%20d.txt",
		"/srv/task/x.py":      "file:///srv/task/x.py",
		"":                    ".",
		"caf\xc3\xa9/\n?#.md": "caf%C3%A9/%0A%3F%23.md",
	} {
		if got := sarifURI(p); got != want {
			t.Errorf("sarifURI(%q) = %q, want %q", p, got, want)
		}
		if u, err := url.Parse(sarifURI(p)); err != nil || (u.Scheme != "" && u.Scheme != "file") {
			t.Errorf("sarifURI(%q) = %q reads as scheme %q (%v)", p, sarifURI(p), u.Scheme, err)
		}
	}
}

// marker is a fresh canary value: letters and digits, so the scan finds it as one run.
func marker(t *testing.T) string {
	t.Helper()
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "cnry" + string(b)
}

// markersIn is every marker found in raw, in any letter case: the canary's check.
func markersIn(raw []byte, markers []string) []string {
	var out []string
	low := bytes.ToLower(raw)
	for _, m := range markers {
		if bytes.Contains(low, []byte(strings.ToLower(m))) {
			out = append(out, m)
		}
	}
	return out
}

func tarGz(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The canary: fresh marker values withheld, planted in every place a scanned file can
// carry one (its text, in another letter case, escaped, in base64, inside a tar.gz, its
// name, its directory's name; in an image, a layer file's path, a symbolic link's target
// and the image's environment) and the harness file whose copy is found by its digest
// holding one too. Both commands' SARIF reports find them, and hold none of them.
func TestSARIFCanaryHoldsNoWithheldValue(t *testing.T) {
	v := loadSARIFSchema(t)
	dir := t.TempDir()
	m := []string{marker(t), marker(t), marker(t), marker(t), marker(t)}
	write(t, filepath.Join(dir, "values.txt"), strings.Join(m[:4], "\n")+"\n")
	harness := "import numpy as np\n\nKEY = '" + m[4] + "'\n\ndef step(state, u, dt):\n    return state + dt * (u - 0.3 * state)\n"
	write(t, filepath.Join(dir, "harness", "secret.py"), harness)
	var set bytes.Buffer
	if code, err := run([]string{"build", "-mode", "audit", "-file", filepath.Join(dir, "harness"), "-values", filepath.Join(dir, "values.txt")}, &set, io.Discard); err != nil || code != 0 {
		t.Fatalf("build: %d, %v", code, err)
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())

	task := filepath.Join(dir, "task")
	write(t, filepath.Join(task, "plain.txt"), "the seed is "+m[0]+"\n")
	write(t, filepath.Join(task, "upper.html"), "<a href='x?k="+strings.ToUpper(m[1])+"'>x</a>\n")
	write(t, filepath.Join(task, "b64.txt"), base64.StdEncoding.EncodeToString([]byte("prefix "+m[2]+" suffix"))+"\n")
	write(t, filepath.Join(task, "escaped.json"), `{"next": "v.html%3Fseed%3D`+m[3]+`"}`+"\n")
	write(t, filepath.Join(task, "run_"+m[0], "notes.txt"), "nothing here\n")
	write(t, filepath.Join(task, m[1]+".json"), `{"a": "`+m[2]+`"}`+"\n")
	write(t, filepath.Join(task, "helpers", "h.py"), harness)
	write(t, filepath.Join(task, "deps.tar.gz"), tarGz(t, map[string]string{m[3] + ".txt": m[0] + "\n"}))

	var out bytes.Buffer
	code, err := run([]string{"scan", "-set", setPath, "-format", "sarif", task}, &out, io.Discard)
	if err != nil || code != 1 {
		t.Fatalf("scan: %d, %v\n%s", code, err, out.String())
	}
	if leaked := markersIn(out.Bytes(), m); len(leaked) > 0 {
		t.Fatalf("the SARIF report holds %d withheld values:\n%s", len(leaked), out.String())
	}
	labels := map[string]bool{}
	for _, r := range mustValidSARIF(t, v, out.Bytes())["runs"].([]any)[0].(map[string]any)["results"].([]any) {
		labels[r.(map[string]any)["properties"].(map[string]any)["label"].(string)] = true
	}
	for _, l := range []string{"values.txt:1", "values.txt:2", "values.txt:3", "values.txt:4", "harness/secret.py"} {
		if !labels[l] {
			t.Errorf("the report does not name %s, so the canary tested nothing for it: %v", l, labels)
		}
	}

	// The same markers in an image.
	var layer bytes.Buffer
	lw := tar.NewWriter(&layer)
	for _, f := range []struct{ name, content, link string }{
		{"app/run_" + m[0] + "/x.txt", "nothing\n", ""},
		{"usr/src/h.py", harness, ""},
		{"etc/conf", "key=" + m[1] + "\n", ""},
		{"app/link", "", "/opt/" + m[2]},
	} {
		h := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.content)), Typeflag: tar.TypeReg}
		if f.link != "" {
			h = &tar.Header{Name: f.name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: f.link}
		}
		if err := lw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := lw.Write([]byte(f.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	var arch bytes.Buffer
	aw := tar.NewWriter(&arch)
	for _, mem := range [][2]string{{"blobs/sha256/layer", layer.String()}, {"blobs/sha256/config", `{"config":{"Env":["SEED=` + m[3] + `"]}}`}} {
		if err := aw.WriteHeader(&tar.Header{Name: mem[0], Mode: 0o644, Size: int64(len(mem[1])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := aw.Write([]byte(mem[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(dir, "image.tar")
	write(t, img, arch.String())
	out.Reset()
	if code, err = run([]string{"scan-image", "-set", setPath, "-format", "sarif", "-archive", img}, &out, io.Discard); err != nil || code != 1 {
		t.Fatalf("scan-image: %d, %v\n%s", code, err, out.String())
	}
	if leaked := markersIn(out.Bytes(), m); len(leaked) > 0 {
		t.Fatalf("the image's SARIF report holds %d withheld values:\n%s", len(leaked), out.String())
	}
	got := sarifResults(mustValidSARIF(t, v, out.Bytes()))
	if len(got) != 5 {
		t.Errorf("%d results, want 5 (a path, a harness copy, a file, a link target, the environment):\n%s", len(got), strings.Join(got, "\n"))
	}
}

// The canary's check is not vacuous: with the redaction undone (a path holding a marker
// named as it is, and the scan of the report before it is written bypassed), it sees the
// marker. And that scan, left in place, refuses to write such a report.
func TestSARIFCanaryCatchesAPlantedLeak(t *testing.T) {
	dir := t.TempDir()
	m := marker(t)
	write(t, filepath.Join(dir, "values.txt"), m+"\n")
	var buf bytes.Buffer
	if code, err := run([]string{"build", "-mode", "audit", "-values", filepath.Join(dir, "values.txt")}, &buf, io.Discard); err != nil || code != 0 {
		t.Fatalf("build: %d, %v", code, err)
	}
	set, err := withheld.Parse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	w := newSARIF(set)
	// The leak: the find's path named although it holds the marker (no hide).
	w.find(withheld.Finding{Label: "values.txt:1", Mode: withheld.ModeAudit}, sarifPlace{path: "task/run_" + m + "/notes.txt", part: withheld.PartPath})
	raw, err := json.Marshal(sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{w.run}})
	if err != nil {
		t.Fatal(err)
	}
	if leaked := markersIn(raw, []string{m}); len(leaked) != 1 {
		t.Fatalf("the canary missed a planted leak:\n%s", raw)
	}
	if out, err := w.bytes(context.Background()); err == nil || !strings.Contains(err.Error(), "values.txt:1") {
		t.Fatalf("a report naming a withheld value was written (%v):\n%s", err, out)
	}
}

// A label holding a value (a values file named after one) would carry it into the report:
// nothing is written, and the error says why.
func TestSARIFRefusesALabelHoldingAValue(t *testing.T) {
	dir := t.TempDir()
	m := marker(t)
	values := filepath.Join(dir, "seeds_"+m+".txt")
	write(t, values, m+"\n")
	var set bytes.Buffer
	if code, err := run([]string{"build", "-mode", "audit", "-values", values}, &set, io.Discard); err != nil || code != 0 {
		t.Fatalf("build: %d, %v", code, err)
	}
	setPath := filepath.Join(dir, "set.json")
	write(t, setPath, set.String())
	write(t, filepath.Join(dir, "task", "a.txt"), m+"\n")
	var out bytes.Buffer
	code, err := run([]string{"scan", "-set", setPath, "-format", "sarif", filepath.Join(dir, "task")}, &out, io.Discard)
	if code != 2 || err == nil || !strings.Contains(err.Error(), "nothing written") || out.Len() != 0 {
		t.Fatalf("exit %d, %v, wrote:\n%s", code, err, out.String())
	}
}
