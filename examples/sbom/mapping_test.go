package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/plimsollmark/plimsoll/attest"
)

func fixtures(t *testing.T) ([]source, []byte, []byte) {
	t.Helper()
	b, err := os.ReadFile("../../docs/examples/sbom/bundle.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.ReadFile("../../docs/examples/sbom/harness.pub")
	if err != nil {
		t.Fatal(err)
	}
	s, err := sources(b, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 {
		t.Fatalf("want two signed runs, got %d", len(s))
	}
	return s, b, p
}

func emitted(t *testing.T, s source, b, p []byte) []byte {
	t.Helper()
	o := defaults()
	o.ImageBOM = fixtureImage(t)
	raw, err := buildBOM(s, b, p, o)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func scratch(t *testing.T) string {
	t.Helper()
	if err := os.MkdirAll("../../tmp", 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("../../tmp", "sbom-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func TestPublishedBOMsReproduceAndVerify(t *testing.T) {
	s, b, p := fixtures(t)
	for _, run := range s {
		t.Run(run.Record.SHA256[:12], func(t *testing.T) {
			raw := emitted(t, run, b, p)
			published, err := os.ReadFile("../../docs/examples/sbom/run-" + run.Record.SHA256[:12] + ".cdx.json")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, published) {
				t.Fatal("published BOM is not the deterministic output")
			}
			if err := validateSchema(raw); err != nil {
				t.Fatal(err)
			}
			checks, err := checkBOM(raw, p, fixtureImage(t))
			if err != nil {
				t.Fatal(err)
			}
			if len(checks) != 9 {
				t.Fatalf("missing verification receipts: %v", checks)
			}
			var bom cdx.BOM
			if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
				t.Fatal(err)
			}
			d, err := fileSetDigest(*bom.Metadata.Component.Components)
			if err != nil {
				t.Fatal(err)
			}
			if (*bom.Metadata.Component.Hashes)[0].Value != d {
				t.Fatal("SDK-decoded file digest differs")
			}
			// An independent construction, using the actual stored file contents.
			var concatenated []byte
			for _, file := range *bom.Metadata.Component.Components {
				var content string
				found := false
				for _, f := range run.Request.GetProject().GetFiles() {
					if f.GetPath() == file.Name {
						content = f.GetContent()
						found = true
						break
					}
				}
				if !found {
					t.Fatal("BOM file absent from signed request")
				}
				path, _ := hex.DecodeString(digest([]byte(file.Name)))
				data, _ := hex.DecodeString(digest([]byte(content)))
				concatenated = append(concatenated, path...)
				concatenated = append(concatenated, data...)
			}
			if digest(concatenated) != d {
				t.Fatal("file-set algorithm differs from independent construction")
			}
			// Verify the envelope using precisely the key attached to this BOM.
			a := *(*bom.Declarations.Evidence)[0].Data
			envBytes, err := base64.StdEncoding.DecodeString(a[0].Contents.Attachment.Content)
			if err != nil {
				t.Fatal(err)
			}
			keyBytes, err := base64.StdEncoding.DecodeString(a[1].Contents.Attachment.Content)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := attest.ParsePublicKey(keyBytes)
			if err != nil {
				t.Fatal(err)
			}
			var env attest.Envelope
			if err := json.Unmarshal(envBytes, &env); err != nil {
				t.Fatal(err)
			}
			r, err := attest.NewVerifier(pub).Verify(env)
			if err != nil || r.SHA256 != run.Record.SHA256 {
				t.Fatalf("attached envelope: %v", err)
			}
		})
	}
}

func TestThreeOneByteTamperCases(t *testing.T) {
	s, b, p := fixtures(t)
	for _, run := range s {
		lines, err := tamperChecks(emitted(t, run, b, p), p, fixtureImage(t))
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) != 3 {
			t.Fatal("missing a required negative check")
		}
	}
}

func mutate(t *testing.T, raw []byte, edit func(object)) []byte {
	t.Helper()
	var d object
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	edit(d)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func component(d object) object { return d["metadata"].(map[string]any)["component"].(map[string]any) }
func workflow(d object) object {
	return d["formulation"].([]any)[0].(map[string]any)["workflows"].([]any)[0].(map[string]any)
}

func TestCoordinatedFileSubstitutionIsRejected(t *testing.T) {
	s, b, p := fixtures(t)
	raw := emitted(t, s[0], b, p)
	changed := mutate(t, raw, func(d object) {
		program := component(d)
		files := program["components"].([]any)
		first := files[0].(map[string]any)
		first["hashes"].([]any)[0].(map[string]any)["content"] = digest([]byte("substituted code"))
		var typed []cdx.Component
		fileJSON, _ := json.Marshal(files)
		if err := json.Unmarshal(fileJSON, &typed); err != nil {
			t.Fatal(err)
		}
		fd, err := fileSetDigest(typed)
		if err != nil {
			t.Fatal(err)
		}
		program["hashes"].([]any)[0].(map[string]any)["content"] = fd
		program["version"] = fd[:12]
		// Even if the attacker rewrites the unsigned code claim to agree with its
		// substituted list, the verified request binds the original files.
		claims := d["declarations"].(map[string]any)["claims"].([]any)
		old := claims[0].(map[string]any)["predicate"].(string)
		_, original, err := programFiles(s[0])
		if err != nil {
			t.Fatal(err)
		}
		claims[0].(map[string]any)["predicate"] = strings.ReplaceAll(old, original, fd)
	})
	if err := validateSchema(changed); err != nil {
		t.Fatal("mutation should remain schema-valid:", err)
	}
	if _, err := checkBOM(changed, p, fixtureImage(t)); err == nil {
		t.Fatal("accepted an internally consistent substituted file list")
	}
}

func TestEveryMappedFieldIsBound(t *testing.T) {
	s, b, p := fixtures(t)
	raw := emitted(t, s[1], b, p)
	edits := map[string]func(object){
		"command": func(d object) {
			workflow(d)["tasks"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)["commands"].([]any)[0].(map[string]any)["executed"] = "node different.js"
		},
		"exit code": func(d object) {
			workflow(d)["tasks"].([]any)[2].(map[string]any)["steps"].([]any)[0].(map[string]any)["commands"].([]any)[0].(map[string]any)["properties"].([]any)[0].(map[string]any)["value"] = "0"
		},
		"image": func(d object) {
			d["components"].([]any)[0].(map[string]any)["version"] = "sha256:" + strings.Repeat("0", 64)
		},
		"timestamp": func(d object) { d["metadata"].(map[string]any)["timestamp"] = "2000-01-01T00:00:00.000Z" },
		"timeout": func(d object) {
			for _, v := range workflow(d)["properties"].([]any) {
				x := v.(map[string]any)
				if x["name"] == "plimsoll:timeout_ms" {
					x["value"] = "99999"
				}
			}
		},
		"claim reasoning": func(d object) {
			d["declarations"].(map[string]any)["claims"].([]any)[0].(map[string]any)["reasoning"] = "independently verified hardware attestation"
		},
		"bundle digest": func(d object) { d["properties"].([]any)[0].(map[string]any)["value"] = strings.Repeat("0", 64) },
		"additional component": func(d object) {
			d["components"] = append(d["components"].([]any), object{"type": "application", "name": "extra"})
		},
		"evidence media type": func(d object) {
			d["declarations"].(map[string]any)["evidence"].([]any)[0].(map[string]any)["data"].([]any)[0].(map[string]any)["contents"].(map[string]any)["attachment"].(map[string]any)["contentType"] = "text/plain"
		},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			changed := mutate(t, raw, edit)
			if err := validateSchema(changed); err != nil {
				t.Fatal(err)
			}
			if _, err := checkBOM(changed, p, fixtureImage(t)); err == nil {
				t.Fatal("accepted changed mapped field")
			}
		})
	}
}

func TestTrustBoundaryIsExplicit(t *testing.T) {
	s, b, p := fixtures(t)
	raw := emitted(t, s[0], b, p)
	checks, err := checkBOM(raw, nil, fixtureImage(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(checks, "\n"), "signer identity is not established") {
		t.Fatal("embedded key was treated as trusted identity")
	}
	other, err := os.ReadFile("../../docs/examples/sessions/harness.pub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkBOM(raw, other, fixtureImage(t)); err == nil {
		t.Fatal("accepted different trusted key")
	}
	changed := mutate(t, raw, func(d object) { component(d)["name"] = "new display name" })
	if _, err := checkBOM(changed, p, fixtureImage(t)); err != nil {
		t.Fatal("unsigned presentation should be changeable:", err)
	}
}

func TestSessionsAreRefused(t *testing.T) {
	b, err := os.ReadFile("../../docs/examples/sessions/bundle.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.ReadFile("../../docs/examples/sessions/harness.pub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sources(b, p); err == nil || !strings.Contains(err.Error(), "a session is many runs of one sandbox") {
		t.Fatalf("want stated session refusal, got %v", err)
	}
}

func TestMalformedBOMsAndEvidenceFailWithoutPanic(t *testing.T) {
	s, b, p := fixtures(t)
	raw := emitted(t, s[0], b, p)
	for _, bad := range [][]byte{[]byte(`{}`), []byte(`null`), []byte(`{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}`), append(bytes.Clone(raw), []byte(`{}`)...)} {
		if _, err := checkBOM(bad, p, fixtureImage(t)); err == nil {
			t.Fatal("accepted malformed or ambiguous BOM")
		}
	}
	changed := mutate(t, raw, func(d object) {
		d["declarations"].(map[string]any)["evidence"].([]any)[0].(map[string]any)["data"].([]any)[2].(map[string]any)["contents"].(map[string]any)["attachment"].(map[string]any)["content"] = base64.StdEncoding.EncodeToString(b[:len(b)/2])
	})
	if _, err := checkBOM(changed, p, fixtureImage(t)); err == nil {
		t.Fatal("accepted cut bundle")
	}
	if _, err := sources(bytes.Replace(b, []byte("request"), []byte("changed"), 1), p); err == nil {
		t.Fatal("accepted changed source bundle")
	}
}

func TestCLIReproducesOutputsAndReportsChecks(t *testing.T) {
	dir := scratch(t)
	var out bytes.Buffer
	if err := execute([]string{"-out", dir}, &out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"run-c7e245a369dd.cdx.json", "run-af0fa2597b81.cdx.json", "index.html"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join("../../docs/examples/sbom", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("generation did not reproduce %s", name)
		}
	}
	out.Reset()
	if err := execute([]string{"-check", filepath.Join(dir, "run-c7e245a369dd.cdx.json"), "-trusted-pub", "../../docs/examples/sbom/harness.pub"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "every mapped field") {
		t.Fatal("missing CLI receipts")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := execute([]string{"-check", bad}, &out); err == nil {
		t.Fatal("invalid -check did not fail")
	}
	missingOutput := filepath.Join(dir, "refused-output")
	if err := execute([]string{"-bundle", bad, "-out", missingOutput}, &out); err == nil {
		t.Fatal("invalid bundle accepted")
	}
	if _, err := os.Stat(missingOutput); !os.IsNotExist(err) {
		t.Fatal("created output before verifying the bundle")
	}
}
