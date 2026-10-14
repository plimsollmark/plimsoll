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
	"github.com/plimsollmark/plimsoll/examples/adapter/qualify"
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
	s, err := sources(b, p, defaults().Pages)
	if err != nil {
		t.Fatal(err)
	}
	// Two gVisor runs, then the same two requests sent to Docker Cloud (tier vm): the
	// request digests pair up, since the bytes are the same.
	if len(s) != 4 || s[0].Record.Isolation != "kernel" || s[2].Record.Isolation != "vm" || s[3].Record.Isolation != "vm" ||
		s[2].Record.RequestSHA256 != s[0].Record.RequestSHA256 || s[3].Record.RequestSHA256 != s[1].Record.RequestSHA256 {
		t.Fatalf("want two kernel runs and their two vm repeats, got %d runs", len(s))
	}
	return s, b, p
}

// verdictFixtures are the two adapter runs the published page carries a verdict for:
// line 8 (adapter-v2, nominal, pass) and line 4 (adapter-v1, lost_ack, fail).
func verdictFixtures(t *testing.T) []source {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("../../docs/examples/adapter/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	s, err := qualified(read("bundle.jsonl"), read("harness.pub"), read("qualification.jsonl"), "https://plimsollmark.github.io/plimsoll/examples/adapter/", []int{8, 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 || s[0].Verdict.Verdict != "pass" || s[1].Verdict.Verdict != "fail" || s[1].Verdict.Evidence.Scenario.Name != "lost_ack" {
		t.Fatalf("want a pass and the lost_ack fail, got %d runs", len(s))
	}
	return s
}

// have is what the emitter holds of a run's shared files: everything.
func have(s source) sharedFiles { return sharedFiles{Bundle: s.Shared.bundle, Qualification: s.Shared.qualification} }

// imageFor is the example's one image label when run executed in that image, else nil:
// the Docker Cloud runs booted a public node image that has no label here.
func imageFor(t *testing.T, run source) *imageBOM {
	t.Helper()
	if d, _, _ := imageDigest(run.Record); d == "1c6cbab4a47d34da471ab4ab970709cbba18e2a3445fde884b5d90ec2c4c5b25" {
		return fixtureImage(t)
	}
	return nil
}

func emitted(t *testing.T, s source) []byte {
	t.Helper()
	o := defaults()
	o.Name = s.displayName(o.Name)
	o.ImageBOM = imageFor(t, s)
	raw, err := buildBOM(s, o)
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
	s, _, _ := fixtures(t)
	for _, run := range append(s, verdictFixtures(t)...) {
		t.Run(run.Record.SHA256[:12], func(t *testing.T) {
			raw := emitted(t, run)
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
			checks, err := checkBOM(raw, run.PEM, imageFor(t, run), have(run))
			if err != nil {
				t.Fatal(err)
			}
			want := 9
			if imageFor(t, run) != nil {
				want++
			}
			if run.Verdict != nil {
				want += 2
			}
			if len(checks) != want || strings.Contains(strings.Join(checks, "\n"), "LIMIT: the referenced") {
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
	s, _, _ := fixtures(t)
	for _, run := range append(s, verdictFixtures(t)...) {
		lines, err := tamperChecks(emitted(t, run), run.PEM, imageFor(t, run), have(run))
		if err != nil {
			t.Fatal(err)
		}
		want := 3
		if run.Verdict != nil {
			want = 4
		}
		if len(lines) != want {
			t.Fatalf("missing a required negative check: %v", lines)
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
	s, _, p := fixtures(t)
	raw := emitted(t, s[0])
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
	if _, err := checkBOM(changed, p, fixtureImage(t), have(s[0])); err == nil {
		t.Fatal("accepted an internally consistent substituted file list")
	}
}

func TestEveryMappedFieldIsBound(t *testing.T) {
	s, _, p := fixtures(t)
	raw := emitted(t, s[1])
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
			if _, err := checkBOM(changed, p, fixtureImage(t), have(s[1])); err == nil {
				t.Fatal("accepted changed mapped field")
			}
		})
	}
}

func TestTrustBoundaryIsExplicit(t *testing.T) {
	s, _, p := fixtures(t)
	raw := emitted(t, s[0])
	checks, err := checkBOM(raw, nil, fixtureImage(t), have(s[0]))
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
	if _, err := checkBOM(raw, other, fixtureImage(t), have(s[0])); err == nil {
		t.Fatal("accepted different trusted key")
	}
	changed := mutate(t, raw, func(d object) { component(d)["name"] = "new display name" })
	if _, err := checkBOM(changed, p, fixtureImage(t), have(s[0])); err != nil {
		t.Fatal("unsigned presentation should be changeable:", err)
	}
	// Without the shared files the line still proves itself, and the checker says what
	// it did not see.
	alone, err := checkBOM(raw, p, fixtureImage(t), sharedFiles{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(alone, "\n"), "LIMIT: the referenced bundle was not supplied") {
		t.Fatalf("the missing bundle was not stated: %v", alone)
	}
	if _, err := checkBOM(raw, p, fixtureImage(t), sharedFiles{Bundle: []byte("not the bundle\n")}); err == nil {
		t.Fatal("accepted a bundle that is not the referenced one")
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
	if _, err := sources(b, p, defaults().Pages); err == nil || !strings.Contains(err.Error(), "a session is many runs of one sandbox") {
		t.Fatalf("want stated session refusal, got %v", err)
	}
}

func TestMalformedBOMsAndEvidenceFailWithoutPanic(t *testing.T) {
	s, b, p := fixtures(t)
	raw := emitted(t, s[0])
	for _, bad := range [][]byte{[]byte(`{}`), []byte(`null`), []byte(`{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}`), append(bytes.Clone(raw), []byte(`{}`)...)} {
		if _, err := checkBOM(bad, p, fixtureImage(t), have(s[0])); err == nil {
			t.Fatal("accepted malformed or ambiguous BOM")
		}
	}
	changed := mutate(t, raw, func(d object) {
		d["declarations"].(map[string]any)["evidence"].([]any)[0].(map[string]any)["data"].([]any)[2].(map[string]any)["contents"].(map[string]any)["attachment"].(map[string]any)["content"] = base64.StdEncoding.EncodeToString(b[:len(b)/2])
	})
	if _, err := checkBOM(changed, p, fixtureImage(t), have(s[0])); err == nil {
		t.Fatal("accepted a cut line")
	}
	if _, err := sources(bytes.Replace(b, []byte("request"), []byte("changed"), 1), p, defaults().Pages); err == nil {
		t.Fatal("accepted changed source bundle")
	}
}

func TestCLIReproducesOutputsAndReportsChecks(t *testing.T) {
	dir := scratch(t)
	var out bytes.Buffer
	if err := execute([]string{"-out", dir}, &out); err != nil {
		t.Fatal(err)
	}
	names := []string{"index.html"}
	plain, _, _ := fixtures(t)
	verdicts := verdictFixtures(t)
	for _, v := range append(plain, verdicts...) {
		names = append(names, "run-"+v.Record.SHA256[:12]+".cdx.json")
	}
	for _, name := range names {
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
	if !strings.Contains(out.String(), "every mapped field") || !strings.Contains(out.String(), "LIMIT: the referenced bundle was not supplied") {
		t.Fatalf("missing CLI receipts: %s", out.String())
	}
	out.Reset()
	verdict := filepath.Join(dir, "run-"+verdicts[0].Record.SHA256[:12]+".cdx.json")
	if err := execute([]string{"-check", verdict, "-check-bundle", "../../docs/examples/adapter/bundle.jsonl", "-check-qualification", "../../docs/examples/adapter/qualification.jsonl", "-trusted-pub", "../../docs/examples/adapter/harness.pub"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PASS: the attached line is line 8 of the referenced bundle", "PASS: the attached statement is one of the referenced qualification file's 38", "verdict re-evaluated"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in: %s", want, out.String())
		}
	}
	if err := execute([]string{"-check", verdict, "-check-qualification", "../../docs/examples/adapter/qualification.jsonl"}, &out); err == nil {
		t.Fatal("the qualification file was checked without its bundle")
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

// The verdict claim is bound to the signed statement, and the statement to the run.
func TestVerdictClaimIsBoundToTheStatement(t *testing.T) {
	v := verdictFixtures(t)
	pass, fail := v[0], v[1]
	raw := emitted(t, pass)
	if _, err := checkBOM(raw, pass.PEM, fixtureImage(t), have(pass)); err != nil {
		t.Fatal(err)
	}
	statement := func(d object) object {
		return d["declarations"].(object)["evidence"].([]any)[1].(object)["data"].([]any)[0].(object)["contents"].(object)["attachment"].(object)
	}
	edited, err := qualify.Rewrite(*pass.Statement, func(p *qualify.Predicate) { p.Rules[3].Held = false })
	if err != nil {
		t.Fatal(err)
	}
	editedJSON, _ := json.Marshal(edited)
	otherJSON, _ := json.Marshal(*fail.Statement)
	for name, edit := range map[string]func(object){
		"conformance score": func(d object) {
			d["declarations"].(object)["attestations"].([]any)[0].(object)["map"].([]any)[3].(object)["conformance"].(object)["score"] = 0
		},
		"verdict word": func(d object) {
			c := d["declarations"].(object)["claims"].([]any)[3].(object)
			c["predicate"] = strings.Replace(c["predicate"].(string), "Verdict: pass.", "Verdict: fail.", 1)
		},
		"a rule's outcome in the claim": func(d object) {
			c := d["declarations"].(object)["claims"].([]any)[3].(object)
			c["predicate"] = strings.Replace(c["predicate"].(string), "one order per command: held", "one order per command: broken", 1)
		},
		"statement edited, signature kept": func(d object) {
			statement(d)["content"] = base64.StdEncoding.EncodeToString(editedJSON)
		},
		"the other run's statement": func(d object) {
			statement(d)["content"] = base64.StdEncoding.EncodeToString(otherJSON)
		},
		"qualification reference": func(d object) {
			for _, ref := range component(d)["externalReferences"].([]any) {
				if strings.HasSuffix(ref.(object)["url"].(string), "qualification.jsonl") {
					ref.(object)["hashes"].([]any)[0].(object)["content"] = strings.Repeat("0", 64)
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := mutate(t, raw, edit)
			if err := validateSchema(changed); err != nil {
				t.Fatal(err)
			}
			if _, err := checkBOM(changed, pass.PEM, fixtureImage(t), have(pass)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// The failing run's BOM says so in every place a reader looks.
	failRaw := string(emitted(t, fail))
	for _, want := range []string{`"score": 0`, "Verdict: fail.", "one order per command: broken (run04-c2 became 2 orders (m2, m3))", "1 of 8 rules did not hold"} {
		if !strings.Contains(failRaw, want) {
			t.Fatalf("the failing verdict's BOM lacks %q", want)
		}
	}
	// A line with no statement, and a line that is not a run, are refused.
	read := func(name string) []byte {
		b, err := os.ReadFile("../../docs/examples/adapter/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, line := range []int{39, 40} {
		if _, err := qualified(read("bundle.jsonl"), read("harness.pub"), read("qualification.jsonl"), defaults().Pages, []int{line}); err == nil {
			t.Fatalf("line %d accepted", line)
		}
	}
}
