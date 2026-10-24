package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func decodeAttachmentObject(t *testing.T, a object) object {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(a["content"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var x object
	if err := json.Unmarshal(raw, &x); err != nil {
		t.Fatal(err)
	}
	return x
}
func encodeAttachmentObject(t *testing.T, a, x object) {
	t.Helper()
	raw, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	a["content"] = base64.StdEncoding.EncodeToString(raw)
}

func fixtureImage(t *testing.T) *imageBOM {
	t.Helper()
	image, err := readImageBOM("", "../../docs/examples/sbom", "sha256:a6ef2ea1c8f1de5c885e1a18ba7ee4d962e3a859877f6f46c2fb7ebac1f6cc5c")
	if err != nil || image == nil {
		t.Fatalf("image evidence: %v", err)
	}
	return image
}

func TestImageEvidenceIdentityAndReferences(t *testing.T) {
	image := fixtureImage(t)
	if image.SHA256 != "7e0b9a40e742f401e3a006a7362ebba1c5f3ac832107858dcf104d8f2b6de603" || image.Count != 694 || image.Generator != "syft" || image.GeneratorVersion != "1.54.1" {
		t.Fatalf("pinned image evidence changed: %+v", image)
	}
	s, _, p := fixtures(t)
	raw := emitted(t, s[0])
	if _, err := checkBOM(raw, p, nil, have(s[0])); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing image accepted: %v", err)
	}
	for _, field := range []string{"url", "hash", "link"} {
		changed := mutate(t, raw, func(d object) {
			refs := d["components"].([]any)[0].(object)["externalReferences"].([]any)
			switch field {
			case "url":
				refs[0].(object)["url"] = "https://example.com/changed.cdx.json"
			case "hash":
				refs[0].(object)["hashes"].([]any)[0].(object)["content"] = strings.Repeat("0", 64)
			case "link":
				refs[1].(object)["url"] = "urn:cdx:39c24821-518f-475e-b688-3e366a2310be/2#wrong"
			}
		})
		if _, err := checkBOM(changed, p, image, have(s[0])); err == nil {
			t.Fatalf("changed image %s accepted", field)
		}
	}
	data, err := os.ReadFile("../../docs/examples/sbom/" + image.File)
	if err != nil {
		t.Fatal(err)
	}
	var d object
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	// A legacy-daemon scan names a different manifest despite shared image config.
	d["metadata"].(object)["component"].(object)["version"] = "sha256:" + strings.Repeat("c", 64)
	changed, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseImageBOM(changed, image.File, image.Manifest); err == nil {
		t.Fatal("daemon-sourced manifest accepted")
	}
}

func TestExchangeJSONMustEqualSignedProtobuf(t *testing.T) {
	s, _, p := fixtures(t)
	for _, field := range []string{"content", "duration_ms", "trace_id"} {
		changed := mutate(t, emitted(t, s[0]), func(d object) {
			data := d["declarations"].(object)["evidence"].([]any)[0].(object)["data"].([]any)
			for _, item := range data {
				if item.(object)["name"] != "exchange.json" {
					continue
				}
				a := item.(object)["contents"].(object)["attachment"].(object)
				x := decodeAttachmentObject(t, a)
				switch field {
				case "content":
					x["request"].(object)["project"].(object)["files"].([]any)[0].(object)["content"] = "changed"
				case "duration_ms":
					x["response"].(object)["project"].(object)["steps"].([]any)[0].(object)["duration_ms"] = "1234"
				case "trace_id":
					x["request"].(object)["trace_id"] = "changed"
				}
				encodeAttachmentObject(t, a, x)
			}
		})
		if _, err := checkBOM(changed, p, fixtureImage(t), have(s[0])); err == nil {
			t.Fatalf("changed exchange %s accepted", field)
		}
	}
}
