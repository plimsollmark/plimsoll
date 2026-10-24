// Package cdxutil supplies offline CycloneDX formatting and validation shared by emitters.
package cdxutil

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const Repository = "https://github.com/plimsollmark/plimsoll"

type Object = map[string]any

// InputLimit covers the RPC request/result budgets and base64 expansion.
const InputLimit = 32 << 20

//go:embed schema/*.json
var schemas embed.FS
var selectedImagePattern = regexp.MustCompile(`^oci-manifest:[a-z0-9._/-]+@sha256:[a-f0-9]{64}$`)
var dockerCloudImagePattern = regexp.MustCompile(`^dockercloud-image:sha256:[a-f0-9]{64}$`)
var agentSandboxImagePattern = regexp.MustCompile(`^agentsandbox-image:sha256:[a-f0-9]{64}$`)

// ValidatePages refuses a base URL that is not absolute HTTP(S) and ending in /, or that
// carries credentials, a query or a fragment; flag names the option in the message.
func ValidatePages(flag, pages string) error {
	u, err := url.Parse(pages)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(pages, "/") {
		return fmt.Errorf("%s must be an absolute HTTP(S) URL ending in /, without credentials, query or fragment", flag)
	}
	return nil
}

func ValidateOptions(name, imageName, operator, pages string) error {
	if err := ValidatePages("-pages", pages); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(operator) == "" || !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`).MatchString(imageName) {
		return fmt.Errorf("name and operator must be nonempty; image-name must be a lowercase OCI package name without a path")
	}
	return nil
}
func Digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func Timestamp(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z") }

func Serial(record string) string {
	s := sha256.Sum256([]byte("plimsoll-sbom-serial\n" + record))
	s[6] = (s[6] & 15) | 64
	s[8] = (s[8] & 63) | 128
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", s[:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

// ValidateSchema uses only the embedded schemas and refuses remote loading.
func ValidateSchema(b []byte) error {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft7)
	c.AssertFormat()
	c.UseLoader(offlineLoader{})
	for _, name := range []string{"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"} {
		data, err := schemas.ReadFile("schema/" + name)
		if err != nil {
			return err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			return err
		}
		for _, scheme := range []string{"http", "https"} {
			if err := c.AddResource(scheme+"://cyclonedx.org/schema/"+name, doc); err != nil {
				return err
			}
		}
	}
	s, err := c.Compile("http://cyclonedx.org/schema/bom-1.6.schema.json")
	if err != nil {
		return err
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return err
	}
	return s.Validate(v)
}

// UniqueJSON rejects duplicate keys and excessive nesting before typed decoding.
func UniqueJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 128 {
			return fmt.Errorf("JSON nesting exceeds 128 levels")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		if delim != '{' && delim != '[' {
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return fmt.Errorf("duplicate or invalid JSON key %q", key)
				}
				seen[name] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON value")
	}
	return nil
}

// ImageDigest is the digest of the image the daemon states the run executed in, with the
// words for how the daemon knows it: docker's selected OCI manifest, verified before
// launch; the linux/amd64 manifest Docker Cloud reported it booted, checked against the
// provider's pin; or the digest a Kubernetes agent-sandbox template pins its image by,
// checked against the image ID the kubelet reports for the run's own pod. A run whose
// record states none of them cannot be mapped.
func ImageDigest(r sandbox.RunRecord) (digest, how string, ok bool) {
	switch {
	case selectedImagePattern.MatchString(r.SoftwareIdentity):
		return strings.Split(r.SoftwareIdentity, "@sha256:")[1], "the image whose OCI manifest digest is sha256:%s (environment %s), verified before launch", true
	case r.SoftwareIdentity == "" && dockerCloudImagePattern.MatchString(r.Environment):
		return strings.TrimPrefix(r.Environment, "dockercloud-image:sha256:"), "a Docker Cloud microVM booted from the image whose linux/amd64 manifest digest is sha256:%s (environment %s), the provider's pin, which it compares with the digest the cloud reports each sandbox booted and refuses to run on a difference", true
	case r.SoftwareIdentity == "" && agentSandboxImagePattern.MatchString(r.Environment):
		return strings.TrimPrefix(r.Environment, "agentsandbox-image:sha256:"), "a Kubernetes agent-sandbox pod running the image pinned by sha256:%s (environment %s), the digest the pod's template names, which the provider compares with the image ID the kubelet reports for the run's own pod and refuses to run on a difference", true
	}
	return "", "", false
}

func Props(pairs ...string) []Object {
	p := make([]Object, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		p = append(p, Object{"name": "plimsoll:" + pairs[i], "value": pairs[i+1]})
	}
	return p
}

func Hashes(value string) []Object { return []Object{{"alg": "SHA-256", "content": value}} }

func Attachment(name, kind string, content []byte) Object {
	return Object{"name": name, "contents": Object{"attachment": Object{
		"contentType": kind, "encoding": "base64", "content": base64.StdEncoding.EncodeToString(content),
	}}}
}

// EncodeBOM uses the CycloneDX encoder and preserves explicit self-assessor fields.
func EncodeBOM(doc Object) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := cdx.NewBOMEncoder(&b, cdx.BOMFileFormatJSON).SetPretty(true).Encode(&bom); err != nil {
		return nil, err
	}
	var encoded Object
	if err := json.Unmarshal(b.Bytes(), &encoded); err != nil {
		return nil, err
	}
	for _, a := range encoded["declarations"].(map[string]any)["assessors"].([]any) {
		a.(map[string]any)["thirdParty"] = false
	}
	b.Reset()
	encoder := json.NewEncoder(&b)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(encoded); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ReadInput bounds input before materializing its nested attachments.
func ReadInput(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, InputLimit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > InputLimit {
		return nil, fmt.Errorf("%s exceeds the 32 MiB input budget", path)
	}
	return b, nil
}

type offlineLoader struct{}

func (offlineLoader) Load(u string) (any, error) {
	return nil, fmt.Errorf("schema not vendored: %s", u)
}
