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
var wslcImagePattern = regexp.MustCompile(`^wslc-image:sha256:[a-f0-9]{64}$`)

// WSLCImageClaim is how a bill of materials names a WSL containers run's image: by its
// image ID, which is what the record's environment holds, never as a registry pin. The
// image ID is the SHA-256 of the image's configuration; measured on wslc 3.0.5.0
// (2026-11-17), it equals the configuration digest the registry's manifest names. The
// provider checks a configured pin only by finding it among the repository digests wslc
// lists at startup, and the tar the per-run mode loads into each run's VM holds no
// manifest whose digest is the pin, so nothing the provider holds checks a pin from bytes
// and none is stated. A pin could be checked through the registry, by fetching the pinned
// manifest by its digest and following it to the configuration digest; the provider does
// not do that.
const WSLCImageClaim = "a WSL containers run started by the image whose image ID is sha256:%s (environment %s): the SHA-256 of the image's configuration, which the provider read with wslc image inspect at startup and starts every run by. It is not a registry manifest digest, and no registry pin is stated"

// qualifiedProviders are the providers whose tier always comes with a sentence its vendor
// or design requires (sandbox.Qualifier): a record of one that states none (any record
// before version 5, or a daemon that dropped it) is refused, so a bill of materials never
// restates the tier without the sentence.
var qualifiedProviders = map[string]bool{"wslc": true}

// CheckQualification refuses a record whose provider states a sentence beside its tier
// when the record carries none.
func CheckQualification(r sandbox.RunRecord) error {
	if qualifiedProviders[r.Provider] && r.IsolationQualification == "" {
		return fmt.Errorf("run %s is a %s run whose record states no isolation qualification (a record before version 5, or a daemon that dropped it): its tier would reach the bill of materials without the sentence its provider requires, such as Microsoft's statement that WSL is not a security sandbox", r.SHA256, r.Provider)
	}
	return nil
}

// ImageTitle is the requirement the image claim answers: the image's manifest digest,
// except for a WSL run, whose image is named by its image ID.
func ImageTitle(r sandbox.RunRecord) string {
	if r.SoftwareIdentity == "" && wslcImagePattern.MatchString(r.Environment) {
		return "the image is identified by its image ID"
	}
	return "the image is identified by its manifest digest"
}

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
	case r.SoftwareIdentity == "" && wslcImagePattern.MatchString(r.Environment):
		return strings.TrimPrefix(r.Environment, "wslc-image:sha256:"), WSLCImageClaim, true
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
