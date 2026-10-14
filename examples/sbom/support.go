package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema/*.json
var schemas embed.FS

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func fileSetDigest(files []cdx.Component) (string, error) {
	files = slices.Clone(files)
	slices.SortFunc(files, func(a, b cdx.Component) int { return strings.Compare(a.Name, b.Name) })
	h := sha256.New()
	last := ""
	for _, f := range files {
		if f.Type != cdx.ComponentTypeFile || f.Name == "" || f.Name == last || f.Hashes == nil || len(*f.Hashes) != 1 || (*f.Hashes)[0].Algorithm != cdx.HashAlgoSHA256 {
			return "", fmt.Errorf("invalid or duplicate file component %q", f.Name)
		}
		content, err := hex.DecodeString((*f.Hashes)[0].Value)
		if err != nil || len(content) != sha256.Size || hex.EncodeToString(content) != (*f.Hashes)[0].Value {
			return "", fmt.Errorf("file %q: expected a lowercase SHA-256 hash", f.Name)
		}
		path := sha256.Sum256([]byte(f.Name))
		h.Write(path[:])
		h.Write(content)
		last = f.Name
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func timestamp(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z") }

func serial(record string) string {
	s := sha256.Sum256([]byte("plimsoll-sbom-serial\n" + record))
	s[6] = (s[6] & 15) | 64
	s[8] = (s[8] & 63) | 128
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", s[:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

type options struct {
	Name, ImageName, Operator, Pages string
	ImageBOM                         *imageBOM
}

func defaults() options {
	return options{Name: "reconcile", ImageName: "sandbox", Operator: "plimsoll examples (self-assessed)", Pages: "https://plimsollmark.github.io/plimsoll/examples/sbom/"}
}

func (o options) validate() error {
	u, err := url.Parse(o.Pages)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(o.Pages, "/") {
		return fmt.Errorf("-pages must be an absolute HTTP(S) URL ending in /, without credentials, query or fragment")
	}
	if strings.TrimSpace(o.Name) == "" || strings.TrimSpace(o.Operator) == "" || !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`).MatchString(o.ImageName) {
		return fmt.Errorf("name and operator must be nonempty; image-name must be a lowercase OCI package name without a path")
	}
	return nil
}

// Validate with only the pinned embedded schemas. No schema reference can fetch
// a remote document, even if the input supplies a different $schema URL.
func validateSchema(b []byte) error {
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

type offlineLoader struct{}

func (offlineLoader) Load(u string) (any, error) {
	return nil, fmt.Errorf("schema not vendored: %s", u)
}
