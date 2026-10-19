package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/plimsollmark/plimsoll/examples/sbom/cdxutil"
)

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

type options struct {
	Name, ImageName, Operator, Pages string
	ImageBOM                         *imageBOM
}

func defaults() options {
	return options{Name: "reconcile", ImageName: "sandbox", Operator: "plimsoll examples (self-assessed)", Pages: "https://plimsollmark.github.io/plimsoll/examples/sbom/"}
}

func (o options) validate() error {
	return cdxutil.ValidateOptions(o.Name, o.ImageName, o.Operator, o.Pages)
}
