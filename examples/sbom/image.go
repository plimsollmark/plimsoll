package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type imageBOM struct {
	File, SHA256, Manifest, Link, Generator, GeneratorVersion, Created string
	Count                                                              int
	raw                                                                []byte
}

var imageVersionPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var imageSerialPattern = regexp.MustCompile(`^urn:uuid:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func parseImageBOM(raw []byte, file, manifest string) (*imageBOM, error) {
	if err := uniqueJSON(raw); err != nil {
		return nil, err
	}
	var b struct {
		Format   string `json:"bomFormat"`
		Spec     string `json:"specVersion"`
		Serial   string `json:"serialNumber"`
		Version  int    `json:"version"`
		Metadata struct {
			Timestamp string
			Component struct {
				Type, Version string
				Ref           string `json:"bom-ref"`
			}
			Tools struct {
				Components []struct{ Name, Version string }
			}
		}
		Components []json.RawMessage
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	root := b.Metadata.Component
	if b.Format != "CycloneDX" || (b.Spec != "1.6" && b.Spec != "1.7") || b.Version < 1 || !imageSerialPattern.MatchString(b.Serial) || root.Type != "container" || root.Ref == "" {
		return nil, fmt.Errorf("image SBOM needs a CycloneDX serial, version and container root")
	}
	if !imageVersionPattern.MatchString(manifest) || root.Version != manifest {
		return nil, fmt.Errorf("image SBOM root version %q differs from the record's manifest %q", root.Version, manifest)
	}
	image := &imageBOM{File: file, SHA256: digest(raw), Manifest: manifest, Link: fmt.Sprintf("urn:cdx:%s/%d#%s", strings.TrimPrefix(b.Serial, "urn:uuid:"), b.Version, url.PathEscape(root.Ref)), Count: len(b.Components), raw: raw}
	image.Created = b.Metadata.Timestamp
	if len(b.Metadata.Tools.Components) != 0 {
		image.Generator, image.GeneratorVersion = b.Metadata.Tools.Components[0].Name, b.Metadata.Tools.Components[0].Version
	}
	return image, nil
}

// References are never fetched. Resolve only the digest-derived sibling name,
// or an explicit local file supplied by the caller.
func readImageBOM(explicit, dir, manifest string) (*imageBOM, error) {
	if !imageVersionPattern.MatchString(manifest) {
		return nil, fmt.Errorf("invalid image manifest digest")
	}
	path := explicit
	name := "image-" + strings.TrimPrefix(manifest, "sha256:")[:12] + ".cdx.json"
	if path == "" {
		path = filepath.Join(dir, name)
	}
	raw, err := readInput(path)
	if explicit == "" && os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseImageBOM(raw, name, manifest)
}
