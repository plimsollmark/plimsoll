package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// publish writes evidence.json and the page it renders.
func publish(dir string, ev *evidence, repo string) error {
	raw, err := marshalEvidence(ev)
	if err != nil {
		return err
	}
	if err := noLocalPaths(raw, repo); err != nil {
		return err
	}
	page, err := render(ev)
	if err != nil {
		return err
	}
	if err := noLocalPaths(page, repo); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, fileEvidence), raw, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, filePage), page, 0o644)
}

func marshalEvidence(ev *evidence) ([]byte, error) {
	raw, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func loadEvidence(dir string) (*evidence, error) {
	raw, err := os.ReadFile(filepath.Join(dir, fileEvidence))
	if err != nil {
		return nil, err
	}
	var ev evidence
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return nil, fmt.Errorf("%s: %w", fileEvidence, err)
	}
	return &ev, nil
}

// verifyPublished checks the published directory offline: derive succeeds (the bundle
// and the statement verify, every file is the one the statement names), what it derives
// is evidence.json exactly, every check the page states passes, and index.html is what
// evidence.json renders.
func verifyPublished(dir string) error {
	got, err := derive(dir)
	if err != nil {
		return err
	}
	derived, err := marshalEvidence(got)
	if err != nil {
		return err
	}
	stated, err := os.ReadFile(filepath.Join(dir, fileEvidence))
	if err != nil {
		return err
	}
	if !bytes.Equal(derived, stated) {
		return fmt.Errorf("%s is not what the published files give (%d bytes derived, %d stated): rerun go run ./examples/sdk-grants", fileEvidence, len(derived), len(stated))
	}
	for _, c := range got.Checks {
		if !c.Pass {
			return fmt.Errorf("the check %q does not hold: %s", c.ID, c.Detail)
		}
	}
	page, err := render(got)
	if err != nil {
		return err
	}
	published, err := os.ReadFile(filepath.Join(dir, filePage))
	if err != nil {
		return err
	}
	if !bytes.Equal(page, published) {
		return errors.New("index.html is not what evidence.json renders: run go run ./examples/sdk-grants -render")
	}
	return nil
}

// renderPublished rewrites index.html from the published evidence.json.
func renderPublished(dir string) error {
	ev, err := loadEvidence(dir)
	if err != nil {
		return err
	}
	page, err := render(ev)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, filePage), page, 0o644)
}
