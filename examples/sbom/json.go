package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Reject ambiguous JSON before a schema or typed decoder can discard duplicate
// keys. A different viewer must never select a different value from the checker.
func uniqueJSON(b []byte) error {
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
