// Package clientconfig defines the caller registry shared by the daemon and the
// offline operator CLI. It contains fingerprints and permissions, never tokens.
package clientconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Caller struct {
	ID          string   `json:"id"`
	TokenSHA256 string   `json:"token_sha256"`
	Scopes      []string `json:"scopes"`
}

type File struct {
	Clients []Caller `json:"clients"`
}

// Fingerprint hashes the exact token text sent in the Authorization header.
func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Parse accepts an empty registry so the CLI can revoke the last caller. The
// daemon separately refuses to start without at least one configured caller.
func Parse(raw []byte) (File, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("clients: invalid JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return f, errors.New("clients: unexpected trailing data")
	}
	if f.Clients == nil {
		return f, errors.New("clients: clients must be an array")
	}
	return f, f.Validate()
}

// Validate canonicalizes IDs and hashes while checking the same identity
// constraints used by RPC authentication. Scope names are individual tokens.
func (f *File) Validate() error {
	ids, hashes := map[string]bool{}, map[string]bool{}
	for i := range f.Clients {
		c := &f.Clients[i]
		c.ID = strings.TrimSpace(c.ID)
		if c.ID == "" || c.ID == "*" || !utf8.ValidString(c.ID) || strings.ContainsFunc(c.ID, unicode.IsControl) {
			return fmt.Errorf("clients: entry %d requires a nonempty, non-reserved ID without control characters", i)
		}
		if ids[c.ID] {
			return fmt.Errorf("clients: duplicate id %q", c.ID)
		}
		ids[c.ID] = true
		c.TokenSHA256 = strings.ToLower(strings.TrimSpace(c.TokenSHA256))
		if len(c.TokenSHA256) != 64 {
			return fmt.Errorf("clients: %q: token_sha256 must be a 64-char hex SHA-256", c.ID)
		}
		if _, err := hex.DecodeString(c.TokenSHA256); err != nil {
			return fmt.Errorf("clients: %q: token_sha256 must be hexadecimal", c.ID)
		}
		if hashes[c.TokenSHA256] {
			return fmt.Errorf("clients: %q: duplicate token_sha256", c.ID)
		}
		hashes[c.TokenSHA256] = true
		seen := map[string]bool{}
		for _, scope := range c.Scopes {
			if scope == "" || !utf8.ValidString(scope) || strings.ContainsFunc(scope, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) || seen[scope] {
				return fmt.Errorf("clients: %q: scopes must be unique, nonempty names without whitespace or control characters", c.ID)
			}
			seen[scope] = true
		}
	}
	return nil
}
