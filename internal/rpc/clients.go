package rpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// FileVerifier authenticates many callers from a JSON client list, so each caller
// (e.g. each MCP client) gets its OWN Principal — distinct UserID + scopes. That
// UserID flows downstream as the per-session token's `sub`, so per-client minting is
// actually per client (vs. one shared identity). Tokens are stored as SHA-256 hex
// (token_sha256), so the config file holds no live secrets.
//
// Compute a client's token_sha256 from its bearer token with:
//
//	printf %s "<token>" | sha256sum
type FileVerifier struct {
	clients map[string]Principal // key: lowercase hex SHA-256 of the bearer token
}

type clientConfig struct {
	ID          string   `json:"id"`           // stable principal id (becomes Principal.UserID / token sub)
	TokenSHA256 string   `json:"token_sha256"` // hex SHA-256 of the client's bearer token
	Scopes      []string `json:"scopes"`       // granted scopes, e.g. ["code:run"]
}

type clientsFile struct {
	Clients []clientConfig `json:"clients"`
}

// LoadClientsFromEnv builds a FileVerifier from PLIMSOLL_CLIENTS_FILE, or returns
// nil if that var is unset (the caller then falls back to the single static token or
// open dev mode).
func LoadClientsFromEnv() (*FileVerifier, error) {
	path := strings.TrimSpace(os.Getenv("PLIMSOLL_CLIENTS_FILE"))
	if path == "" {
		return nil, nil
	}
	return LoadClients(path)
}

// LoadClients reads and validates a clients file at path.
func LoadClients(path string) (*FileVerifier, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clients: read %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cf clientsFile
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("clients: parse %s: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("clients: parse %s: unexpected trailing JSON value", path)
		}
		return nil, fmt.Errorf("clients: parse %s: trailing data: %w", path, err)
	}

	v := &FileVerifier{clients: make(map[string]Principal, len(cf.Clients))}
	ids := make(map[string]struct{}, len(cf.Clients))
	for i, c := range cf.Clients {
		id := strings.TrimSpace(c.ID)
		if id == "" {
			return nil, fmt.Errorf("clients: entry %d: id is required", i)
		}
		if id == "*" {
			return nil, fmt.Errorf("clients: entry %d: id %q is reserved", i, id)
		}
		if _, duplicate := ids[id]; duplicate {
			return nil, fmt.Errorf("clients: duplicate id %q", id)
		}
		ids[id] = struct{}{}
		h := strings.ToLower(strings.TrimSpace(c.TokenSHA256))
		if len(h) != 64 {
			return nil, fmt.Errorf("clients: %q: token_sha256 must be a 64-char hex SHA-256", id)
		}
		if _, err := hex.DecodeString(h); err != nil {
			return nil, fmt.Errorf("clients: %q: token_sha256 is not valid hex: %w", id, err)
		}
		if _, dup := v.clients[h]; dup {
			return nil, fmt.Errorf("clients: %q: duplicate token_sha256", id)
		}
		v.clients[h] = Principal{UserID: id, Scopes: c.Scopes}
	}
	if len(v.clients) == 0 {
		return nil, fmt.Errorf("clients: %s defines no clients", path)
	}
	return v, nil
}

// Len reports how many clients are configured.
func (v *FileVerifier) Len() int {
	if v == nil {
		return 0
	}
	return len(v.clients)
}

// VerifyToken matches a presented bearer token (by its SHA-256) to a client. The
// hash key means a wrong token leaks nothing and forging one needs a preimage.
func (v *FileVerifier) VerifyToken(_ context.Context, token string) (Principal, bool, error) {
	if v == nil || token == "" {
		return Principal{}, false, nil
	}
	sum := sha256.Sum256([]byte(token))
	p, ok := v.clients[hex.EncodeToString(sum[:])]
	if !ok {
		return Principal{}, false, nil
	}
	return p, true, nil
}
