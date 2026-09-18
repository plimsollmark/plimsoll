package rpc

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/clientconfig"
)

// FileVerifier authenticates many callers from a JSON client list, so each caller
// (e.g. each MCP client) gets its OWN Principal — distinct UserID + scopes. That
// UserID flows downstream as the per-session token's `sub`, so per-client minting is
// actually per client (vs. one shared identity). Tokens are stored as SHA-256 hex
// (token_sha256), so the config file holds no live secrets.
//
// The plimsoll-clients command manages this file using the same validator.
type FileVerifier struct {
	clients map[string]Principal // key: lowercase hex SHA-256 of the bearer token
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
	cf, err := clientconfig.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("clients: parse %s: %w", path, err)
	}
	v := &FileVerifier{clients: make(map[string]Principal, len(cf.Clients))}
	for _, c := range cf.Clients {
		v.clients[c.TokenSHA256] = Principal{UserID: c.ID, Scopes: c.Scopes}
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
	p, ok := v.clients[clientconfig.Fingerprint(token)]
	if !ok {
		return Principal{}, false, nil
	}
	return p, true, nil
}
