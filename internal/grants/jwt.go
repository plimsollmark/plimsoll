package grants

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// jwtMinter issues a fresh short-lived HS256 JWT per run, with the calling principal
// as `sub` and the grant's scopes as a space-joined `scope` claim — so each MCP
// client/session gets its own scoped, expiring credential instead of one shared
// static token. No third-party deps: an HS256 JWT is
// base64url(header).base64url(claims).base64url(HMAC-SHA256(secret, header.claims)).
// The target API must verify this JWT against the shared secret, reject tokens whose
// `aud` is not its own identity, and derive identity/tenant from `sub`.
//
// The token is bound to an audience (mandatory) so it cannot be replayed against a
// different service that happens to share the secret, and it carries `jti`/`nbf` so
// a verifier can do replay detection and reject not-yet-valid tokens. A `kid` header
// (when configured) lets verifiers hold current+previous keys and roll the secret
// without a flag-day.
type jwtMinter struct {
	secret   []byte
	ttl      time.Duration
	issuer   string
	audience string
	keyID    string
}

func newJWTMinter(secret []byte, ttl time.Duration, issuer, audience, keyID string) *jwtMinter {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &jwtMinter{secret: secret, ttl: ttl, issuer: issuer, audience: audience, keyID: keyID}
}

// RequiresSubject marks this minter as subject-bound: its token embeds the caller
// identity, so the RPC layer must refuse to run it without an authenticated
// principal rather than collapse every caller into one shared `sub`.
func (m *jwtMinter) RequiresSubject() bool { return true }

func (m *jwtMinter) Mint(_ context.Context, scope sandbox.MintScope) (sandbox.MintedToken, error) {
	// Refuse to mint a per-session token with no authenticated subject: a shared
	// `sub` would collapse every unauthenticated caller into one identity against
	// the host API, defeating per-caller rate limiting, tenancy, and audit. The RPC
	// layer already refuses this earlier (grant.RequiresSubject); this is defense in
	// depth so the minter can never silently issue a shared-identity credential.
	sub := strings.TrimSpace(scope.Subject)
	if sub == "" {
		return sandbox.MintedToken{}, errors.New("jwt minter: refusing to mint a per-session token without an authenticated subject")
	}

	now := time.Now()
	// Bound the token's life to the run budget (plus a small grace) but never longer
	// than the configured ttl, so an exfiltrated token dies with the run.
	life := m.ttl
	if scope.TTL > 0 && scope.TTL+5*time.Second < life {
		life = scope.TTL + 5*time.Second
	}
	exp := now.Add(life)

	jti, err := newJTI()
	if err != nil {
		return sandbox.MintedToken{}, err
	}
	claims := map[string]any{
		"sub": sub,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
		"jti": jti,
	}
	if m.issuer != "" {
		claims["iss"] = m.issuer
	}
	if m.audience != "" {
		claims["aud"] = m.audience
	}
	if len(scope.Scopes) > 0 {
		claims["scope"] = strings.Join(scope.Scopes, " ")
	}

	tok, err := signHS256(m.secret, m.keyID, claims)
	if err != nil {
		return sandbox.MintedToken{}, err
	}
	return sandbox.MintedToken{Value: tok, ExpiresAt: exp}, nil
}

// newJTI returns a random 128-bit token id (hex) so verifiers can detect replay.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// signHS256 signs claims with an HS256 JWT. keyID, when non-empty, is emitted as the
// header `kid` so a verifier holding more than one key can select the right one
// during a rotation window.
func signHS256(secret []byte, keyID string, claims map[string]any) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	if keyID != "" {
		header["kid"] = keyID
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signing))
	return signing + "." + enc.EncodeToString(mac.Sum(nil)), nil
}
