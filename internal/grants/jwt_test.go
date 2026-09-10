package grants

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// decodeJWT verifies the HS256 signature with secret and returns the claims.
func decodeJWT(t *testing.T, tok, secret string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)); parts[2] != want {
		t.Fatal("HS256 signature does not verify")
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func TestJWTMinterClaims(t *testing.T) {
	m := newJWTMinter([]byte("s3cr3t"), 60*time.Second, "plimsoll", "inventory-api", "")
	tok, err := m.Mint(context.Background(), sandbox.MintScope{
		Subject: "user:alice", Scopes: []string{"inventory:read"}, TTL: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	c := decodeJWT(t, tok.Value, "s3cr3t")
	if c["sub"] != "user:alice" {
		t.Errorf("sub = %v, want user:alice", c["sub"])
	}
	if c["scope"] != "inventory:read" {
		t.Errorf("scope = %v, want inventory:read", c["scope"])
	}
	if c["iss"] != "plimsoll" || c["aud"] != "inventory-api" {
		t.Errorf("iss/aud = %v / %v", c["iss"], c["aud"])
	}
	// jti (replay id) and nbf (not-before) must be present so verifiers can detect
	// replay and reject not-yet-valid tokens.
	if _, ok := c["jti"].(string); !ok || c["jti"] == "" {
		t.Errorf("jti missing or empty: %v", c["jti"])
	}
	if _, ok := c["nbf"].(float64); !ok {
		t.Errorf("nbf missing: %v", c["nbf"])
	}
	exp, _ := c["exp"].(float64)
	iat, _ := c["iat"].(float64)
	// Lifetime is bounded by the run budget (30s) + 5s grace, NOT the 60s configured.
	if d := exp - iat; d < 30 || d > 40 {
		t.Errorf("lifetime = %v s, want ~35 (run budget + grace)", d)
	}
	if tok.ExpiresAt.IsZero() {
		t.Error("MintedToken.ExpiresAt not set")
	}
}

// TestJWTMinterEmitsKID verifies a configured key_id lands in the JWT header so a
// verifier can select the right key during a rotation window.
func TestJWTMinterEmitsKID(t *testing.T) {
	m := newJWTMinter([]byte("s3cr3t"), 60*time.Second, "plimsoll", "inventory-api", "key-2026-06")
	tok, err := m.Mint(context.Background(), sandbox.MintScope{Subject: "user:alice"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	hb, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok.Value, ".")[0])
	var hdr map[string]any
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if hdr["kid"] != "key-2026-06" {
		t.Errorf("kid = %v, want key-2026-06", hdr["kid"])
	}
}

func TestJWTMinterPerSubject(t *testing.T) {
	m := newJWTMinter([]byte("k"), 60*time.Second, "", "", "")
	a, _ := m.Mint(context.Background(), sandbox.MintScope{Subject: "user:a"})
	b, _ := m.Mint(context.Background(), sandbox.MintScope{Subject: "user:b"})
	ca, cb := decodeJWT(t, a.Value, "k"), decodeJWT(t, b.Value, "k")
	if ca["sub"] == cb["sub"] {
		t.Error("two different callers minted the same sub")
	}
	if ca["sub"] != "user:a" || cb["sub"] != "user:b" {
		t.Errorf("subs = %v / %v", ca["sub"], cb["sub"])
	}
}

// TestJWTMinterRefusesWithoutSubject verifies the minter refuses to issue a
// per-session token when there is no authenticated subject, rather than falling
// back to a shared identity (design-review #6).
func TestJWTMinterRefusesWithoutSubject(t *testing.T) {
	m := newJWTMinter([]byte("k"), 60*time.Second, "", "", "")
	if tok, err := m.Mint(context.Background(), sandbox.MintScope{}); err == nil {
		t.Errorf("expected an error minting without a subject, got token %q", tok.Value)
	}
	// Whitespace-only is also no subject.
	if _, err := m.Mint(context.Background(), sandbox.MintScope{Subject: "  "}); err == nil {
		t.Error("expected an error minting with a blank subject")
	}
}

// TestJWTMinterRequiresSubjectFlag verifies the minter advertises itself as
// subject-bound so the RPC layer can refuse it in open dev mode.
func TestJWTMinterRequiresSubjectFlag(t *testing.T) {
	m := newJWTMinter([]byte("k"), 60*time.Second, "", "aud", "")
	if !m.RequiresSubject() {
		t.Error("jwt minter should report RequiresSubject() == true")
	}
}

func TestLoadJWTProfileMintsPerSubject(t *testing.T) {
	t.Setenv("PL_SECRET", strings.Repeat("s", 32))
	p := writeGrants(t, `{"profiles":{"pl":{"base_url":"https://pl","allow":["GET /a"],"allowed_callers":["user:x"],"scopes":["pl:read"],"token":{"type":"jwt","secret_env":"PL_SECRET","ttl_sec":60,"issuer":"plimsoll","audience":"inventory-api"}}}}`)
	r, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	pProfile, ok := r.Get("pl")
	if !ok || pProfile.Grant().Minter == nil {
		t.Fatal("jwt profile did not load with a minter")
	}
	g := pProfile.Grant()
	tok, err := g.Minter.Mint(context.Background(), sandbox.MintScope{Subject: "user:x", Scopes: g.Scopes})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if c := decodeJWT(t, tok.Value, strings.Repeat("s", 32)); c["sub"] != "user:x" || c["scope"] != "pl:read" {
		t.Errorf("claims sub/scope = %v / %v", c["sub"], c["scope"])
	}
}

func TestLoadRejectsUnknownTokenType(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"token":{"type":"magic"}}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for an unknown token.type")
	}
}

func TestLoadRejectsJWTMissingSecret(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"token":{"type":"jwt","secret_env":"CR_UNSET_SECRET_XYZ"}}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for an unset jwt secret env")
	}
}

func TestLoadRejectsWeakJWTSecret(t *testing.T) {
	t.Setenv("PL_SECRET", "too-short")
	p := writeGrants(t, `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"token":{"type":"jwt","secret_env":"PL_SECRET","audience":"inventory-api"}}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for an HS256 secret shorter than 32 bytes")
	}
}

func TestLoadRejectsJWTMissingAudience(t *testing.T) {
	t.Setenv("PL_SECRET", strings.Repeat("s", 32))
	// A jwt profile with a secret but no audience must fail closed at load: an
	// audience-less token is replayable across any service sharing the secret.
	p := writeGrants(t, `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"token":{"type":"jwt","secret_env":"PL_SECRET"}}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for a jwt token with no audience")
	}
}
