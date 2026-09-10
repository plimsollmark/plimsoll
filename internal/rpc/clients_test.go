package rpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func writeClients(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileVerifierAuthenticatesPerClient(t *testing.T) {
	body := `{"clients":[
		{"id":"mcp-a","token_sha256":"` + sha256hex("tok-a") + `","scopes":["code:run"]},
		{"id":"mcp-b","token_sha256":"` + sha256hex("tok-b") + `","scopes":["code:run"]}
	]}`
	v, err := LoadClients(writeClients(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v.Len() != 2 {
		t.Fatalf("len = %d, want 2", v.Len())
	}

	p, ok, err := v.VerifyToken(context.Background(), "tok-a")
	if err != nil || !ok {
		t.Fatalf("verify tok-a: ok=%v err=%v", ok, err)
	}
	if p.UserID != "mcp-a" {
		t.Errorf("UserID = %q, want mcp-a", p.UserID)
	}
	if !p.HasScope("code:run") {
		t.Error("principal missing code:run scope")
	}
	// A different token resolves to a DIFFERENT principal — the whole point.
	p2, ok, _ := v.VerifyToken(context.Background(), "tok-b")
	if !ok || p2.UserID != "mcp-b" {
		t.Errorf("tok-b -> %q ok=%v, want mcp-b", p2.UserID, ok)
	}
	if _, ok, _ := v.VerifyToken(context.Background(), "wrong"); ok {
		t.Error("an unknown token was accepted")
	}
	if _, ok, _ := v.VerifyToken(context.Background(), ""); ok {
		t.Error("an empty token was accepted")
	}
}

func TestLoadClientsRejectsBadConfig(t *testing.T) {
	cases := map[string]string{
		"missing id":    `{"clients":[{"token_sha256":"` + sha256hex("x") + `"}]}`,
		"short hash":    `{"clients":[{"id":"a","token_sha256":"abc"}]}`,
		"non-hex hash":  `{"clients":[{"id":"a","token_sha256":"` + strings.Repeat("z", 64) + `"}]}`,
		"empty list":    `{"clients":[]}`,
		"unknown field": `{"clients":[{"id":"a","token_sha256":"` + sha256hex("x") + `","oops":1}]}`,
		"reserved id":   `{"clients":[{"id":"*","token_sha256":"` + sha256hex("x") + `"}]}`,
		"trailing data": `{"clients":[{"id":"a","token_sha256":"` + sha256hex("x") + `"}]} garbage`,
	}
	for name, body := range cases {
		if _, err := LoadClients(writeClients(t, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadClientsRejectsDuplicateID(t *testing.T) {
	body := `{"clients":[{"id":"same","token_sha256":"` + sha256hex("a") + `"},{"id":" same ","token_sha256":"` + sha256hex("b") + `"}]}`
	if _, err := LoadClients(writeClients(t, body)); err == nil {
		t.Fatal("expected an error for duplicate normalized client IDs")
	}
}

func TestNilFileVerifierFailsClosed(t *testing.T) {
	var v *FileVerifier
	if _, ok, err := v.VerifyToken(context.Background(), "token"); err != nil || ok {
		t.Fatalf("nil verifier returned ok=%v err=%v, want false,nil", ok, err)
	}
}

func TestLoadClientsRejectsDuplicateToken(t *testing.T) {
	h := sha256hex("same")
	body := `{"clients":[{"id":"a","token_sha256":"` + h + `"},{"id":"b","token_sha256":"` + h + `"}]}`
	if _, err := LoadClients(writeClients(t, body)); err == nil {
		t.Fatal("expected an error for a duplicate token_sha256")
	}
}

// TestAuditCallerUsesPrincipalUserID closes the loop: a verified client's UserID is
// what RunJavaScript stamps as the token-minting subject (via WithSubject).
func TestAuditCallerUsesPrincipalUserID(t *testing.T) {
	ctx := context.WithValue(context.Background(), principalKey{}, Principal{UserID: "mcp-a"})
	if got := auditCaller(ctx); got != "mcp-a" {
		t.Errorf("auditCaller = %q, want mcp-a", got)
	}
	if got := auditCaller(context.Background()); got != "anon" {
		t.Errorf("auditCaller(no principal) = %q, want anon", got)
	}
}

func TestLoadClientsFromEnvUnsetIsNil(t *testing.T) {
	t.Setenv("PLIMSOLL_CLIENTS_FILE", "")
	v, err := LoadClientsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Error("expected a nil verifier when PLIMSOLL_CLIENTS_FILE is unset")
	}
}
