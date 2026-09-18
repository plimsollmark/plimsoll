package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/clientconfig"
	"github.com/plimsollmark/plimsoll/internal/rpc"
)

func invoke(t *testing.T, input string, args ...string) (string, string) {
	t.Helper()
	var out, diagnostic bytes.Buffer
	if err := run(args, strings.NewReader(input), &out, &diagnostic); err != nil {
		t.Fatalf("command failed: %v", err)
	}
	return out.String(), diagnostic.String()
}

func loadVerifier(t *testing.T, path string) *rpc.FileVerifier {
	t.Helper()
	v, err := rpc.LoadClients(path)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func authenticate(v *rpc.FileVerifier, token string) (int, string) {
	id := ""
	h := rpc.AuthenticateHTTP(v, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := rpc.PrincipalFrom(r.Context())
		id = p.UserID
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/plimsoll.v1.SandboxService/Describe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, id
}

func TestCredentialLifecycleAndActivation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	out, diagnostic := invoke(t, "", "create", "-file", path, "-id", "client-a", "-token-stdout")
	token := strings.TrimSuffix(out, "\n")
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		t.Fatal("generated token does not encode 32 random bytes")
	}
	if !strings.Contains(diagnostic, "restart EVERY") || strings.Contains(diagnostic, token) {
		t.Fatal("activation instruction missing or generated secret leaked to diagnostics")
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte(token)) {
		t.Fatal("registry could not be read or contains the plaintext credential")
	}
	registry, err := clientconfig.Parse(raw)
	if err != nil || len(registry.Clients) != 1 || registry.Clients[0].TokenSHA256 != clientconfig.Fingerprint(token) {
		t.Fatal("registry did not store the generated token's fingerprint")
	}
	old := loadVerifier(t, path)
	if status, id := authenticate(old, token); status != http.StatusNoContent || id != "client-a" {
		t.Fatalf("created caller failed HTTP authentication: status=%d id=%q", status, id)
	}
	if status, _ := authenticate(old, "unregistered"); status != http.StatusUnauthorized {
		t.Fatal("unknown token was accepted")
	}
	invoke(t, "other-synthetic-token\n", "import", "-file", path, "-id", "client-b", "-scope", "other:permission")
	listed, _ := invoke(t, "", "list", "-file", path, "-json")
	var callers []map[string]any
	if err := json.Unmarshal([]byte(listed), &callers); err != nil || len(callers) != 2 {
		t.Fatal("list did not return both callers")
	}
	for _, c := range callers {
		if len(c) != 2 || c["id"] == nil || c["scopes"] == nil {
			t.Fatal("list exposed fields beyond caller ID and scopes")
		}
	}
	if status, _ := authenticate(loadVerifier(t, path), "other-synthetic-token"); status != http.StatusForbidden {
		t.Fatal("a recognized token without code:run could execute an RPC")
	}
	out, _ = invoke(t, "", "rotate", "-file", path, "-id", "client-a", "-token-stdout")
	replacement := strings.TrimSuffix(out, "\n")
	current := loadVerifier(t, path)
	if status, id := authenticate(current, replacement); status != http.StatusNoContent || id != "client-a" {
		t.Fatal("rotation changed identity/permissions or failed to activate in a newly loaded verifier")
	}
	if status, _ := authenticate(current, token); status != http.StatusUnauthorized {
		t.Fatal("new verifier accepted the old credential after rotation")
	}
	if status, _ := authenticate(old, token); status != http.StatusNoContent {
		t.Fatal("editing the file unexpectedly altered an already loaded verifier")
	}
	invoke(t, "imported-replacement\r\n", "rotate", "-file", path, "-id", "client-a", "-token-stdin")
	if status, _ := authenticate(loadVerifier(t, path), replacement); status != http.StatusUnauthorized {
		t.Fatal("imported rotation left the previous credential active")
	}
	invoke(t, "", "revoke", "-file", path, "-id", "client-a")
	if status, _ := authenticate(loadVerifier(t, path), "imported-replacement"); status != http.StatusUnauthorized {
		t.Fatal("revoked caller is still authorized in the updated configuration")
	}
	_, diagnostic = invoke(t, "", "revoke", "-file", path, "-id", "client-b")
	if !strings.Contains(diagnostic, "refuses to start") || !strings.Contains(diagnostic, "Stop every daemon") {
		t.Fatal("last-caller revocation did not explain the fail-closed activation step")
	}
	if _, err := rpc.LoadClients(path); err == nil {
		t.Fatal("daemon accepted an empty registry")
	}
	listed, _ = invoke(t, "", "list", "-file", path, "-json")
	if strings.TrimSpace(listed) != "[]" {
		t.Fatal("revocation did not remove the final caller")
	}
	invoke(t, "", "create", "-file", path, "-id", "new-caller", "-token-stdout")
	if loadVerifier(t, path).Len() != 1 {
		t.Fatal("could not recover an empty registry by adding a caller")
	}
}

func TestFailuresDoNotChangeRegistryOrExposeInput(t *testing.T) {
	const secret = "synthetic-existing-secret"
	path := filepath.Join(t.TempDir(), "clients.json")
	invoke(t, secret, "import", "-file", path, "-id", "existing")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, input string
		args        []string
	}{
		{"create needs explicit output", "", []string{"create", "-id", "new"}},
		{"duplicate ID", secret, []string{"import", "-id", "existing"}},
		{"duplicate token", secret, []string{"import", "-id", "new"}},
		{"invalid identity", secret, []string{"import", "-id", "*"}},
		{"control in identity", secret, []string{"import", "-id", "bad\nname"}},
		{"invalid scope", secret, []string{"import", "-id", "new", "-scope", "code:run other"}},
		{"duplicate scope", secret, []string{"import", "-id", "new", "-scope", "code:run", "-scope", "code:run"}},
		{"whitespace in token", secret + " suffix", []string{"import", "-id", "new"}},
		{"oversized input", strings.Repeat("a", 4097), []string{"import", "-id", "new"}},
		{"empty input", "", []string{"import", "-id", "new"}},
		{"unknown rotation", "", []string{"rotate", "-id", "missing", "-token-stdout"}},
		{"ambiguous rotation", "", []string{"rotate", "-id", "existing", "-token-stdout", "-token-stdin"}},
		{"unchanged rotation", secret, []string{"rotate", "-id", "existing", "-token-stdin"}},
		{"unknown revocation", "", []string{"revoke", "-id", "missing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output, diagnostic bytes.Buffer
			args := append(append([]string{}, tc.args...), "-file", path)
			err := run(args, strings.NewReader(tc.input), &output, &diagnostic)
			if err == nil {
				t.Fatal("invalid operation succeeded")
			}
			if output.Len() != 0 || strings.Contains(diagnostic.String()+err.Error(), secret) {
				t.Fatal("failure exposed a credential")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed operation modified the registry")
			}
		})
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestGeneratedTokenOutputFailureExplainsRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	var diagnostic bytes.Buffer
	err := run([]string{"create", "-file", path, "-id", "a", "-token-stdout"}, strings.NewReader(""), brokenWriter{}, &diagnostic)
	if err == nil || !strings.Contains(err.Error(), "registry updated") || !strings.Contains(err.Error(), "rotate") {
		t.Fatal("failed delivery concealed that the registry was already updated")
	}
	f, _, err := clientconfig.ReadRegular(path)
	if err != nil || len(f.Clients) != 1 {
		t.Fatal("delivery failure must not pretend the saved registry was rolled back")
	}
}

func TestReadFailureNeverEchoesReaderError(t *testing.T) {
	_, err := readToken(errorReader{})
	if err == nil || strings.Contains(err.Error(), "private-reader-detail") {
		t.Fatal("token reader leaked upstream error data")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("private-reader-detail") }

// Exercise main's SIGPIPE handling in a separate process with a closed secret
// destination. An io.Writer stub cannot detect an unexpected process signal exit.
func TestClosedSecretPipeReportsRecovery(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	defer writer.Close()
	path := filepath.Join(t.TempDir(), "clients.json")
	cmd := exec.Command(executable, "-test.run=^TestCLIProcess$", "--", "create", "-file", path, "-id", "pipe-test", "-token-stdout")
	cmd.Env = append(os.Environ(), "PLIMSOLL_TEST_CLIENTS_CLI_HELPER=1")
	cmd.Stdout = writer
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err == nil || !strings.Contains(diagnostic.String(), "registry updated but generated token delivery failed") {
		t.Fatal("closed output pipe did not report the saved registry and recovery instructions")
	}
}

func TestCLIProcess(t *testing.T) {
	if os.Getenv("PLIMSOLL_TEST_CLIENTS_CLI_HELPER") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		t.Fatal("missing helper argument separator")
	}
	os.Args = append([]string{"plimsoll-clients"}, os.Args[separator+1:]...)
	main()
	os.Exit(0)
}
