package grants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

func writeGrants(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "grants.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadProfile(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-123")
	p := writeGrants(t, `{
	  "profiles": {
	    "hue-control": {
	      "base_url": "https://hue.internal",
	      "allow": ["PUT /v1/lights/*/on", "get /v1/lights"],
	      "allowed_callers": ["mcp-a"],
	      "token": {"type": "static", "env": "HUE_TOKEN"},
	      "scopes": ["lights:write"]
	    }
	  }
	}`)
	r, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	profile, ok := r.Get("hue-control")
	if !ok {
		t.Fatal("profile hue-control not found")
	}
	g := profile.Grant()
	if g.BaseURL != "https://hue.internal" {
		t.Errorf("base_url = %q", g.BaseURL)
	}
	if len(g.Allow) != 2 || g.Allow[0].Method != "PUT" || g.Allow[0].Path != "/v1/lights/*/on" {
		t.Errorf("allow parsed wrong: %+v", g.Allow)
	}
	if g.Allow[1].Method != "GET" { // method upper-cased
		t.Errorf("method not normalized: %+v", g.Allow[1])
	}
	if _, ok := r.Get("nope"); ok {
		t.Error("unknown profile should not resolve")
	}
	if !profile.Allows("mcp-a") || profile.Allows("mcp-b") {
		t.Errorf("profile caller ACL not enforced")
	}
}

func TestLoadHealthCheck(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-123")
	p := writeGrants(t, `{
	  "profiles": {
	    "hue-control": {
	      "base_url": "https://hue.internal",
	      "allow": ["GET /v1/lights"],
	      "allowed_callers": ["mcp-a"],
	      "token": {"type": "static", "env": "HUE_TOKEN"},
	      "health_check": "GET /v1/health"
	    }
	  }
	}`)
	r, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	profile, _ := r.Get("hue-control")
	hc := profile.Grant().HealthCheck
	if hc == nil || hc.Method != "GET" || hc.Path != "/v1/health" {
		t.Fatalf("health_check parsed wrong: %+v", hc)
	}
}

func TestLoadCatalog(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-123")
	p := writeGrants(t, `{
	  "profiles": {
	    "hue-control": {
	      "base_url": "https://hue.internal",
	      "allow": ["GET /v1/lights/*"],
	      "catalog": ["GET /v1/lights/*", "get /v1/lights"],
	      "allowed_callers": ["mcp-a"],
	      "token": {"type": "static", "env": "HUE_TOKEN"}
	    }
	  }
	}`)
	r, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	profile, _ := r.Get("hue-control")
	cat := profile.Catalog()
	if len(cat) != 2 || cat[1].Method != "GET" || cat[1].Path != "/v1/lights" {
		t.Fatalf("catalog parsed wrong: %+v", cat)
	}
	// Catalog grants nothing: it is not part of the grant's Allow surface.
	if len(profile.Grant().Allow) != 1 {
		t.Errorf("catalog must not widen Allow: %+v", profile.Grant().Allow)
	}
}

func TestLoadRejectsNonGetHealthCheck(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-123")
	p := writeGrants(t, `{
	  "profiles": {
	    "hue-control": {
	      "base_url": "https://hue.internal",
	      "allow": ["GET /v1/lights"],
	      "allowed_callers": ["mcp-a"],
	      "token": {"type": "static", "env": "HUE_TOKEN"},
	      "health_check": "POST /v1/health"
	    }
	  }
	}`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "must be a GET route") {
		t.Fatalf("Load() = %v, want a non-GET health_check rejection", err)
	}
}

func TestLoadAdviceModes(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok")
	base := `"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"token":{"type":"static","env":"HUE_TOKEN"}`
	p := writeGrants(t, `{"profiles":{
	  "silent":{`+base+`},
	  "off":{`+base+`,"advice":"off"},
	  "operator":{`+base+`,"advice":"operator"},
	  "caller":{`+base+`,"advice":"caller"}
	}}`)
	r, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for name, want := range map[string]AdviceMode{
		"silent":   AdviceOff, // absent field defaults to off (opt-in)
		"off":      AdviceOff,
		"operator": AdviceOperator,
		"caller":   AdviceCaller,
	} {
		prof, ok := r.Get(name)
		if !ok {
			t.Fatalf("profile %q missing", name)
		}
		if got := prof.Advice(); got != want {
			t.Errorf("profile %q advice = %v, want %v", name, got, want)
		}
	}
	// A nil Profile advises nothing.
	if (*Profile)(nil).Advice() != AdviceOff {
		t.Error("nil profile should advise off")
	}
}

func TestLoadRejectsUnknownAdviceMode(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok")
	p := writeGrants(t, `{"profiles":{"bad":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"token":{"type":"static","env":"HUE_TOKEN"},"advice":"loud"}}}`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "advice") {
		t.Fatalf("expected an advice-mode error, got %v", err)
	}
}

func TestLoadAdviceRetention(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok")
	base := `"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"token":{"type":"static","env":"HUE_TOKEN"}`
	p := writeGrants(t, `{"profiles":{
	  "silent":{`+base+`,"advice":"operator"},
	  "none":{`+base+`,"advice":"operator","advice_retention":"none"},
	  "aggregate":{`+base+`,"advice":"operator","advice_retention":"aggregate"},
	  "detailed":{`+base+`,"advice":"operator","advice_retention":"detailed"}
	}}`)
	r, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for name, want := range map[string]AdviceRetention{
		"silent":    RetentionNone, // absent field defaults to none (opt-in)
		"none":      RetentionNone,
		"aggregate": RetentionAggregate,
		"detailed":  RetentionDetailed,
	} {
		prof, ok := r.Get(name)
		if !ok {
			t.Fatalf("profile %q missing", name)
		}
		if got := prof.AdviceRetention(); got != want {
			t.Errorf("profile %q retention = %v, want %v", name, got, want)
		}
	}
	// A nil Profile retains nothing.
	if (*Profile)(nil).AdviceRetention() != RetentionNone {
		t.Error("nil profile should retain none")
	}
}

func TestLoadRejectsUnknownAdviceRetention(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok")
	p := writeGrants(t, `{"profiles":{"bad":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"token":{"type":"static","env":"HUE_TOKEN"},"advice":"operator","advice_retention":"forever"}}}`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "advice_retention") {
		t.Fatalf("expected an advice_retention error, got %v", err)
	}
}

func TestLoadRejectsTrailingDataAndInvalidProfileNames(t *testing.T) {
	for name, body := range map[string]string{
		"trailing data":          `{"profiles":{}} garbage`,
		"surrounding whitespace": `{"profiles":{" bad ":{"base_url":"https://x","allowed_callers":["test"]}}}`,
		"unsupported character":  `{"profiles":{"bad/name":{"base_url":"https://x","allowed_callers":["test"]}}}`,
	} {
		if _, err := Load(writeGrants(t, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadRejectsPreambleSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	grantsDir := filepath.Join(root, "config")
	if err := os.Mkdir(grantsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.js")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(grantsDir, "sdk.js")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(grantsDir, "grants.json")
	body := `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"preamble_file":"sdk.js"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected a symlinked preamble outside the grants directory to be rejected")
	}
}

func TestLoadRejectsForbiddenScope(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"bad":{"base_url":"https://x","allow":["GET /v1/x"],"allowed_callers":["test"],"scopes":["code:run"]}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for a code:run scope")
	}
}

func TestLoadRejectsMissingBaseURL(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"bad":{"allow":["GET /v1/x"],"allowed_callers":["test"]}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for missing base_url")
	}
}

func TestLoadRejectsUnsetTokenEnv(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"bad":{"base_url":"https://x","allow":["GET /v1/x"],"allowed_callers":["test"],"token":{"type":"static","env":"CR_DEFINITELY_UNSET_XYZ"}}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for an unset static token env")
	}
}

func TestLoadRejectsMalformedAllow(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"bad":{"base_url":"https://x","allow":["GET"],"allowed_callers":["test"]}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for a malformed allow entry")
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"bad":{"base_url":"https://x","allow":["GET /v1/x"],"allowed_callers":["test"],"oops":1}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for an unknown config field")
	}
}

func TestLoadFromEnvUnsetIsEmpty(t *testing.T) {
	t.Setenv("PLIMSOLL_GRANTS_FILE", "")
	r, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 0 {
		t.Errorf("expected empty registry, got %d profiles", r.Len())
	}
	if _, ok := r.Get("anything"); ok {
		t.Error("empty registry should resolve nothing")
	}
}

func TestLoadPreambleFile(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"preamble_file":"sdk.js"}}}`)
	// preamble_file resolves relative to the grants file, so put sdk.js next to it.
	if err := os.WriteFile(filepath.Join(filepath.Dir(p), "sdk.js"), []byte("globalThis.x = 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	profile, _ := r.Get("p")
	if profile.Grant().Preamble != "globalThis.x = 1;" {
		t.Errorf("preamble = %q, want it loaded from sdk.js", profile.Grant().Preamble)
	}
}

func TestLoadRejectsPreambleFileTraversal(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"preamble_file":"../escape.js"}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for a preamble_file escaping the grants dir")
	}
}

func TestLoadRejectsPreambleAndFile(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"preamble":"y","preamble_file":"sdk.js"}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error when both preamble and preamble_file are set")
	}
}

// TestExampleProfileLoads loads the REAL committed example profile and its client
// file, proving the artifacts under docs/examples/grants wire into a valid grant
// rather than being prose that drifted from the loader. It is the only test that
// exercises preamble_file resolving a sibling path relative to the profile.
func TestExampleProfileLoads(t *testing.T) {
	t.Setenv("INVENTORY_JWT_SECRET", strings.Repeat("s", 32))
	r, err := Load("../../docs/examples/grants/grants.example.json")
	if err != nil {
		t.Fatalf("load example: %v", err)
	}
	p, ok := r.Get("inventory")
	if !ok {
		t.Fatal("inventory profile not found")
	}
	g := p.Grant()
	if g.BaseURL == "" || len(g.Allow) == 0 {
		t.Errorf("incomplete grant: %+v", g)
	}
	if !strings.Contains(g.Preamble, "globalThis.inventory") {
		t.Errorf("preamble was not loaded from inventory.client.js")
	}
}

func TestLoadRequiresAllowedCallers(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"]}}}`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "allowed_callers") {
		t.Fatalf("Load error = %v, want required allowed_callers", err)
	}
}

func TestLoadRejectsWhitespaceScopeInjection(t *testing.T) {
	p := writeGrants(t, `{"profiles":{"p":{"base_url":"https://x","allow":["GET /a"],"allowed_callers":["test"],"scopes":["safe code:run"]}}}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected a scope entry containing two tokens to be rejected")
	}
}

func TestNilRegistryGet(t *testing.T) {
	var r *Registry
	if _, ok := r.Get("x"); ok {
		t.Error("nil registry should resolve nothing")
	}
	if r.Len() != 0 {
		t.Error("nil registry Len should be 0")
	}
}

// TestRegistryIsFrozenAfterLoad verifies the registry hands out deep copies: a
// consumer mutating one run's grant (routes, scopes, or the top-level struct)
// must never change what the next Get returns. Without this, hostile-input
// handling anywhere downstream could permanently widen a loaded profile.
func TestRegistryIsFrozenAfterLoad(t *testing.T) {
	t.Setenv("HUE_TOKEN", "tok-123")
	p := writeGrants(t, `{
	  "profiles": {
	    "hue": {
	      "base_url": "https://hue.internal",
	      "allow": ["GET /v1/lights"],
	      "allowed_callers": ["mcp-a"],
	      "token": {"type": "static", "env": "HUE_TOKEN"},
	      "scopes": ["lights:read"]
	    }
	  }
	}`)
	r, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	profile, _ := r.Get("hue")
	first := profile.Grant()
	first.BaseURL = "https://evil.example"
	first.Allow[0] = sandbox.HostRoute{Method: "DELETE", Path: "/admin"}
	first.Allow = append(first.Allow, sandbox.HostRoute{Method: "PUT", Path: "/v1/anything/*"})
	first.Scopes[0] = "everything:write"

	second := profile.Grant()
	if second.BaseURL != "https://hue.internal" {
		t.Fatalf("BaseURL mutated through a run's grant: %q", second.BaseURL)
	}
	if len(second.Allow) != 1 || second.Allow[0].Method != "GET" || second.Allow[0].Path != "/v1/lights" {
		t.Fatalf("Allow mutated through a run's grant: %+v", second.Allow)
	}
	if second.Scopes[0] != "lights:read" {
		t.Fatalf("Scopes mutated through a run's grant: %v", second.Scopes)
	}
	if first == second {
		t.Fatal("Grant() returned the same pointer twice")
	}
}
