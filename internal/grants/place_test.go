package grants

import (
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestLoadProfileTokenPlace: token.place puts the credential in a named header or HTTP
// basic authentication, the default stays Authorization: Bearer, and a stray or wrong
// setting fails the load.
func TestLoadProfileTokenPlace(t *testing.T) {
	t.Setenv("PLACE_TOKEN", "tok-123")
	load := func(token string) (*sandbox.HostAPIGrant, error) {
		p := writeGrants(t, `{"profiles": {"x": {"base_url": "https://api.example", "allow": ["GET /v1/models"],
		  "allowed_callers": ["agent-a"], "token": `+token+`}}}`)
		r, err := Load(p)
		if err != nil {
			return nil, err
		}
		profile, _ := r.Get("x")
		return profile.Grant(), nil
	}
	for token, want := range map[string]sandbox.CredentialPlacement{
		`{"env": "PLACE_TOKEN"}`:                                                {},
		`{"env": "PLACE_TOKEN", "place": "bearer"}`:                             {},
		`{"env": "PLACE_TOKEN", "place": "header", "header": "x-goog-api-key"}`: {Kind: "header", Header: "x-goog-api-key"},
		`{"env": "PLACE_TOKEN", "place": "basic", "username": "svc"}`:           {Kind: "basic", Username: "svc"},
		`{"env": "PLACE_TOKEN", "place": "basic"}`:                              {Kind: "basic"},
	} {
		g, err := load(token)
		if err != nil {
			t.Errorf("%s: %v", token, err)
			continue
		}
		if g.CredentialPlacement != want {
			t.Errorf("%s: placement %+v, want %+v", token, g.CredentialPlacement, want)
		}
	}
	for _, bad := range []string{
		`{"env": "PLACE_TOKEN", "place": "query"}`, `{"env": "PLACE_TOKEN", "place": "header"}`,
		`{"env": "PLACE_TOKEN", "place": "header", "header": "Authorization"}`, `{"env": "PLACE_TOKEN", "place": "header", "header": "Host"}`,
		`{"env": "PLACE_TOKEN", "place": "header", "header": "x-k", "username": "u"}`, `{"env": "PLACE_TOKEN", "header": "x-goog-api-key"}`,
		`{"env": "PLACE_TOKEN", "username": "u"}`, `{"env": "PLACE_TOKEN", "place": "basic", "username": "a:b"}`,
		`{"env": "PLACE_TOKEN", "place": "basic", "header": "x-k"}`, `{"env": "PLACE_TOKEN", "place": "Header", "header": "x-k"}`,
	} {
		if _, err := load(bad); err == nil {
			t.Errorf("Load accepted token %s", bad)
		}
	}
	p := writeGrants(t, `{"profiles": {"x": {"base_url": "https://api.example", "allow": ["GET /v1/models"], "allowed_callers": ["agent-a"],
	  "token": {"env": "PLACE_TOKEN", "place": "header", "header": "x-k"}, "pass_headers": ["X-K"]}}}`)
	if _, err := Load(p); err == nil {
		t.Error("Load accepted the credential header in pass_headers")
	}
}
