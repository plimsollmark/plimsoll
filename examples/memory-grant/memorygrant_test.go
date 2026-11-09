package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/specgen"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// published is the page's directory, from this package's.
var published = filepath.Join("..", "..", "docs", "examples", "memory-grant")

// The committed page, the generated grant files and the profile are what the example
// produces now: the five runs pass their checks, and every file is byte for byte what
// they render.
func TestPublishedFilesAreCurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ev, err := generate(ctx, published, compareFile(published))
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Scenes) != len(scenes) || len(ev.Server) != 4 {
		t.Fatalf("%d scenes and %d requests at the API, want %d and 4", len(ev.Scenes), len(ev.Server), len(scenes))
	}
	page, err := os.ReadFile(filepath.Join(published, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(page), fakeToken) {
		t.Fatal("the page prints the token")
	}
}

// The key search in the fifth run can find a key that is there: with a preamble that
// plants it in a global, the same snippet names the global, and execArgv too, since
// execArgv holds all the source the engine was given, the preamble included. Without
// this, "none" could be a search that finds nothing anywhere.
func TestKeySearchFindsAPlantedKey(t *testing.T) {
	provider := sandbox.DefaultWasm()
	grant := &sandbox.HostAPIGrant{
		BaseURL:  "http://127.0.0.1:1",
		Allow:    []sandbox.HostRoute{{Method: "GET", Path: "/x"}},
		Minter:   sandbox.StaticToken(fakeToken),
		Global:   global,
		Preamble: `globalThis.planted = "` + fakeToken + `";`,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := provider.RunJavaScript(ctx, sandbox.Request{Code: scenes[len(scenes)-1].code, Grant: grant, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "globals holding the key: execArgv,planted") {
		t.Fatalf("the search missed a planted key:\n%s", res.Stdout)
	}
}

// Each claim the run checks fails when it is false.
func TestEvidenceChecksFailWhenFalse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ev, err := generate(ctx, published, func(string, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	grant := &sandbox.HostAPIGrant{}
	for name, alter := range map[string]func(*evidence){
		"a trace row holding a raw path": func(e *evidence) {
			e.Scenes[0].Calls[2].Route = strings.Replace(e.Scenes[0].Calls[2].Route, "*", "01JFAKEMEM0000000000000001", 1)
		},
		"a trace row holding the memory's content": func(e *evidence) { e.Scenes[0].Calls[0].Route += memoryContent },
		"a request without the broker's token":     func(e *evidence) { e.Server[0].Credential = "none" },
		"another customer's profile reached":       func(e *evidence) { e.Server[1].Path = strings.Replace(e.Server[1].Path, profile, "customer-43", 1) },
		"the delete reached":                       func(e *evidence) { e.Server[2].Method = "DELETE" },
		"the token in the profile":                 func(e *evidence) { e.Profile += fakeToken },
	} {
		t.Run(name, func(t *testing.T) {
			e := *ev
			e.Scenes = append([]scene(nil), ev.Scenes...)
			e.Scenes[0].Calls = append([]traceRow(nil), ev.Scenes[0].Calls...)
			e.Server = append([]seenRequest(nil), ev.Server...)
			alter(&e)
			if err := checkEvidence(&e, grant); err == nil {
				t.Fatal("checkEvidence accepted it")
			}
		})
	}
}

// The profile must narrow the document: a route the document does not have, a
// catalog that drifted from it, or a preamble that is not specgen's is refused.
func TestProfileMustNarrowTheDocument(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join(published, specFile))
	if err != nil {
		t.Fatal(err)
	}
	gen, err := specgen.Generate(spec, specgen.Options{Global: global})
	if err != nil {
		t.Fatal(err)
	}
	good := func() *sandbox.HostAPIGrant {
		return &sandbox.HostAPIGrant{Global: global, Preamble: gen.Preamble, Allow: []sandbox.HostRoute{
			{Method: "POST", Path: "/client/v4/accounts/1/agent-memory/namespaces/n/profiles/p/recall"},
		}}
	}
	if err := checkProfile(gen, gen.Allow, good()); err != nil {
		t.Fatalf("a narrowing was refused: %v", err)
	}
	for name, tc := range map[string]struct {
		catalog []sandbox.HostRoute
		alter   func(*sandbox.HostAPIGrant)
	}{
		"a route the document lacks": {gen.Allow, func(g *sandbox.HostAPIGrant) {
			g.Allow[0].Path = "/client/v4/accounts/1/agent-memory/namespaces/n/profiles/p/export"
		}},
		"the right path, the wrong method": {gen.Allow, func(g *sandbox.HostAPIGrant) { g.Allow[0].Method = "DELETE" }},
		"a route without the base path": {gen.Allow, func(g *sandbox.HostAPIGrant) {
			g.Allow[0].Path = "/accounts/1/agent-memory/namespaces/n/profiles/p/recall"
		}},
		"a drifted catalog": {gen.Allow[1:], func(*sandbox.HostAPIGrant) {}},
		"another preamble":  {gen.Allow, func(g *sandbox.HostAPIGrant) { g.Preamble += "\n" }},
	} {
		t.Run(name, func(t *testing.T) {
			g := good()
			tc.alter(g)
			if err := checkProfile(gen, tc.catalog, g); err == nil {
				t.Fatal("checkProfile accepted it")
			}
		})
	}
}

// The fake API refuses a request without the token or with another one, so the runs'
// 200s show the broker attached it.
func TestFakeRefusesWithoutTheToken(t *testing.T) {
	fake := newFakeMemory(fakeToken)
	api := httptest.NewServer(fake)
	defer api.Close()
	path := api.URL + "/client/v4/accounts/" + account + "/agent-memory/namespaces/" + namespace + "/profiles/" + profile + "/recall"
	for name, auth := range map[string]string{"none": "", "a wrong one": "Bearer another-token", "the broker's token": "Bearer " + fakeToken} {
		req, err := http.NewRequest(http.MethodPost, path, strings.NewReader(`{"query":"anything at all"}`))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := http.StatusUnauthorized
		if name == "the broker's token" {
			want = http.StatusOK
		}
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", name, resp.StatusCode, want)
		}
	}
	recorded := map[string]int{}
	for _, r := range fake.requests() {
		recorded[r.Credential]++
	}
	if len(recorded) != 3 || recorded["none"] != 1 || recorded["a wrong one"] != 1 || recorded["the broker's token"] != 1 {
		t.Errorf("the fake recorded %v, want one request of each kind", recorded)
	}
}

// The extract is made from the pinned upstream file only.
func TestExtractRefusesAnotherFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "openapi.json")
	if err := os.WriteFile(src, []byte(`{"openapi":"3.0.3","paths":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := writeExtract(src, filepath.Join(dir, specFile))
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("err = %v, want a refusal naming the SHA-256", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, specFile)); !os.IsNotExist(statErr) {
		t.Fatal("an extract was written from another file")
	}
}
