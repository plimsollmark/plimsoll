// Command memory-grant shows agent-written code using a hosted memory API through a
// plimsoll grant: the code stores a memory and recalls it in a later run, the API key
// stays in the broker on the host, and the run's call trace names route templates only.
//
// The API is Cloudflare's Agent Memory. Its operations are taken unchanged from the
// OpenAPI document Cloudflare publishes under the BSD 3-Clause license, the grant's
// catalog, typed client and model-facing description are generated from it by
// plimsoll-specgen, and the API itself is a fake on loopback (fake.go), so the example
// needs no account, no key and no network, and spends nothing:
//
//	go run ./examples/memory-grant          # rewrite docs/examples/memory-grant
//	go run ./examples/memory-grant -check   # write nothing; fail unless it is current
//
// Five runs, on the in-process WASM provider:
//
//  1. store a memory, recall it, and read it back by its ID;
//  2. a later run, in a fresh sandbox, recalls what the first one stored;
//  3. another customer's memory, through the client and around it, refused;
//  4. a route the key could reach and the grant does not list, refused;
//  5. the guest looking for the key, which is not in the sandbox to find.
//
// -extract FILE rebuilds the extract from Cloudflare's whole openapi.json, which must
// be the pinned commit's (upstreamURL); it refuses any other file.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/internal/grants"
	"github.com/plimsollmark/plimsoll/internal/specgen"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const (
	// pageDir holds the page, the spec extract and everything generated from it.
	pageDir  = "docs/examples/memory-grant"
	specFile = "agent-memory.openapi.json"

	// The upstream document, pinned: the extract is reproducible from exactly this file.
	upstreamRepo   = "https://github.com/cloudflare/api-schemas"
	upstreamCommit = "2d7642070d549e2e36be64d7ded20b4ac748f53a"
	upstreamURL    = "https://raw.githubusercontent.com/cloudflare/api-schemas/" + upstreamCommit + "/openapi.json"
	upstreamSHA256 = "29f54710427f411f81c6738c735f3586580f089648f20ca05212d94f4f52bdf0"
	// extractPrefix selects the Agent Memory operations from the whole Cloudflare API.
	extractPrefix = "/accounts/{account_id}/agent-memory/"

	// global is the JavaScript object the guest calls the API through.
	global = "memory"
	// profileName is the grant profile in grants.json; tokenEnv is where a daemon would
	// read the Cloudflare API token from.
	profileName = "agent-memory"
	tokenEnv    = "CLOUDFLARE_API_TOKEN"

	// fakeToken stands in for a Cloudflare API token. The broker attaches it to every
	// upstream request; the point of the example is that this string never enters the
	// JavaScript runtime.
	fakeToken = "fake-agent-memory-token-held-by-the-broker"
)

func main() {
	check := flag.Bool("check", false, "write nothing; fail unless every published file is what this run produces")
	extract := flag.String("extract", "", "rebuild "+specFile+" from Cloudflare's whole openapi.json at this path (the pinned commit's)")
	flag.Parse()

	var err error
	switch {
	case *extract != "":
		err = writeExtract(*extract, filepath.Join(pageDir, specFile))
	case *check:
		_, err = generate(context.Background(), pageDir, compareFile(pageDir))
		if err == nil {
			fmt.Println("memory-grant: every published file is current")
		}
	default:
		_, err = generate(context.Background(), pageDir, writeFile(pageDir))
		if err == nil {
			fmt.Println("memory-grant: wrote", pageDir)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "memory-grant:", err)
		os.Exit(1)
	}
}

// emitFunc receives each generated file: written in the default mode, compared with
// the committed one under -check.
type emitFunc func(name string, data []byte) error

func writeFile(dir string) emitFunc {
	return func(name string, data []byte) error {
		return os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}
}

func compareFile(dir string) emitFunc {
	return func(name string, data []byte) error {
		have, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if !bytes.Equal(have, data) {
			return fmt.Errorf("%s is not what this run produces; run go run ./examples/memory-grant and review the diff", filepath.Join(dir, name))
		}
		return nil
	}
}

// evidence is everything the page shows, gathered from one run.
type evidence struct {
	SpecTitle, SpecVersion string
	UpstreamRepo           string
	UpstreamCommit         string
	UpstreamURL            string
	UpstreamSHA256         string
	BasePath               string
	Operations             int
	Catalog                []string // every route specgen derived, the profile's catalog
	Allow                  []string // the routes the profile grants
	Warnings               []string // specgen's notes on narrowed operations
	Description            string   // the model-facing text specgen wrote
	Profile                string   // grants.json as published
	Scenes                 []scene
	Server                 []seenRequest // every request the fake API received
	TokenEnv               string
	MemoryContent          string
}

// scene is one run: its code, what the guest printed, the broker's trace and the
// requests that reached the API while it ran.
type scene struct {
	Title   string
	Note    string
	Code    string
	Output  []string
	Calls   []traceRow
	Denied  int
	Reached []seenRequest
}

// traceRow is a CallRow without its latency, which differs from run to run; the page
// is the same on every run.
type traceRow struct {
	Seq       int
	Method    string
	Route     string
	Status    int
	ReqBytes  int
	RespBytes int
}

// generate builds every published file from the spec extract in dir and one run of the
// scenes, handing each file to emit, and checks the claims the page makes.
func generate(ctx context.Context, dir string, emit emitFunc) (*evidence, error) {
	spec, err := os.ReadFile(filepath.Join(dir, specFile))
	if err != nil {
		return nil, err
	}
	gen, err := specgen.Generate(spec, specgen.Options{Global: global})
	if err != nil {
		return nil, err
	}
	// The same three files plimsoll-specgen -outdir writes, rendered the same way.
	catalogJSON, err := json.MarshalIndent(gen.AllowStrings(), "", "  ")
	if err != nil {
		return nil, err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"allow.json", append(catalogJSON, '\n')},
		{"preamble.js", []byte(gen.Preamble)},
		{"description.txt", []byte(gen.Description)},
	} {
		if err := emit(f.name, f.data); err != nil {
			return nil, err
		}
	}

	// The profile is the operator's: specgen's routes as its catalog, three of them as
	// its allow list with the account, namespace and profile written in. It is loaded
	// exactly as plimsolld loads PLIMSOLL_GRANTS_FILE, with the fake token in the
	// variable the profile names.
	profilePath := filepath.Join(dir, "grants.json")
	profileRaw, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, err
	}
	reg, err := loadProfiles(profilePath)
	if err != nil {
		return nil, err
	}
	prof, ok := reg.Get(profileName)
	if !ok {
		return nil, fmt.Errorf("grants.json has no profile %q", profileName)
	}
	grant := prof.Grant()
	if err := checkProfile(gen, prof.Catalog(), grant); err != nil {
		return nil, err
	}

	fake := newFakeMemory(fakeToken)
	api := httptest.NewServer(fake)
	defer api.Close()
	// The one change from the published profile: base_url points at the fake.
	grant.BaseURL = api.URL

	provider, err := sandbox.Build(func(key string) string {
		if key == "SANDBOX_PROVIDER" {
			return "wasm"
		}
		return ""
	})
	if err != nil {
		return nil, err
	}
	if err := provider.EnsureReady(ctx); err != nil {
		return nil, err
	}

	ev := &evidence{
		SpecTitle:      gen.Title,
		SpecVersion:    gen.Version,
		UpstreamRepo:   upstreamRepo,
		UpstreamCommit: upstreamCommit,
		UpstreamURL:    upstreamURL,
		UpstreamSHA256: upstreamSHA256,
		BasePath:       gen.BasePath,
		Operations:     len(gen.Operations),
		Catalog:        gen.AllowStrings(),
		Warnings:       gen.Warnings,
		Description:    gen.Description,
		Profile:        string(profileRaw),
		TokenEnv:       tokenEnv,
		MemoryContent:  memoryContent,
	}
	for _, a := range grant.Allow {
		ev.Allow = append(ev.Allow, a.Method+" "+a.Path)
	}
	for _, s := range scenes {
		before := len(fake.requests())
		res, err := provider.Sandbox.RunJavaScript(ctx, sandbox.Request{Code: s.code, Grant: grant, Timeout: 20 * time.Second})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.title, err)
		}
		if res.ExitCode != 0 || res.Stderr != "" {
			return nil, fmt.Errorf("%s: exit %d, stderr %q", s.title, res.ExitCode, res.Stderr)
		}
		sc := scene{Title: s.title, Note: s.note, Code: strings.TrimSpace(s.code), Reached: fake.requests()[before:]}
		sc.Output = strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n")
		if res.CallTrace != nil {
			sc.Denied = res.CallTrace.Denied
			for _, row := range res.CallTrace.Calls {
				sc.Calls = append(sc.Calls, traceRow{Seq: row.Seq, Method: row.Method, Route: row.Route, Status: row.Status, ReqBytes: row.ReqBytes, RespBytes: row.RespBytes})
			}
		}
		if err := s.expect(sc); err != nil {
			return nil, fmt.Errorf("%s: %w", s.title, err)
		}
		ev.Scenes = append(ev.Scenes, sc)
		// The failure this design exists to prevent, checked rather than assumed.
		if strings.Contains(res.Stdout, fakeToken) || strings.Contains(res.Stderr, fakeToken) {
			return nil, fmt.Errorf("%s: the token reached guest-visible output", s.title)
		}
	}
	ev.Server = fake.requests()
	if err := checkEvidence(ev, grant); err != nil {
		return nil, err
	}

	page, err := renderPage(ev)
	if err != nil {
		return nil, err
	}
	if err := emit("index.html", page); err != nil {
		return nil, err
	}
	return ev, nil
}

// loadProfiles loads grants.json with the fake token in the variable its profile
// names, as a daemon would with the real one, and puts the variable back as it was.
func loadProfiles(path string) (*grants.Registry, error) {
	old, had := os.LookupEnv(tokenEnv)
	if err := os.Setenv(tokenEnv, fakeToken); err != nil {
		return nil, err
	}
	defer func() {
		if had {
			_ = os.Setenv(tokenEnv, old)
		} else {
			_ = os.Unsetenv(tokenEnv)
		}
	}()
	return grants.Load(path)
}

// checkProfile ties the published profile to the spec: its catalog is exactly what
// specgen derived, so it cannot drift from the document, and every allow entry is one
// of those routes with some "*" segments written in, so the grant is a narrowing of
// the document's surface and never a route the document does not have.
func checkProfile(gen *specgen.Result, catalog []sandbox.HostRoute, grant *sandbox.HostAPIGrant) error {
	var have []string
	for _, r := range catalog {
		have = append(have, r.Method+" "+r.Path)
	}
	if !slices.Equal(have, gen.AllowStrings()) {
		return fmt.Errorf("grants.json's catalog is not the route list specgen derives from %s:\n have %v\n want %v", specFile, have, gen.AllowStrings())
	}
	if grant.Global != global {
		return fmt.Errorf("grants.json's global is %q, and the preamble attaches to %q", grant.Global, global)
	}
	if grant.Preamble != gen.Preamble {
		return errors.New("grants.json's preamble_file is not the preamble specgen generates")
	}
	for _, a := range grant.Allow {
		if !slices.ContainsFunc(gen.Allow, func(c sandbox.HostRoute) bool { return narrows(a, c) }) {
			return fmt.Errorf("allow entry %s %s is not a narrowing of any route in the document", a.Method, a.Path)
		}
	}
	return nil
}

// narrows reports whether route a is route c with zero or more "*" segments replaced
// by literal ones.
func narrows(a, c sandbox.HostRoute) bool {
	if a.Method != c.Method {
		return false
	}
	as, cs := strings.Split(a.Path, "/"), strings.Split(c.Path, "/")
	if len(as) != len(cs) {
		return false
	}
	for i := range as {
		if cs[i] != "*" && as[i] != cs[i] {
			return false
		}
	}
	return true
}

// checkEvidence checks what the page claims across the whole run.
func checkEvidence(ev *evidence, grant *sandbox.HostAPIGrant) error {
	stored := ev.Scenes[0].Output
	for _, s := range ev.Scenes {
		for _, row := range s.Calls {
			// A trace row names an allow entry as written, never the path requested.
			if !slices.Contains(ev.Allow, row.Method+" "+row.Route) {
				return fmt.Errorf("%s: trace row %s %s is not an allow entry", s.Title, row.Method, row.Route)
			}
			for _, secret := range []string{memoryContent, "01JFAKEMEM", "customer-43", fakeToken} {
				if strings.Contains(row.Route, secret) {
					return fmt.Errorf("%s: trace row holds %q", s.Title, secret)
				}
			}
		}
	}
	if len(stored) == 0 || !strings.HasPrefix(stored[0], "stored 01JFAKEMEM") {
		return fmt.Errorf("the first run stored nothing: %q", stored)
	}
	for _, r := range ev.Server {
		if r.Credential != "the broker's token" {
			return fmt.Errorf("the API received %s %s with %s", r.Method, r.Path, r.Credential)
		}
		if strings.Contains(r.Path, "customer-43") || r.Method == "DELETE" {
			return fmt.Errorf("a refused call reached the API: %s %s", r.Method, r.Path)
		}
	}
	if strings.Contains(ev.Profile, fakeToken) || strings.Contains(grant.Preamble, fakeToken) {
		return errors.New("the token is written into the profile or the preamble")
	}
	return nil
}

// writeExtract rebuilds the spec extract from Cloudflare's whole openapi.json: the
// Agent Memory paths unchanged, the document's openapi, servers and info (with its
// description replaced by where the extract came from), and the one security scheme
// those operations name. It refuses any file but the pinned one, so the committed
// extract can be checked against its source by anyone who downloads upstreamURL.
func writeExtract(src, dst string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != upstreamSHA256 {
		return fmt.Errorf("%s has SHA-256 %s; the extract is made from %s, SHA-256 %s", src, got, upstreamURL, upstreamSHA256)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // numbers verbatim
	var doc struct {
		OpenAPI    string                    `json:"openapi"`
		Info       map[string]any            `json:"info"`
		Servers    []any                     `json:"servers"`
		Paths      map[string]map[string]any `json:"paths"`
		Components map[string]map[string]any `json:"components"`
	}
	if err := dec.Decode(&doc); err != nil {
		return err
	}
	paths := map[string]any{}
	schemes := map[string]any{}
	for p, item := range doc.Paths {
		if !strings.HasPrefix(p, extractPrefix) {
			continue
		}
		paths[p] = item
		for _, op := range item {
			opMap, ok := op.(map[string]any)
			if !ok {
				continue
			}
			reqs, _ := opMap["security"].([]any)
			for _, req := range reqs {
				m, _ := req.(map[string]any)
				for name := range m {
					scheme, ok := doc.Components["securitySchemes"][name]
					if !ok {
						return fmt.Errorf("%s names security scheme %q, which the document does not define", p, name)
					}
					schemes[name] = scheme
				}
			}
		}
	}
	if len(paths) == 0 {
		return fmt.Errorf("%s has no path under %s", src, extractPrefix)
	}
	names := make([]string, 0, len(paths))
	for p := range paths {
		names = append(names, p)
	}
	sort.Strings(names)
	out := map[string]any{
		"openapi": doc.OpenAPI,
		"info": map[string]any{
			"title":   doc.Info["title"],
			"version": doc.Info["version"],
			"license": doc.Info["license"],
			"description": fmt.Sprintf("The %d Agent Memory paths of the Cloudflare API, unchanged, from openapi.json in %s at commit %s (SHA-256 %s). "+
				"Only this description and the cut to these paths and the security scheme they name differ from the source. "+
				"Copyright (c) 2022, Cloudflare; BSD 3-Clause License, in LICENSE.cloudflare-api-schemas beside this file. Rebuilt by go run ./examples/memory-grant -extract FILE.",
				len(paths), upstreamRepo, upstreamCommit, upstreamSHA256),
		},
		"servers":    doc.Servers,
		"paths":      paths,
		"components": map[string]any{"securitySchemes": schemes},
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	if err := os.WriteFile(dst, b.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("memory-grant: wrote %s (%d paths: %s ... %s)\n", dst, len(paths), names[0], names[len(names)-1])
	return nil
}
