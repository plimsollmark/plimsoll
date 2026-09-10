package sandbox

// Call-level fuzzing for the hostile-input surfaces the 2026-07-15 hardening review
// named: project paths, grant routes/patterns, env parsing, Docker runner framing, and
// E2B stream frames (the Connect HTTP edge is fuzzed in internal/rpc). Each
// target asserts the SAFETY INVARIANT accepted inputs must uphold, not exact
// outputs, so `go test` replays the seeds as regressions and `go test -fuzz`
// explores. The corpus lives in testdata/fuzz once -fuzz finds anything.

import (
	"bytes"
	"net/url"
	pathpkg "path"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func FuzzValidateProjectPath(f *testing.F) {
	for _, seed := range []string{
		"main.ts", "src/app/x.tsx", "..", "../x", "a/../../b", "/etc/passwd",
		"a\\b", "a\x00b", ".", "a/./b", "a//b", "a/..", "%2e%2e/x", "..∕x",
		strings.Repeat("p/", 600) + "x", "a/.. /b", ".hidden", "a/", "\xff\xfe",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if err := validateProjectPath("file", p); err != nil {
			return
		}
		// Every accepted path must be exactly what providers assume when they
		// stage files: clean, relative, traversal-free, byte-sane.
		if p == "" || pathpkg.Clean(p) != p || strings.HasPrefix(p, "/") ||
			p == "." || p == ".." || strings.HasPrefix(p, "../") {
			t.Fatalf("accepted unsafe path %q", p)
		}
		if !utf8.ValidString(p) || strings.Contains(p, "\\") || strings.IndexFunc(p, unicode.IsControl) >= 0 {
			t.Fatalf("accepted byte-unsafe path %q", p)
		}
		if len(p) > MaxProjectPathBytes {
			t.Fatalf("accepted over-length path (%d bytes)", len(p))
		}
		// The join providers perform (docker /work, e2b project dir) must stay
		// strictly inside the root.
		if joined := pathpkg.Join("/work", p); joined == "/work" || !strings.HasPrefix(joined, "/work/") {
			t.Fatalf("accepted path %q escapes the project root (joins to %q)", p, joined)
		}
	})
}

func FuzzValidateProjectRequest(f *testing.F) {
	f.Add("main.mjs", "console.log(1)", "node main.mjs", "out.txt")
	f.Add("../x", "boom", "true", "..")
	f.Add("a.txt", "\xff", "s\x00tep", "/abs")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, filePath, content, step, artifact string) {
		req := ProjectRequest{
			Files:     []File{{Path: filePath, Content: content}},
			Steps:     []string{step},
			Artifacts: []string{artifact},
		}
		if err := ValidateProjectRequest(req); err != nil {
			return
		}
		// Accepted requests must satisfy every bound providers rely on downstream.
		if len(content) > MaxProjectBytes || !utf8.ValidString(content) {
			t.Fatalf("accepted over-budget or non-UTF-8 content (%d bytes)", len(content))
		}
		if len(step) > MaxProjectStepBytes || !utf8.ValidString(step) || strings.ContainsRune(step, 0) {
			t.Fatalf("accepted unsafe step %q", step)
		}
		for _, p := range []string{filePath, artifact} {
			if dest := pathpkg.Join("/home/user/project", p); !strings.HasPrefix(dest, "/home/user/project/") {
				t.Fatalf("accepted path %q that stages outside the project dir (%q)", p, dest)
			}
		}
	})
}

func FuzzRouteAllowed(f *testing.F) {
	grant := &HostAPIGrant{
		BaseURL: "https://host.internal",
		Allow: []HostRoute{
			{Method: "GET", Path: "/v1/lights"},
			{Method: "PUT", Path: "/v1/lights/*/on"},
			{Method: "POST", Path: "/a/*/b/*"},
		},
	}
	for _, seed := range [][2]string{
		{"GET", "/v1/lights"}, {"PUT", "/v1/lights/abc/on"}, {"PUT", "/v1/lights/../on"},
		{"GET", "/v1/lights%2f"}, {"PUT", "/v1/lights/%2e%2e/on"}, {"GET", "/v1/lights?x=1"},
		{"POST", "/a//b/c"}, {"get", "/v1/lights"}, {"DELETE", "/v1/lights"},
		{"GET", "\\v1\\lights"}, {"PUT", "/v1/lights/\x00/on"}, {"GET", ""},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, method, reqPath string) {
		if !grant.routeAllowed(method, reqPath) {
			return
		}
		// The approve==wire invariant: an allowed path must be byte-for-byte what
		// the HTTP layer will send — decoded, canonical, structural-character-free.
		if decoded, err := url.PathUnescape(reqPath); err != nil || decoded != reqPath {
			t.Fatalf("allowed percent-encoded/undecodable path %q", reqPath)
		}
		if !strings.HasPrefix(reqPath, "/") || pathpkg.Clean(reqPath) != reqPath ||
			strings.ContainsAny(reqPath, "?#\\") || strings.IndexFunc(reqPath, unicode.IsControl) >= 0 {
			t.Fatalf("allowed non-canonical path %q", reqPath)
		}
		if (&url.URL{Path: reqPath}).EscapedPath() != reqPath {
			t.Fatalf("allowed path whose wire encoding differs: %q", reqPath)
		}
		for _, seg := range strings.Split(reqPath, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("allowed traversal path %q", reqPath)
			}
		}
		switch strings.ToUpper(method) {
		case "GET", "PUT", "POST":
		default:
			t.Fatalf("allowed method %q that no route declares", method)
		}
	})
}

func FuzzValidateRoutePattern(f *testing.F) {
	for _, seed := range []string{
		"/v1/lights", "/v1/lights/*/on", "/", "/*", "/a/*b", "/a/../b", "/a//b",
		"a/b", "/a?x", "/a#f", "/a\\b", "/%2e%2e", "/a/\x01", "", "/a/*/",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		if err := validateRoutePattern(pattern); err != nil {
			return
		}
		// A valid pattern must admit its own literal instantiation ("*" → "x")
		// through routeAllowed — otherwise a profile could load routes that can
		// never match and silently deny what it declared.
		segs := strings.Split(pattern, "/")
		lit := make([]string, len(segs))
		for i, s := range segs {
			if s == "*" {
				lit[i] = "x"
			} else {
				lit[i] = s
			}
		}
		literal := strings.Join(lit, "/")
		g := &HostAPIGrant{BaseURL: "https://h.internal", Allow: []HostRoute{{Method: "GET", Path: pattern}}}
		if !g.routeAllowed("GET", literal) {
			t.Fatalf("valid pattern %q does not admit its own literal %q", pattern, literal)
		}
	})
}

func FuzzHostAPIGrantValidate(f *testing.F) {
	f.Add("https://host.internal", "lights:write", "GET", "/v1/lights", "host", "")
	f.Add("http://10.0.0.1", "a b", "TRACE", "/../x", "", "sdk()")
	f.Add("https://u:p@h/", "*", "get", "/", "g", "\xff")
	f.Add("http://localhost:9", "code:run", "PUT", "/a/*", "host", "")
	f.Fuzz(func(t *testing.T, baseURL, scope, method, routePath, global, preamble string) {
		g := &HostAPIGrant{
			BaseURL:  baseURL,
			Scopes:   []string{scope},
			Allow:    []HostRoute{{Method: method, Path: routePath}},
			Global:   global,
			Preamble: preamble,
		}
		if err := g.Validate(); err != nil {
			return
		}
		// Accepted grants must be exactly the shape every provider assumes.
		u, err := url.Parse(g.BaseURL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			t.Fatalf("accepted unparseable BaseURL %q", baseURL)
		}
		if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("accepted non-origin BaseURL %q", baseURL)
		}
		if scope == "*" || scope == "code:run" || strings.IndexFunc(scope, unicode.IsSpace) >= 0 || scope == "" {
			t.Fatalf("accepted forbidden scope %q", scope)
		}
		// The injected JS client must always be fully instantiated.
		out := withHostSDK("1", g)
		if strings.Contains(out, "__ALLOW_JSON__") || strings.Contains(out, "__HOST_JSON__") {
			t.Fatalf("accepted grant left template placeholders in the injected client")
		}
	})
}

func FuzzReadConnectStream(f *testing.F) {
	f.Add(frame(0, []byte(`{"event":{"data":{"stdout":"aGk="}}}`)))
	f.Add(append(frame(0, []byte(`{"a":1}`)), frame(0x2, []byte(`{}`))...))
	f.Add(frame(0x2, []byte(`{"error":{"code":"internal","message":"x"}}`)))
	f.Add([]byte{0, 0xff, 0xff, 0xff, 0xff}) // 4 GiB declared frame
	f.Add([]byte{0, 0, 0, 0, 5, 'a'})        // truncated payload
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var delivered int64
		_ = readConnectStream(bytes.NewReader(data), func(msg []byte) error {
			if len(msg) > maxConnectFrameBytes {
				t.Fatalf("delivered a %d-byte frame past the per-frame cap", len(msg))
			}
			delivered += int64(len(msg))
			return nil
		})
		// Whatever the framing claimed, the reader must never hand more total
		// bytes to the callback than the whole-stream transfer budget.
		if delivered > maxStreamTransferBytes {
			t.Fatalf("delivered %d bytes past the stream transfer budget", delivered)
		}
	})
}

func FuzzParseRunnerOutput(f *testing.F) {
	f.Add(`build output` + runnerSentinel + `{"steps":[{"command":"node x","exitCode":0,"durationMs":5}]}`)
	f.Add(runnerSentinel + `{"artifacts":[{"path":"o.txt","content":"aGk="}],"artifactsTruncated":true}`)
	f.Add(runnerSentinel + `{"error":"illegal file path"}`)
	f.Add(runnerSentinel + `not json`)
	f.Add(`no sentinel at all`)
	f.Add(runnerSentinel + `{}` + runnerSentinel + `{"steps":[]}`) // hostile early sentinel
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		report, found, err := parseRunnerOutput(out)
		if found != strings.Contains(out, runnerSentinel) {
			t.Fatalf("found=%v disagrees with sentinel presence in %q", found, out)
		}
		if !found && err != nil {
			t.Fatalf("no sentinel but parse error %v", err)
		}
		if err != nil && (len(report.Steps) != 0 || len(report.Artifacts) != 0 || report.Err != "" || report.ArtifactsTruncated) {
			t.Fatalf("parse error must return a zero report, got %+v", report)
		}
	})
}

func FuzzBuild(f *testing.F) {
	f.Add("docker", "256", "1", "128", "160", "1", "runsc", "img@sha256:x")
	f.Add("e2b", "1024", "2", "", "2048", "", "", "")
	f.Add("wasm", "64", "", "", "", "", "", "")
	f.Add("", "", "", "", "", "", "", "")
	f.Add("DOCKER ", "-1", "0.5", "1e9", "NaN", "yes", "", "-rm")
	f.Add("systemd", "9999999999999999999999", "inf", "0x10", " 1 ", "true", "unconfined", "")
	f.Fuzz(func(t *testing.T, provider, mem, cpus, pids, disk, pinned, runtime, image string) {
		env := map[string]string{
			"SANDBOX_PROVIDER":              provider,
			"SANDBOX_MEMORY_MB":             mem,
			"SANDBOX_CPUS":                  cpus,
			"SANDBOX_PIDS":                  pids,
			"SANDBOX_DISK_MB":               disk,
			"SANDBOX_REQUIRE_PINNED_IMAGES": pinned,
			"SANDBOX_DOCKER_RUNTIME":        runtime,
			"SANDBOX_DOCKER_IMAGE":          image,
		}
		p, err := Build(func(k string) string { return env[k] })
		if err != nil {
			return
		}
		if p.Sandbox == nil {
			t.Fatal("Build returned a nil sandbox without an error")
		}
		// Fail-safe selection: only the four known names may construct anything,
		// and the empty name must always be the inert provider.
		switch strings.ToLower(strings.TrimSpace(provider)) {
		case "docker", "e2b", "wasm":
		case "":
			if p.Sandbox.Name() != "disabled" {
				t.Fatalf("empty provider built %q, want disabled", p.Sandbox.Name())
			}
		default:
			t.Fatalf("unrecognized provider %q built %q without error", provider, p.Sandbox.Name())
		}
		// A successful Build implies the envelope round-tripped: no accepted
		// dimension may be negative.
		if p.Resources.MemoryMB < 0 || p.Resources.CPUs < 0 || p.Resources.PidsLimit < 0 || p.Resources.DiskMB < 0 {
			t.Fatalf("accepted negative resource envelope %+v", p.Resources)
		}
	})
}
