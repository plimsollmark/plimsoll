// Package typescript holds no Go code but this test: it serves the real RPC
// handler and runs the TypeScript client's suites against it, so the client is
// proven against the daemon it talks to rather than against a recording of one.
package typescript

import (
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/clientcases"
	"github.com/plimsollmark/plimsoll/internal/clientsuite"
)

// TestTypeScript serves every daemon of internal/clientsuite's table (honest and hostile:
// its Daemons list says what each one tests) and runs two suites against them: the
// client's own, which needs nothing but node, and the add-ons', which need the client's dev
// dependencies (npm install in clients/typescript). A suite whose dependencies are absent
// is skipped unless PLIMSOLL_REQUIRE_CLIENTS=1, which makes missing prerequisites fail.
// Files run one at a time because the end-sessions endpoint reaches every session.
func TestTypeScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		clientSkipOrFail(t, "node is not installed")
	}
	if out, err := exec.Command(node, "-e", "process.exit(process.features.typescript ? 0 : 1)").CombinedOutput(); err != nil {
		clientSkipOrFail(t, "this node cannot run TypeScript directly (needs >= 22.18): %v %s", err, out)
	}

	daemons := clientsuite.Env(t)
	env := append(os.Environ(), daemons...)

	suites := []struct{ name, dir, glob, needs string }{
		{"client", ".", "test/*.test.ts", ""},
		{"addons", ".", "test/addons/*.test.ts", "node_modules/@mastra/core"},
	}
	for _, s := range suites {
		t.Run(s.name, func(t *testing.T) {
			if s.needs != "" {
				if _, err := os.Stat(filepath.Join(s.dir, s.needs)); err != nil {
					clientSkipOrFail(t, "run npm install in %s first", s.dir)
				}
			}
			files, err := filepath.Glob(filepath.Join(s.dir, s.glob))
			if err != nil || len(files) == 0 {
				t.Fatalf("no tests match %s: %v", s.glob, err)
			}
			for i := range files {
				files[i], _ = filepath.Rel(s.dir, files[i])
			}
			cmd := exec.Command(node, append([]string{"--test", "--test-concurrency=1", "--test-reporter=spec"}, files...)...)
			cmd.Dir = s.dir
			cmd.Env = env
			// The client's own suite writes its verdict on each shared case here, and the
			// judge reads them after it (internal/clientcases): a case the suite skipped, or
			// answered otherwise than its file states, fails this test even when every
			// assertion in the suite passed.
			verdicts := filepath.Join(t.TempDir(), "verdicts.jsonl")
			if s.name == "client" {
				cmd.Env = append(append([]string{}, env...), "PLIMSOLL_CASE_VERDICTS="+verdicts)
			}
			out, err := cmd.CombinedOutput()
			t.Logf("%s", out)
			if s.name == "client" {
				judgeVerdicts(t, "typescript", verdicts)
			}
			if err != nil {
				t.Fatalf("node --test: %v", err)
			}
		})
	}
}

// judgeVerdicts judges the verdict file a client's suite wrote against every shared case;
// a file the suite never wrote is every case missing.
func judgeVerdicts(t *testing.T, client, path string) {
	t.Helper()
	a, err := clientcases.Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	vs, err := clientcases.ReadVerdicts(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	clientcases.Judge(t, a, client, vs)
}

func clientSkipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("PLIMSOLL_REQUIRE_CLIENTS") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// The package ships its own copy of the license, because a published package carries
// nothing from outside its directory; it must stay the repository's license.
func TestLicenseMatchesRepository(t *testing.T) { clientsuite.LicenseMatchesRepository(t) }

// typescriptDeclined names the daemons of internal/clientsuite's table these suites do not
// use, and why; TestTypeScriptUsesOrDeclinesEveryDaemon fails a daemon they neither read
// nor name here.
var typescriptDeclined = map[string]string{
	"PLIMSOLL_AUTH_URL":          "the bearer token is checked against a stub fetch (test/client.test.ts), not a daemon",
	"PLIMSOLL_AUTH_TOKEN":        "the bearer token is checked against a stub fetch (test/client.test.ts), not a daemon",
	"PLIMSOLL_TAMPER_URL":        "answers are tampered with in the process, by a fetch wrapped around the wasm daemon (tampering in test/client.test.ts)",
	"PLIMSOLL_SCRIPTED_URL":      "this client sends no module runs, and the awkward values it digests are vectors in record/testdata/golden.json",
	"PLIMSOLL_SCRIPTED_SOFTWARE": "this client sends no module runs, and the awkward values it digests are vectors in record/testdata/golden.json",
	"PLIMSOLL_LOSSY_URL":         "not covered here yet: a session call whose answer is lost after it ran is tested in the Python suite only",
	"PLIMSOLL_ONE_CALL_URL":      "a Run cell's pool member is counted on the pooled and drained daemons (test/sandboxes.test.ts) instead",
	"PLIMSOLL_NO_POOL_URL":       "not covered here yet: a Run cell that prefers a member on a daemon with no pool is tested in the Python suite only",
	"PLIMSOLL_CLAIM_MISS_URL":    "not covered here yet: a pool whose provider has no member to hand over is tested in the Python suite only",
	"PLIMSOLL_TLS_CA":            "the suite checks only that a certificate no trusted authority signed is refused",
}

func TestTypeScriptUsesOrDeclinesEveryDaemon(t *testing.T) {
	clientsuite.CheckDeclined(t, typescriptDeclined, filepath.Join("test", "*.ts"), filepath.Join("test", "addons", "*.ts"))
}

// Both client packages carry the version of the plimsoll release they ship in, so a
// reader can tell which daemon release a package was built and tested with: the npm
// package, its lockfile, the Python distribution and the version the Python client
// sends.
func TestClientVersionsAgree(t *testing.T) {
	var pkg, lock struct {
		Version string `json:"version"`
	}
	for _, f := range []struct {
		path string
		into any
	}{{"package.json", &pkg}, {"package-lock.json", &lock}} {
		b, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, f.into); err != nil {
			t.Fatalf("%s: %v", f.path, err)
		}
	}
	python := func(path, pattern string) string {
		b, err := os.ReadFile(filepath.Join("..", "python", path))
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`(?m)` + pattern).FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s: no version", path)
		}
		return string(m[1])
	}
	versions := map[string]string{
		"package.json":                           pkg.Version,
		"package-lock.json":                      lock.Version,
		"python/pyproject.toml":                  python("pyproject.toml", `^version = "([^"]+)"$`),
		"python/src/plimsoll_client/_version.py": python(filepath.Join("src", "plimsoll_client", "_version.py"), `^__version__ = "([^"]+)"$`),
	}
	// Every framework package (python/<name>-plimsoll: crewai-plimsoll, langchain-plimsoll and
	// the rest) moves with the release and requires the plimsoll-client of the same number.
	packages, err := filepath.Glob(filepath.Join("..", "python", "*-plimsoll", "pyproject.toml"))
	if err != nil || len(packages) == 0 {
		t.Fatalf("no framework package under python/*-plimsoll (%v)", err)
	}
	for _, p := range packages {
		name := filepath.Base(filepath.Dir(p))
		module := strings.ReplaceAll(name, "-", "_")
		versions["python/"+name+"/pyproject.toml"] = python(filepath.Join(name, "pyproject.toml"), `^version = "([^"]+)"$`)
		versions["python/"+name+"/ its plimsoll-client pin"] = python(filepath.Join(name, "pyproject.toml"), `^\s*"plimsoll-client==([^"]+)",$`)
		versions["python/"+name+"/.../__init__.py"] = python(filepath.Join(name, "src", module, "__init__.py"), `^__version__ = "([^"]+)"$`)
	}
	for _, v := range versions {
		if v != pkg.Version || v == "" {
			t.Fatalf("client versions disagree: %v", versions)
		}
	}
}

// TestPeerFloorsAreTheLockedVersions: each optional peer of the add-ons (package.json's
// peerDependencies: @mastra/core, ai, zod) declares a range whose floor is
// exactly the version package-lock.json installs, the version every suite runs it at, and
// keeps an upper bound; the lock's own copy of the ranges is the same; and the README says
// each range and "tested at exactly" that version, beside every add-on that needs it. A
// range stays, rather than an exact pin, because the peers are the whole package's: npm
// refuses to install a package whose optional peer is pinned beside an application's other
// patch of it (measured 2026-11-20, finding hunt-quality-70; the owner's A that day: "keep
// ranges, but raise each floor to the version the tests run at, and say 'tested at exactly
// X' on the page"). The Python adapters are held to their locks the same way, by exact
// pins (clients/python/frameworks_test.go, TestAdaptersPinTheVersionTheirLockInstalls).
func TestPeerFloorsAreTheLockedVersions(t *testing.T) {
	var pkg struct {
		Peers map[string]string `json:"peerDependencies"`
	}
	var lock struct {
		Packages map[string]struct {
			Version string            `json:"version"`
			Peers   map[string]string `json:"peerDependencies"`
		} `json:"packages"`
	}
	for _, f := range []struct {
		path string
		into any
	}{{"package.json", &pkg}, {"package-lock.json", &lock}} {
		b, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, f.into); err != nil {
			t.Fatalf("%s: %v", f.path, err)
		}
	}
	if len(pkg.Peers) < 3 {
		t.Fatalf("package.json declares %d peers, fewer than the three there were: is the scan reading its peerDependencies?", len(pkg.Peers))
	}
	if root := lock.Packages[""].Peers; !maps.Equal(root, pkg.Peers) {
		t.Errorf("package-lock.json's root entry declares the peers %v; package.json declares %v", root, pkg.Peers)
	}
	rangeRule := regexp.MustCompile(`^>=(\S+) <(\S+)$`)
	locked := map[string]string{}
	for name, rule := range pkg.Peers {
		locked[name] = lock.Packages["node_modules/"+name].Version
		m := rangeRule.FindStringSubmatch(rule)
		switch {
		case locked[name] == "":
			t.Errorf("package.json's peer %s is not in package-lock.json, so no suite runs it", name)
		case m == nil:
			t.Errorf("package.json's peer %s declares %q; want \">=%s <NEXT-MAJOR\", a floor and an upper bound", name, rule, locked[name])
		case m[1] != locked[name]:
			t.Errorf("package.json's peer %s declares %q, whose floor is %s; want the floor %s, the version package-lock.json installs and every suite runs it at", name, rule, m[1], locked[name])
		}
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(readme)), " ")
	said := map[string]int{}
	for _, m := range regexp.MustCompile("`([^`]+)` \\(([^,()]+), tested at exactly ([^()]+)\\)").FindAllStringSubmatch(text, -1) {
		name, rule, version := m[1], m[2], m[3]
		switch {
		case pkg.Peers[name] == "":
			t.Errorf("README.md says %q, but %s is not a peer in package.json", m[0], name)
		case rule != pkg.Peers[name] || version != locked[name]:
			t.Errorf("README.md says %q; want (%s, tested at exactly %s), package.json's range and package-lock.json's version", m[0], pkg.Peers[name], locked[name])
		}
		said[name]++
	}
	for name := range pkg.Peers {
		if said[name] == 0 {
			t.Errorf("README.md never says %s's range and the version it is tested at exactly (\"`%s` (%s, tested at exactly %s)\")", name, name, pkg.Peers[name], locked[name])
		}
	}
}
