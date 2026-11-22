package sandbox_test

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The roads by which a program comes to load a file a session wrote, planted in an E2B
// session's machine, and plimsoll's control programs shown not to take them. Shared by
// the docker-backed stand-in (free) and the live suite (paid). An operator's template
// would carry the machine's half of a road; here the test plants it as root, after the
// open, and the session's code plants its half, as the session's code would:
//
//   - A relative library search folder: the loader's search file names "lib" (musl's
//     /etc/ld-musl-x86_64.path, or glibc's ld.so.conf with its cache rebuilt), so a
//     program started in the work folder looks for its libraries in /work/lib, where
//     the session put a libstdc++.so.6 of its own. Closed by starting every control
//     program in /.
//   - OpenSSL's settings file, in every place node may read it from, names a module in
//     the work folder, which OpenSSL loads when node starts. Closed by the empty OpenSSL
//     settings file every control program gets (sessionkit.ControlOpenSSL).
//
// The session's library is e2bRoadC: its start-up code creates
// /tmp/plimsoll-road-uid-<its uid> and does nothing else. Each road is first shown live
// with a guest process (the positive check: a road nothing takes proves nothing), then
// every control program is run (the stager, the step's chain, the artifact reader, the
// launcher, the relay, the identity check, the sweep after each call and after a
// resume), and no marker but the guest's may exist.

// e2bRoadC is the session's library: no C library, raw x86-64 system calls, so one
// build loads on a glibc and on a musl machine. Loaded as an OpenSSL module, it is a
// provider with no algorithms, so node goes on starting after its start-up code ran.
const e2bRoadC = `struct dispatch { int id; void (*fn)(void); };
int OSSL_provider_init(const void *core, const void *in, const struct dispatch **out, void **ctx) {
	static const struct dispatch none[] = {{0, 0}};
	*out = none;
	*ctx = 0;
	return 1;
}
static long sc(long n, long a, long b, long c) {
	long r;
	__asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
	return r;
}
__attribute__((constructor)) static void road(void) {
	char p[] = "/tmp/plimsoll-road-uid-0000000000";
	long uid = sc(102, 0, 0, 0);
	for (int i = sizeof p - 2; i >= (int)sizeof p - 11; i--) { p[i] = '0' + uid % 10; uid /= 10; }
	long fd = sc(2, (long)p, 0101, 0644);
	if (fd >= 0) sc(3, fd, 0, 0);
}
`

// e2bRoadPlant is the machine's half of the roads, run as root in /.
const e2bRoadPlant = `set -e
if [ -e /lib/ld-musl-x86_64.so.1 ]; then
  f=/etc/ld-musl-x86_64.path
  if [ -f "$f" ]; then old=$(cat "$f"); else old=$(printf '/lib\n/usr/local/lib\n/usr/lib'); fi
  printf 'lib\n%s\n' "$old" > "$f"
  echo musl
else
  echo lib > /etc/ld.so.conf.d/00-plimsoll-road.conf
  echo glibc
fi
for d in /etc/ssl /usr/lib/ssl /usr/local/ssl; do
  mkdir -p "$d"
  cat > "$d/openssl.cnf" <<'EOF'
openssl_conf = plimsoll_road
nodejs_conf = plimsoll_road
[plimsoll_road]
providers = plimsoll_road_providers
[plimsoll_road_providers]
default = plimsoll_road_default
plimsoll_road = plimsoll_road_module
[plimsoll_road_default]
activate = 1
[plimsoll_road_module]
module = /work/road.so
activate = 1
EOF
done
`

// e2bRoadLive is the positive check, a step of the session's own: node started in the
// work folder takes the library road (it fails to start, or runs the library), and node
// started in / runs the OpenSSL road's module as the guest.
const e2bRoadLive = `cd /work && node -e 1 >/dev/null 2>&1; echo "work=$?"
cd / && node -e 1 >/dev/null 2>&1; echo "root=$?"
`

var e2bRoadMarker = regexp.MustCompile(`plimsoll-road-uid-([0-9]{10})`)

// buildE2BRoadLib compiles e2bRoadC with the host's C compiler.
func buildE2BRoadLib(t *testing.T) []byte {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Fatalf("the road library is x86-64 system calls; this host is %s", runtime.GOARCH)
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("the road check needs a C compiler on the host (cc)")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "road.c")
	if err := os.WriteFile(src, []byte(e2bRoadC), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "road.so")
	if b, err := exec.Command(cc, "-shared", "-fPIC", "-nostdlib", "-fno-stack-protector", "-O2", "-o", out, src).CombinedOutput(); err != nil {
		t.Fatalf("build the road library: %v\n%s", err, b)
	}
	lib, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return lib
}

// checkE2BRoads plants both roads in s's machine and fails if any control program of
// plimsoll's takes one. s must be fresh (no call made yet).
func checkE2BRoads(t *testing.T, s sandbox.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	root := func(script string) string {
		t.Helper()
		out, stderr, code, err := sandbox.E2BSessionRoot(ctx, s, "/bin/sh", "-c", script)
		if err != nil || code != 0 {
			t.Fatalf("as root: %q: exit %d, %v: %s", script, code, err, stderr)
		}
		return out
	}
	guest := sandbox.E2BSessionGuestUID(s)
	lib := buildE2BRoadLib(t)
	libc := strings.TrimSpace(root(e2bRoadPlant))
	project := func(req sandbox.ProjectRequest) sandbox.ProjectResult {
		t.Helper()
		req.Timeout = 30 * time.Second
		res, err := s.RunProject(ctx, req)
		if err != nil || res.Outcome != sandbox.ProjectOutcomeCompleted {
			t.Fatalf("project %v: %s %q, %v", req.Steps, res.Outcome, res.Detail, err)
		}
		return res
	}
	// The session's half: its library at both places the roads name (a call's files are
	// text, so it travels as base64).
	project(sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "road.b64", Content: base64.StdEncoding.EncodeToString(lib)}},
		Steps: []string{"base64 -d road.b64 > road.so && mkdir -p lib && cp road.so lib/libstdc++.so.6"},
	})
	if libc == "glibc" {
		// glibc's loader reads its search folders from the cache ldconfig builds, which
		// holds a relative folder's libraries as ldconfig found them from where it ran.
		root("cd /work && ldconfig 2>/dev/null; true")
	}
	live := project(sandbox.ProjectRequest{Steps: []string{e2bRoadLive}})
	got := live.Steps[0].Stdout
	t.Logf("%s machine; the session's node, as the guest: %s", libc, strings.ReplaceAll(strings.TrimSpace(got), "\n", ", "))
	if !strings.Contains(got, "root=0") || strings.Contains(got, "work=0") {
		t.Fatalf("the library road is not live here (node started in the work folder ran, or node started in / did not): %q; nothing was measured", got)
	}
	markers := func() map[int]bool {
		uids := map[int]bool{}
		for _, m := range e2bRoadMarker.FindAllStringSubmatch(root("ls -a /tmp"), -1) {
			n, _ := strconv.Atoi(m[1])
			uids[n] = true
		}
		return uids
	}
	if !markers()[guest] {
		t.Fatal("the OpenSSL road is not live here: the guest's node did not run the module its settings file names; nothing was measured")
	}

	// Every control program, with both roads in place.
	if _, err := s.Suspend(ctx); err != nil {
		t.Fatal(err)
	}
	res := project(sandbox.ProjectRequest{Files: []sandbox.File{{Path: "a.txt", Content: "a"}}, Steps: []string{"cp a.txt out.txt"}, Artifacts: []string{"out.txt"}})
	if len(res.Artifacts) != 1 || string(res.Artifacts[0].Content) != "a" {
		t.Fatalf("the artifact reader returned %+v (%s)", res.Artifacts, res.Detail)
	}
	cell, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguagePython, Code: "print(6 * 7)", Timeout: 30 * time.Second})
	if err != nil || strings.TrimSpace(cell.Stdout) != "42" {
		t.Fatalf("a python cell (the launcher, the relay, the identity check): %+v, %v", cell, err)
	}
	if cell, err = s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguagePython, Code: "print(1)", Timeout: 30 * time.Second}); err != nil || cell.InterpreterStarted {
		t.Fatalf("the second cell: %+v, %v; want the kept interpreter", cell, err)
	}
	for uid := range markers() {
		if uid != guest {
			t.Errorf("a program running as uid %d ran the session's library: a control program of plimsoll's took a road", uid)
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("the session ended: %v", err)
	}
}
