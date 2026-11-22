// Package python holds no Go code but this test: it serves the real RPC handler
// and runs the Python client's suite against it, so the client is proven against
// the daemon it talks to rather than against a recording of one. It also hands the
// suite a fixture of run-record digests the Go record package computed over JSON
// the Go protobuf encoder wrote, so the two digest implementations are compared on
// the daemon's own encoding of awkward values.
package python

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/clientcases"
	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestPython serves every daemon of internal/clientsuite's table (honest and hostile:
// its Daemons list says what each one tests) and runs the Python suite against them,
// with what only this suite needs beside them: the Go side's protocol number and record
// version, a fixture of digests the Go record package computed, and a plimsoll-attest
// binary.
//
// The suite fails rather than skips when it is run here, so a green test means
// every case ran. It needs python3 >= 3.10 and nothing else.
//
// A working copy may keep test modules of its own beside the published ones, which need
// none of these daemons and run under a runner of its own: PLIMSOLL_PY_ELSEWHERE names
// them (unittest module names, space separated), and this test then runs every other
// module and logs the ones it left out (unittestArgs). Unset, as in the published tree,
// it runs every module discover finds.
func TestPython(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		clientSkipOrFail(t, "python3 is not installed")
	}
	if out, err := exec.Command(python, "-c", "import sys; sys.exit(sys.version_info < (3, 10))").CombinedOutput(); err != nil {
		clientSkipOrFail(t, "the client needs Python 3.10 or later: %v %s", err, out)
	}

	fixture := filepath.Join(t.TempDir(), "digests.json")
	writeFixture(t, fixture)
	// A Python test verifies a signed run bundle with plimsoll-attest;
	// built here, so it runs rather than skips on a machine with none on PATH.
	attest := filepath.Join(t.TempDir(), "plimsoll-attest")
	if out, err := exec.Command("go", "build", "-o", attest, "github.com/plimsollmark/plimsoll/cmd/plimsoll-attest").CombinedOutput(); err != nil {
		t.Fatalf("building plimsoll-attest: %v\n%s", err, out)
	}
	// The suite writes its verdict on each shared case here, and the judge reads them after
	// it (internal/clientcases): a case the suite skipped, or answered otherwise than its
	// file states, fails this test even when every Python assertion passed.
	verdicts := filepath.Join(t.TempDir(), "verdicts.jsonl")
	env := append(os.Environ(), clientsuite.Env(t)...)
	env = append(env,
		"PLIMSOLL_GO_PROTOCOL="+strconv.FormatUint(uint64(protocol.Number), 10),
		"PLIMSOLL_GO_RECORD_VERSION="+strconv.Itoa(record.Version),
		"PLIMSOLL_DIGEST_FIXTURE="+fixture,
		"PLIMSOLL_ATTEST="+attest,
		"PLIMSOLL_INTEGRATION_REQUIRED=1",
		"PYTHONPATH=src",
		"PYTHONDONTWRITEBYTECODE=1",
		// Every temporary directory the suite makes goes under one that this test removes: the suite's tests
		// call tempfile.mkdtemp in many places and do not all clean up, and one run left thousands of
		// directories in the system's temporary directory.
		"TMPDIR="+t.TempDir(),
		"PLIMSOLL_CASE_VERDICTS="+verdicts,
	)
	leaveOut := strings.Fields(os.Getenv("PLIMSOLL_PY_ELSEWHERE"))
	args, err := unittestArgs("tests", leaveOut)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaveOut) > 0 {
		t.Logf("left out, for a runner of their own (PLIMSOLL_PY_ELSEWHERE): %s", strings.Join(leaveOut, " "))
	}
	cmd := exec.Command(python, append([]string{"-B", "-m", "unittest"}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	judgeVerdicts(t, "python", verdicts)
	if err != nil {
		t.Fatalf("python3 -m unittest: %v", err)
	}
	// unittest -v marks a skip "... skipped 'reason'" and counts them "(skipped=N)"; a
	// test whose name contains the word must not read as one.
	if pythonSkip.Match(out) {
		t.Fatal("the Python suite skipped a case; under this test every case must run")
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

// unittestArgs returns python -m unittest's arguments for the suite in dir, a package in
// the working directory: discover's, or, when leaveOut names modules a runner of their own
// runs, every other test module of dir by name (dir.<module>), in discover's order.
// Discover finds the files directly in dir named test*.py with a valid module name, and the
// test modules of any subpackage, which a list of names would miss, so a subpackage is
// refused; so is a name in leaveOut that is not one of dir's test modules (a stale list),
// and a leaveOut that leaves nothing to run.
func unittestArgs(dir string, leaveOut []string) ([]string, error) {
	if len(leaveOut) == 0 {
		return []string{"discover", "-s", dir, "-t", ".", "-v"}, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	modules := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			if _, err := os.Stat(filepath.Join(dir, e.Name(), "__init__.py")); err == nil {
				return nil, fmt.Errorf("%s/%s is a package, whose tests discover finds and a list of modules does not: PLIMSOLL_PY_ELSEWHERE cannot be used beside it", dir, e.Name())
			}
			continue
		}
		if testModule.MatchString(e.Name()) {
			modules[dir+"."+strings.TrimSuffix(e.Name(), ".py")] = true
		}
	}
	for _, m := range leaveOut {
		if !modules[m] {
			return nil, fmt.Errorf("PLIMSOLL_PY_ELSEWHERE names %s, which is not a test module of %s", m, dir)
		}
		delete(modules, m)
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("PLIMSOLL_PY_ELSEWHERE leaves out every test module of %s", dir)
	}
	args := []string{"-v"}
	for m := range modules {
		args = append(args, m)
	}
	slices.Sort(args[1:])
	return args, nil
}

// testModule is discover's default pattern, test*.py, for a file whose name is a module's.
var testModule = regexp.MustCompile(`^test\w*\.py$`)

// TestUnittestArgs: with nothing left out the suite is discovered; with modules left out,
// every other test module runs by name, and a name that is no module, a list leaving
// nothing, or a subpackage discover would search is refused.
func TestUnittestArgs(t *testing.T) {
	t.Chdir(t.TempDir())
	const dir = "tests"
	for _, f := range []string{"__init__.py", "_env.py", "test_b.py", "test_a.py", "test_c.py", "mutate_x.py", "test-y.py", "data/x.json", "testdata/make.py"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := unittestArgs(dir, nil); !slices.Equal(got, []string{"discover", "-s", dir, "-t", ".", "-v"}) {
		t.Errorf("nothing left out: %q", got)
	}
	if got, err := unittestArgs(dir, []string{dir + ".test_b"}); err != nil || !slices.Equal(got, []string{"-v", dir + ".test_a", dir + ".test_c"}) {
		t.Errorf("test_b left out: %q, %v", got, err)
	}
	if _, err := unittestArgs(dir, []string{dir + ".test_gone"}); err == nil {
		t.Error("a name that is no module is accepted")
	}
	if _, err := unittestArgs(dir, []string{dir + ".mutate_x"}); err == nil {
		t.Error("a module that is not a test module is accepted")
	}
	if _, err := unittestArgs(dir, []string{dir + ".test_a", dir + ".test_b", dir + ".test_c"}); err == nil {
		t.Error("leaving out every module is accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "testdata", "__init__.py"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := unittestArgs(dir, []string{dir + ".test_b"}); err == nil {
		t.Error("a subpackage, whose tests a list of modules would miss, is accepted")
	}
}

func clientSkipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("PLIMSOLL_REQUIRE_CLIENTS") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

var pythonSkip = regexp.MustCompile(`(?m)\.\.\. skipped|skipped=[0-9]+`)

// --- the digest fixture -----------------------------------------------------------

type fixtureCase struct {
	Name    string          `json:"name"`
	Message json.RawMessage `json:"message"`
	Digest  string          `json:"digest"`
}

type digestFixture struct {
	Requests     []fixtureCase `json:"requests"`
	Results      []fixtureCase `json:"results"`
	Records      []fixtureCase `json:"records"`
	Fingerprints []struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
	} `json:"fingerprints"`
}

func marshal(t *testing.T, m proto.Message) json.RawMessage {
	t.Helper()
	b, err := protojson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeFixture writes run-record digests the Go record package computes, each with
// its message as Go's protobuf JSON encoder writes it (the encoder Connect uses).
func writeFixture(t *testing.T, path string) {
	t.Helper()
	identities := []string{"oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64), "oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)}
	js := &plimsollv1.JavaScriptRun{Code: "console.log('héllo ☃ 𝄞\\n')", GrantProfile: "profile-1"}
	project := &plimsollv1.ProjectRun{
		Files: []*plimsollv1.ProjectFile{{Path: "main.py", Content: "print('\\u00e9')\n"}, {Path: "empty.txt"}, {Path: "nul.bin", Content: "a\x00b"}},
		Steps: []string{"python3 main.py", ""}, Artifacts: []string{"out.txt"},
	}
	module := &plimsollv1.ModuleRun{Model: "Lorenz", EndTime: 1e-7, Step: 5e-324, Rows: []*plimsollv1.ModuleRow{
		{Values: []float64{math.Copysign(0, -1), math.MaxFloat64, 1e21, 123456789012345678901, -1.5e-300}}, {Values: []float64{}},
	}}
	var f digestFixture
	for _, c := range []struct {
		name string
		msg  *plimsollv1.RunRequest
	}{
		{"protocol 1 javascript", &plimsollv1.RunRequest{Protocol: 1, MinimumIsolation: "vm", TimeoutMs: math.MaxInt32, Payload: &plimsollv1.RunRequest_Javascript{Javascript: js}}},
		{"protocol 2 javascript, exact rule", &plimsollv1.RunRequest{Protocol: 2, TimeoutMs: -5, TraceId: "t",
			SoftwareRule: &plimsollv1.SoftwareRule{Mode: "exact", Identities: identities[:1]}, Payload: &plimsollv1.RunRequest_Javascript{Javascript: js}}},
		{"protocol 2 project, approved rule", &plimsollv1.RunRequest{Protocol: 2, MinimumIsolation: "kernel",
			SoftwareRule: &plimsollv1.SoftwareRule{Mode: "approved", Identities: identities}, Payload: &plimsollv1.RunRequest_Project{Project: project}}},
		{"protocol 2 empty project", &plimsollv1.RunRequest{Protocol: 2, Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{}}}},
		{"protocol 2 module", &plimsollv1.RunRequest{Protocol: 2, Payload: &plimsollv1.RunRequest_Module{Module: module}}},
		{"protocol 2 no payload", &plimsollv1.RunRequest{Protocol: 2}},
	} {
		f.Requests = append(f.Requests, fixtureCase{c.name, marshal(t, c.msg), record.RunRequestDigest(c.msg)})
	}
	for _, c := range []struct {
		name string
		msg  *plimsollv1.RunResponse
	}{
		{"javascript", &plimsollv1.RunResponse{Sandbox: "docker", DurationMs: 9, Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{
			Stdout: []byte{0xff, 0x00, 'a'}, Stderr: []byte("é"), ExitCode: -1, TimedOut: true, StdoutTruncated: true, StderrTruncated: true,
			Advice: []*plimsollv1.AdviceFinding{{Pattern: "fan_out", ExtraCalls: 3}},
		}}}},
		{"project", &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{
			Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_SETUP_FAILED, OutcomeDetail: "détail", ArtifactsTruncated: true,
			Steps:     []*plimsollv1.StepResult{{Command: "a", Stdout: []byte{0}, ExitCode: math.MinInt32, DurationMs: 1 << 40, StderrTruncated: true}, {}},
			Artifacts: []*plimsollv1.Artifact{{Path: "out.txt", Content: []byte{0xfe}}, {Path: "empty"}},
		}}}},
		{"project with an outcome this client does not name", &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Project{Project: &plimsollv1.ProjectResult{Outcome: 9}}}},
		{"module", &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Module{Module: &plimsollv1.ModuleResult{
			Outcome: plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED, Width: 4, Stdout: []byte("rows=2\n"), Stderr: []byte{0x80},
			Runs: []*plimsollv1.ModuleRowResult{
				{Status: 1, Outputs: []float64{math.Copysign(0, -1), math.Inf(1), math.Inf(-1), clientsuite.CanonicalNaN}},
				{Status: -3},
				{Status: 1, Outputs: []float64{math.MaxFloat64, math.SmallestNonzeroFloat64, 1e21, 123456789012345678901}},
			},
		}}}},
		{"no result", &plimsollv1.RunResponse{Sandbox: "x"}},
	} {
		f.Results = append(f.Results, fixtureCase{c.name, marshal(t, c.msg), record.ResultDigest(c.msg)})
	}
	for _, c := range []struct {
		name string
		rec  sandbox.RunRecord
	}{
		{"version 2 session call", sandbox.RunRecord{Version: 2, RequestSHA256: "r", ResultSHA256: "s", Provider: "openshell", Isolation: "container",
			Environment: "e", Policy: "p", SoftwareIdentity: identities[0], SoftwareRuleID: "exact:" + identities[0],
			Started: time.UnixMilli(-1), Ended: time.UnixMilli(math.MaxInt64), Session: "f", Sequence: math.MaxUint64, PreviousSHA256: "prev"}},
		{"version 1 single run", sandbox.RunRecord{Version: 1, Provider: "wasm", Isolation: "process", Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000812)}},
	} {
		c.rec.SHA256 = "not covered by its own digest"
		f.Records = append(f.Records, fixtureCase{c.name, marshal(t, record.ToWire(c.rec)), record.Digest(c.rec)})
	}
	for _, id := range []string{"", "00112233445566778899aabbccddeeff", "é"} {
		f.Fingerprints = append(f.Fingerprints, struct {
			ID     string `json:"id"`
			Digest string `json:"digest"`
		}{id, record.SessionFingerprint(id)})
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The package ships its own copy of the license, because a published package carries
// nothing from outside its directory; it must stay the repository's license.
func TestLicenseMatchesRepository(t *testing.T) { clientsuite.LicenseMatchesRepository(t) }

// pythonDeclined names the daemons of internal/clientsuite's table this suite does not
// use, and why; TestPythonUsesOrDeclinesEveryDaemon fails a daemon the suite neither
// reads nor names here.
var pythonDeclined = map[string]string{
	"PLIMSOLL_ECHO_URL": "the client's own suite runs no executeCode tool; the framework suites, which run code tools, use tool-echo",
}

func TestPythonUsesOrDeclinesEveryDaemon(t *testing.T) {
	clientsuite.CheckDeclined(t, pythonDeclined, filepath.Join("tests", "*.py"))
}
