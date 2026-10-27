package record

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// golden is record/testdata/golden.json: the vectors' inputs in the proto3 JSON form a
// client sends and receives, with the digests they must produce. The Python and
// TypeScript clients' tests read the same file.
type golden struct {
	Requests []struct {
		Name    string          `json:"name"`
		Kind    string          `json:"kind"` // "run" or "session"
		Request json.RawMessage `json:"request"`
		SHA256  string          `json:"sha256"`
	} `json:"requests"`
	Results []struct {
		Name     string          `json:"name"`
		Response json.RawMessage `json:"response"`
		SHA256   string          `json:"sha256"`
	} `json:"results"`
	Records []struct {
		Name   string          `json:"name"`
		Record json.RawMessage `json:"record"`
		SHA256 string          `json:"sha256"`
	} `json:"records"`
	SessionFingerprints []struct {
		Name      string `json:"name"`
		SessionID string `json:"sessionId"`
		SHA256    string `json:"sha256"`
	} `json:"sessionFingerprints"`
}

var loadGolden = sync.OnceValue(func() golden {
	b, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		panic(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		panic(err)
	}
	return g
})

// fixture decodes one named input of the golden file into m.
func fixture[M proto.Message](name string, m M) M {
	g := loadGolden()
	var raw json.RawMessage
	for _, r := range g.Requests {
		if r.Name == name {
			raw = r.Request
		}
	}
	for _, r := range g.Results {
		if r.Name == name {
			raw = r.Response
		}
	}
	for _, r := range g.Records {
		if r.Name == name {
			raw = r.Record
		}
	}
	if raw == nil {
		panic("no golden input named " + name)
	}
	if err := protojson.Unmarshal(raw, m); err != nil {
		panic(name + ": " + err.Error())
	}
	return m
}

func jsRequest() *plimsollv1.RunRequest {
	return fixture("javascript request", &plimsollv1.RunRequest{})
}

func projectRequest() *plimsollv1.RunRequest {
	return fixture("project request", &plimsollv1.RunRequest{})
}

func moduleRequest() *plimsollv1.RunRequest {
	return fixture("module request", &plimsollv1.RunRequest{})
}

// withApprovedRule is base with an approved rule of two identities, as the golden file's
// "with an approved rule" requests are.
func withApprovedRule(base *plimsollv1.RunRequest) *plimsollv1.RunRequest {
	out := proto.Clone(base).(*plimsollv1.RunRequest)
	out.SoftwareRule = &plimsollv1.SoftwareRule{Mode: "approved", Identities: []string{
		"oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64),
		"oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64),
	}}
	return out
}

func jsResponse() *plimsollv1.RunResponse {
	return fixture("javascript result", &plimsollv1.RunResponse{})
}

func projectResponse() *plimsollv1.RunResponse {
	return fixture("project result", &plimsollv1.RunResponse{})
}

func moduleResponse() *plimsollv1.RunResponse {
	return fixture("module result", &plimsollv1.RunResponse{})
}

func cellRequest() *plimsollv1.SessionRunRequest {
	return fixture("cell request", &plimsollv1.SessionRunRequest{})
}

func cellResponse() *plimsollv1.RunResponse {
	return fixture("cell result", &plimsollv1.RunResponse{})
}

func goldenRecord() sandbox.RunRecord {
	return FromWire(fixture("record", &plimsollv1.RunRecord{}))
}

// The golden vectors pin the encoding: a change to any of these digests is a
// change to docs/run-records.md, whose reference implementation computes all of
// them (checked against an independent Python implementation on 2026-09-28, the
// cell vectors on 2026-10-01 before this code ran), and to every verifier written
// against it.
func TestGoldenVectors(t *testing.T) {
	g := loadGolden()
	n := 0
	for _, r := range g.Requests {
		var got string
		switch r.Kind {
		case "run":
			got = RunRequestDigest(fixture(r.Name, &plimsollv1.RunRequest{}))
		case "session":
			got = SessionRunRequestDigest(fixture(r.Name, &plimsollv1.SessionRunRequest{}))
		default:
			t.Fatalf("%s: unknown kind %q", r.Name, r.Kind)
		}
		if got != r.SHA256 {
			t.Errorf("%s: got %s, want %s", r.Name, got, r.SHA256)
		}
		n++
	}
	for _, r := range g.Results {
		if got := ResultDigest(fixture(r.Name, &plimsollv1.RunResponse{})); got != r.SHA256 {
			t.Errorf("%s: got %s, want %s", r.Name, got, r.SHA256)
		}
		n++
	}
	for _, r := range g.Records {
		if got := Digest(FromWire(fixture(r.Name, &plimsollv1.RunRecord{}))); got != r.SHA256 {
			t.Errorf("%s: got %s, want %s", r.Name, got, r.SHA256)
		}
		n++
	}
	for _, f := range g.SessionFingerprints {
		if got := SessionFingerprint(f.SessionID); got != f.SHA256 {
			t.Errorf("%s: got %s, want %s", f.Name, got, f.SHA256)
		}
		n++
	}
	// 13 vectors on 2026-10-01; fewer means one was dropped from the file.
	if n < 13 {
		t.Fatalf("the golden file holds %d vectors, fewer than the 13 it had", n)
	}
	// The requests with an approved rule are the plain ones under withApprovedRule, which
	// other tests use, so the two cannot drift apart; every request states this protocol.
	for _, kind := range []string{"javascript", "project", "module"} {
		plain := fixture(kind+" request", &plimsollv1.RunRequest{})
		ruled := fixture(kind+" request with an approved rule", &plimsollv1.RunRequest{})
		if !proto.Equal(withApprovedRule(plain), ruled) || plain.GetProtocol() != 4 {
			t.Errorf("%s request with an approved rule is not the plain one under withApprovedRule, at protocol 4", kind)
		}
	}
}

func TestSoftwareAdmissionRecordIsBoundToRequestAndResponse(t *testing.T) {
	id := "oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64)
	req := &plimsollv1.RunRequest{Protocol: 4, SoftwareRule: &plimsollv1.SoftwareRule{Mode: "exact", Identities: []string{id}},
		Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
	resp := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "kernel", Environment: "docker-image:sha256:outer", SoftwareIdentity: id,
		Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{}}}
	resp.Record = Stamp(sandbox.RunRecord{RequestSHA256: RunRequestDigest(req), SoftwareRuleID: "exact:" + id}, resp)
	if _, err := Check(req, resp); err != nil {
		t.Fatal(err)
	}
	tampered := proto.Clone(resp).(*plimsollv1.RunResponse)
	tampered.SoftwareIdentity = ""
	if _, err := Check(req, tampered); !errors.Is(err, ErrMismatch) {
		t.Fatalf("changed selected image: %v", err)
	}
	tampered = proto.Clone(resp).(*plimsollv1.RunResponse)
	tampered.GetRecord().SoftwareRuleId = "approved:sha256:deadbeef"
	rec := FromWire(tampered.GetRecord())
	tampered.GetRecord().RecordSha256 = Digest(rec)
	if _, err := Check(req, tampered); !errors.Is(err, ErrMismatch) {
		t.Fatalf("changed rule with recomputed digest: %v", err)
	}
	changedReq := proto.Clone(req).(*plimsollv1.RunRequest)
	changedReq.SoftwareRule.Identities = []string{"oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)}
	if _, err := Check(changedReq, resp); !errors.Is(err, ErrMismatch) {
		t.Fatalf("changed request rule: %v", err)
	}
}

// Only version 4 is read: a record of an earlier layout is refused, its digest
// recomputed under its own domain or not.
func TestEarlierVersionsAreRefused(t *testing.T) {
	req := jsRequest()
	resp := jsResponse()
	for _, v := range []int{1, 2, 3, 5} {
		r := sandbox.RunRecord{Version: v, RequestSHA256: RunRequestDigest(req), ResultSHA256: ResultDigest(resp),
			Provider: resp.GetSandbox(), Isolation: resp.GetIsolation(), Started: time.UnixMilli(1), Ended: time.UnixMilli(2)}
		r.SHA256 = Digest(r)
		resp.Record = ToWire(r)
		if _, err := Check(req, resp); !errors.Is(err, ErrVersion) {
			t.Errorf("a version %d record: %v, want ErrVersion", v, err)
		}
	}
}

// The instance is evidence like the environment: the record must state the response's,
// in the typed form, and the result digest does not cover it.
func TestInstanceIsBoundToTheResponse(t *testing.T) {
	req := jsRequest()
	resp := jsResponse()
	resp.Instance = sandbox.PodInstance("7f3e9c2a-5b1d-4e8f-9a0c-2d6b8e4f1a37")
	if resp.Instance != "k8s-pod-uid:7f3e9c2a-5b1d-4e8f-9a0c-2d6b8e4f1a37" || ResultDigest(resp) != ResultDigest(jsResponse()) {
		t.Fatalf("instance %q, or it moved the result digest", resp.Instance)
	}
	resp.Record = Stamp(sandbox.RunRecord{RequestSHA256: RunRequestDigest(req)}, resp)
	if r, err := Check(req, resp); err != nil || r.Instance != resp.Instance {
		t.Fatalf("matching record: %v", err)
	}
	for name, edit := range map[string]func(*plimsollv1.RunResponse){
		"another instance in the response": func(m *plimsollv1.RunResponse) {
			m.Instance = sandbox.PodInstance("00000000-0000-0000-0000-000000000000")
		},
		"another instance in the record": func(m *plimsollv1.RunResponse) {
			m.Record.Instance = "k8s-pod-uid:other"
			m.Record.RecordSha256 = Digest(FromWire(m.Record))
		},
		"an instance that is not a typed reference": func(m *plimsollv1.RunResponse) {
			m.Instance = "/var/run/pod"
			m.Record.Instance = m.Instance
			m.Record.RecordSha256 = Digest(FromWire(m.Record))
		},
	} {
		changed := proto.Clone(resp).(*plimsollv1.RunResponse)
		edit(changed)
		if _, err := Check(req, changed); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: %v, want ErrMismatch", name, err)
		}
	}
	for _, bad := range []string{"k8s-pod-uid:", "K8S:x", "k8s-pod-uid:a/b", "no-colon", ":x", "k8s-pod-uid:" + strings.Repeat("a", 128)} {
		if sandbox.ValidInstance(bad) {
			t.Errorf("%q passes for an instance", bad)
		}
	}
	if sandbox.PodInstance("a/b") != "" || !sandbox.ValidInstance("") {
		t.Error("PodInstance kept a UID outside the form, or an empty instance is refused")
	}
}

func TestRecordRejectsEnvironmentDisagreement(t *testing.T) {
	req := withApprovedRule(jsRequest())
	resp := jsResponse()
	resp.Environment = "docker-image:sha256:outer"
	resp.SoftwareIdentity = req.SoftwareRule.Identities[0]
	rec := sandbox.RunRecord{Version: Version, RequestSHA256: RunRequestDigest(req),
		ResultSHA256: ResultDigest(resp), Provider: resp.Sandbox, Isolation: resp.Isolation,
		Environment: resp.Environment, SoftwareIdentity: resp.SoftwareIdentity,
		SoftwareRuleID: (sandbox.SoftwareRule{Mode: sandbox.SoftwareApproved, Identities: req.SoftwareRule.Identities}).ID()}
	rec.SHA256 = Digest(rec)
	resp.Record = ToWire(rec)
	if _, err := Check(req, resp); err != nil {
		t.Fatalf("matching record: %v", err)
	}
	changed := proto.Clone(resp).(*plimsollv1.RunResponse)
	changed.Record.Environment = "docker-image:sha256:other"
	rec = FromWire(changed.Record)
	changed.Record.RecordSha256 = Digest(rec)
	if _, err := Check(req, changed); !errors.Is(err, ErrMismatch) {
		t.Fatalf("record environment differs from response even with a valid record digest: %v", err)
	}
}

// Every field a caller sends moves the request digest, and the trace id does not.
func TestRequestDigestCoversWhatWasSent(t *testing.T) {
	type mutation struct {
		name  string
		base  func() *plimsollv1.RunRequest
		apply func(*plimsollv1.RunRequest)
	}
	changes := []mutation{
		{"protocol", jsRequest, func(m *plimsollv1.RunRequest) { m.Protocol = 5 }},
		{"floor", jsRequest, func(m *plimsollv1.RunRequest) { m.MinimumIsolation = "vm" }},
		{"timeout", jsRequest, func(m *plimsollv1.RunRequest) { m.TimeoutMs = 5001 }},
		{"code", jsRequest, func(m *plimsollv1.RunRequest) { m.GetJavascript().Code += " " }},
		{"snippet grant", jsRequest, func(m *plimsollv1.RunRequest) { m.GetJavascript().GrantProfile = "p" }},
		{"file content", projectRequest, func(m *plimsollv1.RunRequest) { m.GetProject().Files[1].Content = "module.exports = 43" }},
		{"file path", projectRequest, func(m *plimsollv1.RunRequest) { m.GetProject().Files[1].Path = "lib2.js" }},
		{"file order", projectRequest, func(m *plimsollv1.RunRequest) {
			f := m.GetProject().Files
			f[0], f[1] = f[1], f[0]
		}},
		{"step", projectRequest, func(m *plimsollv1.RunRequest) { m.GetProject().Steps[1] = "cat  out.txt" }},
		{"artifact", projectRequest, func(m *plimsollv1.RunRequest) { m.GetProject().Artifacts = nil }},
		{"project grant", projectRequest, func(m *plimsollv1.RunRequest) { m.GetProject().GrantProfile = "p" }},
		{"model", moduleRequest, func(m *plimsollv1.RunRequest) { m.GetModule().Model = "Lorenz" }},
		{"row value", moduleRequest, func(m *plimsollv1.RunRequest) { m.GetModule().Rows[1].Values[1] = -3.0000000000000004 }},
		{"end time", moduleRequest, func(m *plimsollv1.RunRequest) { m.GetModule().EndTime = 2 }},
		{"step size", moduleRequest, func(m *plimsollv1.RunRequest) { m.GetModule().Step = 0.2 }},
		// Moving a boundary keeps the concatenated bytes and must still change the digest.
		{"path and content boundary", projectRequest, func(m *plimsollv1.RunRequest) {
			m.GetProject().Files[1] = &plimsollv1.ProjectFile{Path: "lib.jsm", Content: "odule.exports = 42"}
		}},
		{"two steps become one", projectRequest, func(m *plimsollv1.RunRequest) {
			m.GetProject().Steps = []string{"node main.js > out.txtcat out.txt"}
		}},
		{"rows regrouped", moduleRequest, func(m *plimsollv1.RunRequest) {
			m.GetModule().Rows = []*plimsollv1.ModuleRow{{Values: []float64{1}}, {Values: []float64{2, 0.5, -3}}}
		}},
	}
	for _, c := range changes {
		base := c.base()
		changed := proto.Clone(base).(*plimsollv1.RunRequest)
		c.apply(changed)
		if RunRequestDigest(base) == RunRequestDigest(changed) {
			t.Errorf("%s: the request digest did not change", c.name)
		}
	}
	ruled := withApprovedRule(jsRequest())
	for name, apply := range map[string]func(*plimsollv1.RunRequest){
		"software mode":     func(m *plimsollv1.RunRequest) { m.SoftwareRule.Mode = "exact" },
		"software identity": func(m *plimsollv1.RunRequest) { m.SoftwareRule.Identities[0] += "x" },
		"software identity order": func(m *plimsollv1.RunRequest) {
			m.SoftwareRule.Identities[0], m.SoftwareRule.Identities[1] = m.SoftwareRule.Identities[1], m.SoftwareRule.Identities[0]
		},
	} {
		changed := proto.Clone(ruled).(*plimsollv1.RunRequest)
		apply(changed)
		if RunRequestDigest(changed) == RunRequestDigest(ruled) {
			t.Errorf("%s did not move the request digest", name)
		}
	}
	same := jsRequest()
	same.TraceId = "another-trace"
	if RunRequestDigest(same) != RunRequestDigest(jsRequest()) {
		t.Error("the trace id moved the request digest")
	}
	// The payload kinds never collide: an empty snippet, an empty project and an
	// empty module differ, and none equals a request with no payload.
	seen := map[string]string{}
	for name, m := range map[string]*plimsollv1.RunRequest{
		"javascript": {Protocol: 4, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{}}},
		"project":    {Protocol: 4, Payload: &plimsollv1.RunRequest_Project{Project: &plimsollv1.ProjectRun{}}},
		"module":     {Protocol: 4, Payload: &plimsollv1.RunRequest_Module{Module: &plimsollv1.ModuleRun{}}},
		"none":       {Protocol: 4},
	} {
		d := RunRequestDigest(m)
		if other, dup := seen[d]; dup {
			t.Errorf("%s and %s share a request digest", name, other)
		}
		seen[d] = name
	}
}

// Every part of a result moves the result digest; durations, advice and the
// envelope's evidence fields do not.
func TestResultDigestCoversWhatCameBack(t *testing.T) {
	type mutation struct {
		name  string
		base  func() *plimsollv1.RunResponse
		apply func(*plimsollv1.RunResponse)
	}
	changes := []mutation{
		{"stdout", jsResponse, func(m *plimsollv1.RunResponse) { m.GetJavascript().Stdout = []byte("3\n") }},
		{"stderr byte", jsResponse, func(m *plimsollv1.RunResponse) { m.GetJavascript().Stderr = []byte{0xfe, 'x'} }},
		{"exit code", jsResponse, func(m *plimsollv1.RunResponse) { m.GetJavascript().ExitCode = 1 }},
		{"timed out", jsResponse, func(m *plimsollv1.RunResponse) { m.GetJavascript().TimedOut = true }},
		{"stdout truncated", jsResponse, func(m *plimsollv1.RunResponse) { m.GetJavascript().StdoutTruncated = true }},
		{"stderr truncated", jsResponse, func(m *plimsollv1.RunResponse) { m.GetJavascript().StderrTruncated = true }},
		{"outcome", projectResponse, func(m *plimsollv1.RunResponse) {
			m.GetProject().Outcome = plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT
		}},
		{"outcome detail", projectResponse, func(m *plimsollv1.RunResponse) { m.GetProject().OutcomeDetail = "x" }},
		{"step output", projectResponse, func(m *plimsollv1.RunResponse) { m.GetProject().Steps[1].Stdout = []byte("43\n") }},
		{"step exit", projectResponse, func(m *plimsollv1.RunResponse) { m.GetProject().Steps[0].ExitCode = 2 }},
		{"step dropped", projectResponse, func(m *plimsollv1.RunResponse) { m.GetProject().Steps = m.GetProject().Steps[:1] }},
		{"artifact content", projectResponse, func(m *plimsollv1.RunResponse) {
			m.GetProject().Artifacts[0].Content = []byte("42")
		}},
		{"artifact path", projectResponse, func(m *plimsollv1.RunResponse) { m.GetProject().Artifacts[0].Path = "o.txt" }},
		{"artifacts truncated", projectResponse, func(m *plimsollv1.RunResponse) { m.GetProject().ArtifactsTruncated = true }},
		{"module output", moduleResponse, func(m *plimsollv1.RunResponse) { m.GetModule().Runs[0].Outputs[1] = 1.25 }},
		{"module status", moduleResponse, func(m *plimsollv1.RunResponse) { m.GetModule().Runs[1].Status = -4 }},
		{"module width", moduleResponse, func(m *plimsollv1.RunResponse) { m.GetModule().Width = 2 }},
		{"module stdout", moduleResponse, func(m *plimsollv1.RunResponse) { m.GetModule().Stdout = nil }},
	}
	for _, c := range changes {
		base := c.base()
		changed := proto.Clone(base).(*plimsollv1.RunResponse)
		c.apply(changed)
		if ResultDigest(base) == ResultDigest(changed) {
			t.Errorf("%s: the result digest did not change", c.name)
		}
	}
	same := projectResponse()
	same.DurationMs = 1
	same.Sandbox, same.Isolation = "docker", "kernel"
	same.GetProject().Steps[0].DurationMs = 7
	same.GetProject().Advice = []*plimsollv1.AdviceFinding{{Pattern: "fan_out"}}
	if ResultDigest(same) != ResultDigest(projectResponse()) {
		t.Error("a duration, advice or an evidence field moved the result digest")
	}
}

func TestRecordDigestCoversEveryField(t *testing.T) {
	base := goldenRecord()
	// Keyed by field name, and checked against the struct, so a field added to
	// RunRecord fails here until the digest covers it. The version was once left out
	// (external review of v0.10.0, finding 9, 2026-09-28).
	moves := map[string]func(*sandbox.RunRecord){
		"Version":          func(r *sandbox.RunRecord) { r.Version = 5 },
		"RequestSHA256":    func(r *sandbox.RunRecord) { r.RequestSHA256 = RunRequestDigest(jsRequest()) },
		"ResultSHA256":     func(r *sandbox.RunRecord) { r.ResultSHA256 = ResultDigest(jsResponse()) },
		"Provider":         func(r *sandbox.RunRecord) { r.Provider = "docker" },
		"Isolation":        func(r *sandbox.RunRecord) { r.Isolation = "kernel" },
		"Environment":      func(r *sandbox.RunRecord) { r.Environment = "" },
		"SoftwareIdentity": func(r *sandbox.RunRecord) { r.SoftwareIdentity = "oci-manifest:linux/amd64@sha256:aa" },
		"SoftwareRuleID":   func(r *sandbox.RunRecord) { r.SoftwareRuleID = "exact:oci-manifest:linux/amd64@sha256:aa" },
		"Policy":           func(r *sandbox.RunRecord) { r.Policy = "" },
		"Started":          func(r *sandbox.RunRecord) { r.Started = r.Started.Add(time.Millisecond) },
		"Ended":            func(r *sandbox.RunRecord) { r.Ended = r.Ended.Add(time.Millisecond) },
		"Session":          func(r *sandbox.RunRecord) { r.Session = "" },
		"Sequence":         func(r *sandbox.RunRecord) { r.Sequence = 3 },
		"PreviousSHA256":   func(r *sandbox.RunRecord) { r.PreviousSHA256 = "" },
		"Unanswered":       func(r *sandbox.RunRecord) { r.Unanswered = "unknown" },
		"Instance":         func(r *sandbox.RunRecord) { r.Instance = "" },
	}
	fields := reflect.TypeOf(sandbox.RunRecord{})
	for i := range fields.NumField() {
		if name := fields.Field(i).Name; name != "SHA256" && moves[name] == nil {
			t.Errorf("RunRecord.%s has no case here: add it and cover it in Digest", name)
		}
	}
	for name, apply := range moves {
		changed := base
		apply(&changed)
		if Digest(changed) == Digest(base) {
			t.Errorf("%s: the record digest did not change", name)
		}
	}
	// A sub-millisecond difference is not on the wire, so it is not in the digest.
	finer := base
	finer.Started = finer.Started.Add(400 * time.Microsecond)
	if Digest(finer) != Digest(base) {
		t.Error("a sub-millisecond time moved the record digest")
	}
}

func TestWireRoundTrip(t *testing.T) {
	r := goldenRecord()
	r.SHA256 = Digest(r)
	back := FromWire(ToWire(r))
	if Digest(back) != r.SHA256 || back.SHA256 != r.SHA256 || !back.Started.Equal(r.Started) {
		t.Fatalf("round trip changed the record: %+v", back)
	}
}

// signedResponse is what a daemon sends for req: resp with a record over both.
func signedResponse(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) *plimsollv1.RunResponse {
	r := sandbox.RunRecord{
		Version: Version, RequestSHA256: RunRequestDigest(req), ResultSHA256: ResultDigest(resp),
		Provider: resp.GetSandbox(), Isolation: resp.GetIsolation(),
		Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000812),
	}
	r.SHA256 = Digest(r)
	out := proto.Clone(resp).(*plimsollv1.RunResponse)
	out.Record = ToWire(r)
	return out
}

func TestCheck(t *testing.T) {
	req := jsRequest()
	good := signedResponse(req, jsResponse())
	if r, err := Check(req, good); err != nil || r == nil || r.SHA256 != good.GetRecord().GetRecordSha256() {
		t.Fatalf("a matching record: %v, %v", r, err)
	}
	if r, err := Check(req, jsResponse()); r != nil || !errors.Is(err, ErrNoRecord) {
		t.Fatalf("no record must be ErrNoRecord: %v, %v", r, err)
	}
	// Stamp builds the same record a daemon states: signedResponse assembles it by hand.
	stamped := Stamp(sandbox.RunRecord{RequestSHA256: RunRequestDigest(req),
		Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000812)}, jsResponse())
	if !proto.Equal(stamped, good.GetRecord()) {
		t.Fatalf("Stamp: %v, want %v", stamped, good.GetRecord())
	}
	for name, tamper := range map[string]func(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse){
		"the request sent differs": func(req *plimsollv1.RunRequest, _ *plimsollv1.RunResponse) {
			req.GetJavascript().Code = "console.log(3)"
		},
		"the output differs": func(_ *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) {
			resp.GetJavascript().Stdout = []byte("4\n")
		},
		"the provider differs": func(_ *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) { resp.Sandbox = "e2b" },
		"the tier differs":     func(_ *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) { resp.Isolation = "vm" },
		"a record field moved": func(_ *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) { resp.GetRecord().EndedUnixMs++ },
		"it claims a session":  func(_ *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) { resp.GetRecord().Sequence = 1 },
		"the record digest":    func(_ *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) { resp.GetRecord().RecordSha256 = "00" },
	} {
		r := proto.Clone(req).(*plimsollv1.RunRequest)
		resp := proto.Clone(good).(*plimsollv1.RunResponse)
		tamper(r, resp)
		if name == "it claims a session" {
			rec := FromWire(resp.GetRecord())
			resp.GetRecord().RecordSha256 = Digest(rec)
		}
		if _, err := Check(r, resp); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: got %v, want ErrMismatch", name, err)
		}
	}
	future := proto.Clone(good).(*plimsollv1.RunResponse)
	future.GetRecord().Version = 3
	if _, err := Check(req, future); !errors.Is(err, ErrVersion) {
		t.Errorf("an unknown version: got %v, want ErrVersion", err)
	}
}

// Stamp takes the evidence from the response and leaves the response alone: a caller
// that states other evidence cannot make the record and the response disagree
// (review of 5d8724d, finding 7).
func TestStampStatesTheResponsesEvidence(t *testing.T) {
	req := jsRequest()
	resp := jsResponse()
	resp.Environment, resp.SoftwareIdentity = "docker-image:sha256:outer", "oci-manifest:linux/amd64@sha256:"+strings.Repeat("a", 64)
	before := proto.Clone(resp).(*plimsollv1.RunResponse)
	resp.Record = Stamp(sandbox.RunRecord{RequestSHA256: RunRequestDigest(req),
		Environment: "docker-image:sha256:other", SoftwareIdentity: "oci-manifest:linux/amd64@sha256:other"}, resp)
	after := proto.Clone(resp).(*plimsollv1.RunResponse)
	after.Record = nil
	if !proto.Equal(after, before) {
		t.Fatalf("Stamp changed the response: %v, was %v", after, before)
	}
	if got := resp.GetRecord(); got.GetEnvironment() != before.GetEnvironment() || got.GetSoftwareIdentity() != before.GetSoftwareIdentity() {
		t.Fatalf("record states %q, %q; the response %q, %q", got.GetEnvironment(), got.GetSoftwareIdentity(), before.GetEnvironment(), before.GetSoftwareIdentity())
	}
	if _, err := Check(req, resp); err != nil {
		t.Fatal(err)
	}
}

// The error code an unanswered record names moves its digest.
func TestUnansweredCodeIsInTheDigest(t *testing.T) {
	r := goldenRecord()
	r.ResultSHA256, r.Unanswered = "", "unknown"
	other := r
	other.Unanswered = "internal"
	if Digest(r) == Digest(other) {
		t.Fatal("the unanswered code did not move the record digest")
	}
}

// An unanswered session call's record checks against the request sent and the chain
// seen, and is refused when anything it states does not hold.
func TestCheckUnanswered(t *testing.T) {
	req := fixture("cell request", &plimsollv1.SessionRunRequest{})
	fp := SessionFingerprint("session-id")
	stamp := func(edit func(*sandbox.RunRecord), code string) *plimsollv1.RunRecord {
		r := sandbox.RunRecord{RequestSHA256: SessionRunRequestDigest(req), Provider: "docker", Isolation: "container",
			Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000001000), Session: fp, Sequence: 2, PreviousSHA256: "prev"}
		if edit != nil {
			edit(&r)
		}
		return StampUnanswered(r, code)
	}
	if r, err := CheckUnanswered(req, stamp(nil, "unavailable"), fp, 1, "prev"); err != nil || r.Unanswered != "unavailable" || r.Version != Version {
		t.Fatalf("a good unanswered record: %+v, %v", r, err)
	}
	for name, c := range map[string]struct {
		rec  *plimsollv1.RunRecord
		want error
	}{
		"no error code":    {stamp(nil, ""), ErrMismatch},
		"not a code":       {stamp(nil, "the relay said so"), ErrMismatch},
		"another request":  {stamp(func(r *sandbox.RunRecord) { r.RequestSHA256 = "other" }, "unknown"), ErrMismatch},
		"another session":  {stamp(func(r *sandbox.RunRecord) { r.Session = "other" }, "unknown"), ErrChain},
		"a gap":            {stamp(func(r *sandbox.RunRecord) { r.Sequence = 3 }, "unknown"), ErrChain},
		"another previous": {stamp(func(r *sandbox.RunRecord) { r.PreviousSHA256 = "other" }, "unknown"), ErrChain},
		"a version 3":      {func() *plimsollv1.RunRecord { m := stamp(nil, "unknown"); m.Version = 3; return m }(), ErrVersion},
		"a result digest":  {func() *plimsollv1.RunRecord { m := stamp(nil, "unknown"); m.ResultSha256 = "x"; return m }(), ErrMismatch},
		"a changed field":  {func() *plimsollv1.RunRecord { m := stamp(nil, "unknown"); m.Provider = "e2b"; return m }(), ErrMismatch},
		"no record at all": {nil, ErrNoRecord},
	} {
		if _, err := CheckUnanswered(req, c.rec, fp, 1, "prev"); !errors.Is(err, c.want) {
			t.Errorf("%s: %v; want %v", name, err, c.want)
		}
	}
}

// An answered record stating an unanswered code, a field outside
// its digest, is refused, and so is evidence below the request's floor or a floor no
// daemon accepts (v0.15.0 review, H1 and M5.1).
func TestCheckRefusesUncoveredFieldsAndFloorViolations(t *testing.T) {
	for name, tc := range map[string]struct {
		floor, isolation, unanswered string
		want                         error
	}{
		"answered, unanswered set": {"", "vm", "unknown", ErrMismatch},
		"below the floor":          {"vm", "container", "", sandbox.ErrIsolationEvidenceMismatch},
		"unknown evidence":         {"process", "", "", sandbox.ErrIsolationEvidenceMismatch},
		"bad floor":                {"none", "vm", "", ErrMismatch},
		"meets the floor":          {"kernel", "vm", "", nil},
	} {
		t.Run(name, func(t *testing.T) {
			req := &plimsollv1.RunRequest{Protocol: 4, MinimumIsolation: tc.floor, Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "x"}}}
			resp := &plimsollv1.RunResponse{Sandbox: "fake", Isolation: tc.isolation,
				Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{}}}
			resp.Record = Stamp(sandbox.RunRecord{RequestSHA256: RunRequestDigest(req)}, resp)
			resp.Record.Unanswered = tc.unanswered
			_, err := Check(req, resp)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Check = %v, want %v", err, tc.want)
			}
		})
	}
}

// A daemon that answers a request of one kind with a result of another, its record
// stamped over that result so every digest matches, is refused by the record check
// itself, live and stored, so no such exchange is signed into a bundle; so is an
// answered record with no result at all (review, 2026-10-26).
func TestCheckRefusesAResultOfAnotherKind(t *testing.T) {
	req := jsRequest()
	resp := signedResponse(req, projectResponse())
	if _, err := Check(req, resp); !errors.Is(err, ErrMismatch) {
		t.Fatalf("a project result for a snippet request: %v, want ErrMismatch", err)
	}
	if _, err := CheckExchange(req, resp); !errors.Is(err, ErrMismatch) {
		t.Fatalf("stored, a project result for a snippet request: %v, want ErrMismatch", err)
	}
	none := signedResponse(req, &plimsollv1.RunResponse{})
	if _, err := Check(req, none); !errors.Is(err, ErrMismatch) {
		t.Fatalf("no result for a snippet request: %v, want ErrMismatch", err)
	}
}
