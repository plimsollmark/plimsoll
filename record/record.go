// Package record computes the digests in a plimsoll run record: what a caller
// sent, what came back, and the record that states both with the evidence the
// run executed under. The daemon and a caller compute them with this same code,
// so a caller can check a record against its own copy of the request and result
// before a harness signs it (package attest). The daemon holds no key: it only
// hashes.
//
// Every digest is lowercase hex SHA-256 over a length-prefixed encoding, not over
// protobuf or JSON bytes, so another language reproduces it with a hash function
// and nothing else. docs/run-records.md is the specification; the golden vectors
// in record_test.go pin it.
package record

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/softwarewire"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Version is the encoding version of every record this package writes: every field,
// every time. An unanswered session call's record is the same encoding with the result
// digest empty and unanswered set. A live answer must carry it; stored evidence may carry
// any published version.
const Version = 6

// LastWallClockEndVersion is the last record version whose daemons stamped both times from
// the wall clock: daemons v0.10.0 to v0.12.0, so a clock step between the two readings
// could write a genuine record that ends before it starts (5d6270398 measured one 1.3 s
// early and made the end the start plus monotonic elapsed time, from v0.13.0). Version 2
// states no daemon version, so all of versions 1 and 2 are covered. Reading such a record
// was retired by the decision of 2026-11-21 (docs/run-records.md): every reader
// refuses it, with RetiredEndBeforeStartText rather than the text that a current
// record's refusal gives, so the refusal reads as a retirement and not as a forgery. Every
// reader takes the number and the text from internal/wiretables, so they agree
// (record/testdata/retired/clock-step-v1-v2.json).
const LastWallClockEndVersion = 2

// RetiredEndBeforeStartText is the refusal of a version 1 or 2 record that ends before it
// starts.
const RetiredEndBeforeStartText = "the record ends before it starts, and that reading is retired by the decision of 2026-11-21: records of versions 1 and 2 that end before they start are no longer read; daemons v0.10.0 to v0.12.0 could write one during a clock step"

// ErrRetired marks a refusal by a retired reading (RetiredEndBeforeStartText): the record
// may be genuine, and is refused by a dated, announced decision, not as forged. The error
// is ErrMismatch too, so a caller that only asks whether the record was refused still sees
// it refused, but its text is the retirement's alone.
var ErrRetired = errors.New("record: refused by a retired reading")

// retiredEndBeforeStart is the refusal of a version 1 or 2 record that ends before it starts.
type retiredEndBeforeStart struct{}

func (retiredEndBeforeStart) Error() string { return "record: " + RetiredEndBeforeStartText }
func (retiredEndBeforeStart) Is(target error) bool {
	return target == ErrRetired || target == ErrMismatch
}

// published holds every record version a release has written, frozen: the fields its
// digest covers, in order, and what a record of it may state. Writers write Version only,
// and every verifier of stored evidence reads them all, so a record signed under an older
// release still checks without its release's binary (2026-10-23: the
// no-backward-compatibility rule binds writers, not the verification of evidence already
// signed). Version 4 removed this reading for a day, under that rule. A version leaves
// this table only by a dated, announced decision. Each is pinned by what its own release
// produced: record/testdata/published/ and attest/testdata/published/.
var published = map[int]spec{
	// v0.10.0 to v0.11.1: answered calls only, with no software admission and no check
	// of the environment against the response.
	1: {fields: []string{"request_sha256", "result_sha256", "provider", "isolation", "environment", "policy",
		"started_unix_ms", "ended_unix_ms", "session", "sequence", "previous_sha256"}, answered: true},
	// v0.12.0 to v0.22.0, answered calls.
	2: {fields: []string{"request_sha256", "result_sha256", "provider", "isolation", "environment", "policy",
		"software_identity", "software_rule_id", "started_unix_ms", "ended_unix_ms", "session", "sequence",
		"previous_sha256"}, answered: true, evidence: true},
	// v0.15.0 to v0.22.0, unanswered session calls only.
	3: {fields: []string{"request_sha256", "result_sha256", "unanswered", "provider", "isolation", "environment",
		"policy", "software_identity", "software_rule_id", "started_unix_ms", "ended_unix_ms", "session", "sequence",
		"previous_sha256"}, unanswered: true, evidence: true},
	// v0.23.0 to v0.27.x: both kinds, and the instance.
	4: {fields: []string{"request_sha256", "result_sha256", "unanswered", "provider", "isolation", "environment",
		"policy", "software_identity", "software_rule_id", "instance", "started_unix_ms", "ended_unix_ms", "session",
		"sequence", "previous_sha256"}, answered: true, unanswered: true, evidence: true},
	// From v0.28.0: version 4 with the sentence the provider states beside the tier, whether
	// a waiting pool sandbox ran the call, and the daemon's own version.
	5: {fields: []string{"request_sha256", "result_sha256", "unanswered", "provider", "isolation",
		"isolation_qualification", "environment", "policy", "software_identity", "software_rule_id", "instance", "warm",
		"daemon_version", "started_unix_ms", "ended_unix_ms", "session", "sequence", "previous_sha256"},
		answered: true, unanswered: true, evidence: true, result: resultV1},
	// From protocol 9: version 5's fields, written out again so version 5 stays frozen,
	// with results hashed under the second result domain, which adds the files kind.
	// Nothing in a result names its domain, so the domain is the record version's
	// (docs/run-records.md).
	6: {fields: []string{"request_sha256", "result_sha256", "unanswered", "provider", "isolation",
		"isolation_qualification", "environment", "policy", "software_identity", "software_rule_id", "instance", "warm",
		"daemon_version", "started_unix_ms", "ended_unix_ms", "session", "sequence", "previous_sha256"},
		answered: true, unanswered: true, evidence: true, result: resultV2},
}

// spec is one published record version.
type spec struct {
	fields     []string // the record digest's fields, in order
	answered   bool     // may record an answered call
	unanswered bool     // may record an unanswered session call
	// evidence: the environment, the selected software and the admission rule are checked
	// against the response and the request. Version 1 records named an environment but
	// were never checked against the response's.
	evidence bool
	// result is the result domain this version's result digests are computed under;
	// resultV1 (the zero value) for every version before 6.
	result resultEncoding
}

func (s spec) covers(field string) bool { return slices.Contains(s.fields, field) }

// PublishedLayouts returns, for every published record version, the fields its digest
// covers in order: the table internal/wiretables writes into the Python and TypeScript
// clients and examples/sbom/check.js, so no reader keeps a copy by hand.
func PublishedLayouts() map[int][]string {
	out := make(map[int][]string, len(published))
	for v, s := range published {
		out[v] = slices.Clone(s.fields)
	}
	return out
}

// recordField is one field a record digest can cover: how it is encoded, and whether a
// record states it (a field a version does not cover must be empty, or the record would
// state evidence nothing signed).
type recordField struct {
	put func(*encoder, string, sandbox.RunRecord)
	set func(sandbox.RunRecord) bool
}

var recordFields = map[string]recordField{
	"request_sha256":          {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.RequestSHA256) }, func(r sandbox.RunRecord) bool { return r.RequestSHA256 != "" }},
	"result_sha256":           {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.ResultSHA256) }, func(r sandbox.RunRecord) bool { return r.ResultSHA256 != "" }},
	"unanswered":              {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Unanswered) }, func(r sandbox.RunRecord) bool { return r.Unanswered != "" }},
	"provider":                {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Provider) }, func(r sandbox.RunRecord) bool { return r.Provider != "" }},
	"isolation":               {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Isolation) }, func(r sandbox.RunRecord) bool { return r.Isolation != "" }},
	"environment":             {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Environment) }, func(r sandbox.RunRecord) bool { return r.Environment != "" }},
	"policy":                  {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Policy) }, func(r sandbox.RunRecord) bool { return r.Policy != "" }},
	"software_identity":       {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.SoftwareIdentity) }, func(r sandbox.RunRecord) bool { return r.SoftwareIdentity != "" }},
	"software_rule_id":        {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.SoftwareRuleID) }, func(r sandbox.RunRecord) bool { return r.SoftwareRuleID != "" }},
	"instance":                {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Instance) }, func(r sandbox.RunRecord) bool { return r.Instance != "" }},
	"isolation_qualification": {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.IsolationQualification) }, func(r sandbox.RunRecord) bool { return r.IsolationQualification != "" }},
	"warm":                    {func(e *encoder, n string, r sandbox.RunRecord) { e.bool(n, r.Warm) }, func(r sandbox.RunRecord) bool { return r.Warm }},
	"daemon_version":          {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.DaemonVersion) }, func(r sandbox.RunRecord) bool { return r.DaemonVersion != "" }},
	"started_unix_ms":         {func(e *encoder, n string, r sandbox.RunRecord) { e.int(n, r.Started.UnixMilli()) }, func(r sandbox.RunRecord) bool { return !r.Started.IsZero() }},
	"ended_unix_ms":           {func(e *encoder, n string, r sandbox.RunRecord) { e.int(n, r.Ended.UnixMilli()) }, func(r sandbox.RunRecord) bool { return !r.Ended.IsZero() }},
	"session":                 {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Session) }, func(r sandbox.RunRecord) bool { return r.Session != "" }},
	"sequence":                {func(e *encoder, n string, r sandbox.RunRecord) { e.uint(n, r.Sequence) }, func(r sandbox.RunRecord) bool { return r.Sequence != 0 }},
	"previous_sha256":         {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.PreviousSHA256) }, func(r sandbox.RunRecord) bool { return r.PreviousSHA256 != "" }},
}

// Each encoding opens with its domain string, so a digest of one kind can never
// equal a digest of another, whatever the fields hold. A request sent under protocol 1
// (v0.10.0 to v0.11.1, read for their records) has the first request encoding: no
// software rule.
const (
	requestDomainV1 = "plimsoll.run-request.v1"
	requestDomainV2 = "plimsoll.run-request.v2"
	requestDomainV3 = "plimsoll.run-request.v3"
	resultDomainV1  = "plimsoll.run-result.v1"
	resultDomainV2  = "plimsoll.run-result.v2"
)

// FirstFilesProtocol is the first protocol whose requests are hashed under
// plimsoll.run-request.v3, the request domain that covers the files kind: a request's
// protocol number picks its domain (v1 below 2, v2 from 2 to 8, v3 from 9).
const FirstFilesProtocol = 9

// requestDomainFor is the request domain a request stating protocol is hashed under.
func requestDomainFor(protocol uint32) string {
	switch {
	case protocol < 2:
		return requestDomainV1
	case protocol < FirstFilesProtocol:
		return requestDomainV2
	}
	return requestDomainV3
}

// resultEncoding is one result domain: plimsoll.run-result.v1 (the javascript, project,
// module and cell kinds, records of versions 1 to 5) or plimsoll.run-result.v2 (those and
// files, from record version 6).
type resultEncoding int

const (
	resultV1 resultEncoding = iota
	resultV2
)

func (r resultEncoding) domain() string {
	if r == resultV2 {
		return resultDomainV2
	}
	return resultDomainV1
}

// kinds are the result kinds the domain covers, in RunResponse's order.
func (r resultEncoding) kinds() []string {
	if r == resultV2 {
		return []string{"javascript", "project", "module", "cell", "files"}
	}
	return []string{"javascript", "project", "module", "cell"}
}

// ResultDomains returns, for every published record version, the result domain its result
// digests are computed under: the table internal/wiretables writes into the Python and
// TypeScript clients.
func ResultDomains() map[int]string {
	out := make(map[int]string, len(published))
	for v, s := range published {
		out[v] = s.result.domain()
	}
	return out
}

// RequestDomains returns each request domain by the first protocol hashed under it: the
// table internal/wiretables writes into the Python and TypeScript clients. A request is
// hashed under the domain of the highest first protocol at or below its own (a protocol 0
// request, which no daemon runs, under the first).
func RequestDomains() map[int]string {
	return map[int]string{1: requestDomainV1, 2: requestDomainV2, FirstFilesProtocol: requestDomainV3}
}

// encoder streams an encoding into SHA-256. Every value, the domain included, is
// its length as an unsigned 64-bit big-endian integer followed by its bytes, and a
// field is its name encoded that way followed by its value encoded that way. The
// fields of each kind come in one fixed order and a repeated group is preceded by
// its count, so two different inputs never share an encoding.
type encoder struct{ h hash.Hash }

func newEncoder(domain string) *encoder {
	e := &encoder{h: sha256.New()}
	e.value([]byte(domain))
	return e
}

func (e *encoder) value(b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	e.h.Write(n[:])
	e.h.Write(b)
}

func (e *encoder) bytes(name string, v []byte) {
	e.value([]byte(name))
	e.value(v)
}

func (e *encoder) str(name, v string) { e.bytes(name, []byte(v)) }

// Integers are decimal ASCII with a leading "-" when negative: the form every
// language prints by default.
func (e *encoder) int(name string, v int64)   { e.str(name, strconv.FormatInt(v, 10)) }
func (e *encoder) uint(name string, v uint64) { e.str(name, strconv.FormatUint(v, 10)) }
func (e *encoder) bool(name string, v bool)   { e.str(name, strconv.FormatBool(v)) }

// Floating-point values are their IEEE 754 binary64 bits, big-endian, 8 bytes
// each, so no decimal formatting rule can round one.
func (e *encoder) floats(name string, vs ...float64) {
	b := make([]byte, 0, 8*len(vs))
	for _, v := range vs {
		b = binary.BigEndian.AppendUint64(b, math.Float64bits(v))
	}
	e.bytes(name, b)
}

func (e *encoder) sum() string { return hex.EncodeToString(e.h.Sum(nil)) }

// RunRequestDigest is the request digest of a Run request: the protocol number,
// the floor, the timeout and the payload as sent. The trace id is left out: it
// is the caller's correlation key and changes nothing that runs.
func RunRequestDigest(m *plimsollv1.RunRequest) string {
	return requestDigest(m.GetProtocol(), m.GetMinimumIsolation(), m.GetTimeoutMs(),
		m.GetSoftwareRule(), m.GetJavascript(), m.GetProject(), m.GetModule(), m.GetCell(), m.GetFiles())
}

// SessionRunRequestDigest is the request digest of a session call: the same
// fields as a Run request's, so a call and a run of the same payload share a
// digest. The session ID is left out: it is a capability, and the record carries
// the session's fingerprint instead.
func SessionRunRequestDigest(m *plimsollv1.SessionRunRequest) string {
	return requestDigest(m.GetProtocol(), m.GetMinimumIsolation(), m.GetTimeoutMs(),
		m.GetSoftwareRule(), m.GetJavascript(), m.GetProject(), nil, m.GetCell(), m.GetFiles())
}

// AsRunRequest is a session call's request as the Run request with the same
// digest, without the session ID: the form a harness stores and replays. A cell's
// stored form is a Run request with a cell payload, and a file call's one with a files
// payload, both of which Run itself refuses.
func AsRunRequest(m *plimsollv1.SessionRunRequest) *plimsollv1.RunRequest {
	out := &plimsollv1.RunRequest{
		Protocol: m.GetProtocol(), MinimumIsolation: m.GetMinimumIsolation(),
		TraceId: m.GetTraceId(), TimeoutMs: m.GetTimeoutMs(), SoftwareRule: m.GetSoftwareRule(),
	}
	switch p := m.GetPayload().(type) {
	case *plimsollv1.SessionRunRequest_Javascript:
		out.Payload = &plimsollv1.RunRequest_Javascript{Javascript: p.Javascript}
	case *plimsollv1.SessionRunRequest_Project:
		out.Payload = &plimsollv1.RunRequest_Project{Project: p.Project}
	case *plimsollv1.SessionRunRequest_Cell:
		out.Payload = &plimsollv1.RunRequest_Cell{Cell: p.Cell}
	case *plimsollv1.SessionRunRequest_Files:
		out.Payload = &plimsollv1.RunRequest_Files{Files: p.Files}
	}
	return out
}

func requestDigest(protocol uint32, floor string, timeoutMs int32, rule *plimsollv1.SoftwareRule,
	js *plimsollv1.JavaScriptRun, p *plimsollv1.ProjectRun, mod *plimsollv1.ModuleRun, cell *plimsollv1.CellRun,
	files *plimsollv1.FilesRun) string {
	domain := requestDomainFor(protocol)
	first := domain == requestDomainV1
	e := newEncoder(domain)
	e.uint("protocol", uint64(protocol))
	e.str("minimum_isolation", floor)
	e.int("timeout_ms", int64(timeoutMs))
	if !first {
		e.str("software_mode", rule.GetMode())
		e.int("software_identities", int64(len(rule.GetIdentities())))
		for _, id := range rule.GetIdentities() {
			e.str("software_identity", id)
		}
	}
	switch {
	case js != nil:
		e.str("kind", "javascript")
		e.str("code", js.GetCode())
		e.str("grant_profile", js.GetGrantProfile())
	case p != nil:
		e.str("kind", "project")
		e.str("grant_profile", p.GetGrantProfile())
		e.int("files", int64(len(p.GetFiles())))
		for _, f := range p.GetFiles() {
			e.str("file_path", f.GetPath())
			e.str("file_content", f.GetContent())
		}
		e.int("steps", int64(len(p.GetSteps())))
		for _, s := range p.GetSteps() {
			e.str("step_command", s)
		}
		e.int("artifacts", int64(len(p.GetArtifacts())))
		for _, a := range p.GetArtifacts() {
			e.str("artifact_path", a)
		}
	case cell != nil:
		e.str("kind", "cell")
		e.str("language", cell.GetLanguage())
		e.str("code", cell.GetCode())
		e.int("files", int64(len(cell.GetFiles())))
		for _, f := range cell.GetFiles() {
			e.str("file_path", f.GetPath())
			e.str("file_content", f.GetContent())
		}
	case mod != nil:
		e.str("kind", "module")
		e.str("model", mod.GetModel())
		e.floats("end_time", mod.GetEndTime())
		e.floats("step", mod.GetStep())
		e.int("rows", int64(len(mod.GetRows())))
		for _, r := range mod.GetRows() {
			e.floats("row_values", r.GetValues()...)
		}
	case files != nil && domain == requestDomainV3:
		// Only plimsoll.run-request.v3 covers the files kind: under an earlier domain a
		// files payload is no kind at all, and no record of it is accepted (check).
		e.str("kind", "files")
		filesRequest(e, files)
	default:
		e.str("kind", "")
	}
	return e.sum()
}

// filesRequest encodes a file call's request: the scope by its number, then the operation
// by its word, then the operation's fields. Paths and content are their raw bytes.
func filesRequest(e *encoder, f *plimsollv1.FilesRun) {
	e.int("scope", int64(f.GetScope()))
	switch op := f.GetOp().(type) {
	case *plimsollv1.FilesRun_Stat:
		e.str("op", "stat")
		e.bytes("path", op.Stat.GetPath())
	case *plimsollv1.FilesRun_Read:
		e.str("op", "read")
		e.bytes("path", op.Read.GetPath())
		e.uint("offset", op.Read.GetOffset())
		e.uint("max_bytes", uint64(op.Read.GetMaxBytes()))
	case *plimsollv1.FilesRun_Write:
		e.str("op", "write")
		e.bytes("path", op.Write.GetPath())
		e.bytes("content", op.Write.GetContent())
		e.int("write_mode", int64(op.Write.GetMode()))
		e.bool("make_parents", op.Write.GetMakeParents())
	case *plimsollv1.FilesRun_List:
		e.str("op", "list")
		e.bytes("path", op.List.GetPath())
		e.bool("recursive", op.List.GetRecursive())
		e.bytes("match", op.List.GetMatch())
		e.bytes("after", op.List.GetAfter())
		e.uint("budget_bytes", uint64(op.List.GetBudgetBytes()))
	case *plimsollv1.FilesRun_ReadMany:
		e.str("op", "read_many")
		e.int("paths", int64(len(op.ReadMany.GetPaths())))
		for _, p := range op.ReadMany.GetPaths() {
			e.bytes("path", p)
		}
		e.uint("max_bytes_each", uint64(op.ReadMany.GetMaxBytesEach()))
		e.uint("budget_bytes", uint64(op.ReadMany.GetBudgetBytes()))
	case *plimsollv1.FilesRun_MakeDir:
		e.str("op", "make_dir")
		e.bytes("path", op.MakeDir.GetPath())
		e.bool("parents", op.MakeDir.GetParents())
	case *plimsollv1.FilesRun_Remove:
		e.str("op", "remove")
		e.bytes("path", op.Remove.GetPath())
		e.bool("dir", op.Remove.GetDir())
	case *plimsollv1.FilesRun_Rename:
		e.str("op", "rename")
		e.bytes("from_path", op.Rename.GetFromPath())
		e.bytes("to_path", op.Rename.GetToPath())
		e.bool("replace", op.Rename.GetReplace())
	default:
		e.str("op", "")
	}
}

// requestKind is the payload kind a request carries (javascript, project, cell or
// module), "" for none; sessionRequestKind and resultKind are a session request's and
// a response's. A daemon that answered one kind with another used to have its exchange
// signed into a bundle, the client refusing the answer only afterwards (review,
// 2026-10-26).
func requestKind(m *plimsollv1.RunRequest) string {
	switch m.GetPayload().(type) {
	case *plimsollv1.RunRequest_Javascript:
		return "javascript"
	case *plimsollv1.RunRequest_Project:
		return "project"
	case *plimsollv1.RunRequest_Cell:
		return "cell"
	case *plimsollv1.RunRequest_Module:
		return "module"
	case *plimsollv1.RunRequest_Files:
		return "files"
	}
	return ""
}

func sessionRequestKind(m *plimsollv1.SessionRunRequest) string {
	switch m.GetPayload().(type) {
	case *plimsollv1.SessionRunRequest_Javascript:
		return "javascript"
	case *plimsollv1.SessionRunRequest_Project:
		return "project"
	case *plimsollv1.SessionRunRequest_Cell:
		return "cell"
	case *plimsollv1.SessionRunRequest_Files:
		return "files"
	}
	return ""
}

func resultKind(m *plimsollv1.RunResponse) string {
	switch m.GetResult().(type) {
	case *plimsollv1.RunResponse_Javascript:
		return "javascript"
	case *plimsollv1.RunResponse_Project:
		return "project"
	case *plimsollv1.RunResponse_Cell:
		return "cell"
	case *plimsollv1.RunResponse_Module:
		return "module"
	case *plimsollv1.RunResponse_Files:
		return "files"
	}
	return ""
}

// ResultDigest is the result digest of a Run response as a record of the current version
// states it: the result as sent, which is what a replay of a deterministic workload
// reproduces. Durations are left out (they differ on every run), and so is advice, which
// is analysis of the run rather than its output. Provider and tier are the record's
// evidence fields. A verifier of a stored record uses ResultDigestFor with the record's
// version.
func ResultDigest(m *plimsollv1.RunResponse) string {
	return resultDigest(m, published[Version].result)
}

// ResultDigestFor is the result digest a record of the given version states for m: the
// version fixes the result domain (plimsoll.run-result.v1 to version 5,
// plimsoll.run-result.v2 from 6). An unknown version gets the current version's domain.
func ResultDigestFor(m *plimsollv1.RunResponse, version int) string {
	s, ok := published[version]
	if !ok {
		s = published[Version]
	}
	return resultDigest(m, s.result)
}

func resultDigest(m *plimsollv1.RunResponse, enc resultEncoding) string {
	e := newEncoder(enc.domain())
	switch r := m.GetResult().(type) {
	case *plimsollv1.RunResponse_Javascript:
		j := r.Javascript
		e.str("kind", "javascript")
		e.int("exit_code", int64(j.GetExitCode()))
		e.bool("timed_out", j.GetTimedOut())
		e.bytes("stdout", j.GetStdout())
		e.bytes("stderr", j.GetStderr())
		e.bool("stdout_truncated", j.GetStdoutTruncated())
		e.bool("stderr_truncated", j.GetStderrTruncated())
	case *plimsollv1.RunResponse_Project:
		p := r.Project
		e.str("kind", "project")
		e.int("outcome", int64(p.GetOutcome()))
		e.str("outcome_detail", p.GetOutcomeDetail())
		e.bool("artifacts_truncated", p.GetArtifactsTruncated())
		e.int("steps", int64(len(p.GetSteps())))
		for _, s := range p.GetSteps() {
			e.str("step_command", s.GetCommand())
			e.int("step_exit_code", int64(s.GetExitCode()))
			e.bool("step_timed_out", s.GetTimedOut())
			e.bytes("step_stdout", s.GetStdout())
			e.bytes("step_stderr", s.GetStderr())
			e.bool("step_stdout_truncated", s.GetStdoutTruncated())
			e.bool("step_stderr_truncated", s.GetStderrTruncated())
		}
		e.int("artifacts", int64(len(p.GetArtifacts())))
		for _, a := range p.GetArtifacts() {
			e.str("artifact_path", a.GetPath())
			e.bytes("artifact_content", a.GetContent())
		}
	case *plimsollv1.RunResponse_Cell:
		c := r.Cell
		e.str("kind", "cell")
		e.int("exit_code", int64(c.GetExitCode()))
		e.bool("timed_out", c.GetTimedOut())
		e.bytes("stdout", c.GetStdout())
		e.bytes("stderr", c.GetStderr())
		e.bool("stdout_truncated", c.GetStdoutTruncated())
		e.bool("stderr_truncated", c.GetStderrTruncated())
		e.bool("interpreter_started", c.GetInterpreterStarted())
		e.bool("interpreter_ended", c.GetInterpreterEnded())
	case *plimsollv1.RunResponse_Module:
		m := r.Module
		e.str("kind", "module")
		e.int("outcome", int64(m.GetOutcome()))
		e.str("outcome_detail", m.GetOutcomeDetail())
		e.int("width", int64(m.GetWidth()))
		e.bytes("stdout", m.GetStdout())
		e.bytes("stderr", m.GetStderr())
		e.int("runs", int64(len(m.GetRuns())))
		for _, run := range m.GetRuns() {
			e.int("run_status", int64(run.GetStatus()))
			e.floats("run_outputs", run.GetOutputs()...)
		}
	case *plimsollv1.RunResponse_Files:
		if enc != resultV2 {
			// plimsoll.run-result.v1 covers four kinds; a files result is none of them,
			// and no record of a version before 6 is accepted for one (check).
			e.str("kind", "")
			break
		}
		e.str("kind", "files")
		filesResult(e, r.Files)
	default:
		e.str("kind", "")
	}
	return e.sum()
}

// filesResult encodes a file call's result: the outcome and error by their numbers, the
// errno name, then the operation the answer names by its word ("" for none) and the
// answer's fields.
func filesResult(e *encoder, f *plimsollv1.FilesResult) {
	e.int("outcome", int64(f.GetOutcome()))
	e.int("error", int64(f.GetError()))
	e.str("errno", f.GetErrno())
	switch a := f.GetAnswer().(type) {
	case *plimsollv1.FilesResult_Stat:
		e.str("op", "stat")
		e.int("type", int64(a.Stat.GetType()))
		e.uint("size", a.Stat.GetSize())
		e.uint("mode", uint64(a.Stat.GetMode()))
	case *plimsollv1.FilesResult_Read:
		e.str("op", "read")
		e.bytes("content", a.Read.GetContent())
		e.uint("size_at_open", a.Read.GetSizeAtOpen())
	case *plimsollv1.FilesResult_Write:
		e.str("op", "write")
		e.uint("written", a.Write.GetWritten())
	case *plimsollv1.FilesResult_List:
		e.str("op", "list")
		e.int("entries", int64(len(a.List.GetEntries())))
		for _, en := range a.List.GetEntries() {
			e.bytes("entry_path", en.GetPath())
			e.int("entry_type", int64(en.GetType()))
			e.uint("entry_size", en.GetSize())
		}
		e.bool("more", a.List.GetMore())
	case *plimsollv1.FilesResult_ReadMany:
		e.str("op", "read_many")
		e.int("items", int64(len(a.ReadMany.GetItems())))
		for _, it := range a.ReadMany.GetItems() {
			e.int("item_error", int64(it.GetError()))
			e.str("item_errno", it.GetErrno())
			e.bytes("item_content", it.GetContent())
			e.uint("item_size_at_open", it.GetSizeAtOpen())
		}
		e.bool("more", a.ReadMany.GetMore())
	case *plimsollv1.FilesResult_MakeDir:
		e.str("op", "make_dir")
	case *plimsollv1.FilesResult_Remove:
		e.str("op", "remove")
	case *plimsollv1.FilesResult_Rename:
		e.str("op", "rename")
	default:
		e.str("op", "")
	}
}

// Digest is a record's own digest, over the fields its version covers (published),
// every field but SHA256 for an unknown version. The version is the domain's suffix
// (recordDomain), so a record that names another version cannot keep its digest. The
// times count whole milliseconds, as on the wire.
func Digest(r sandbox.RunRecord) string {
	fields := published[Version].fields
	if s, ok := published[r.Version]; ok {
		fields = s.fields
	}
	e := newEncoder(recordDomain(r.Version))
	for _, name := range fields {
		recordFields[name].put(e, name, r)
	}
	return e.sum()
}

// CheckStored verifies what a stored record states on its own: a version this package
// reads (ErrVersion otherwise, which says to upgrade the verifier rather than calling the
// record forged), a kind of call that version records, no field the version does not
// cover, a typed instance reference, and its own digest. Checking it against the request
// and response it came with is CheckExchange's.
func CheckStored(r sandbox.RunRecord) error {
	s, err := readable(r.Version, false)
	if err != nil {
		return err
	}
	return s.statesOnly(r)
}

// CheckVersion is ErrVersion for a record version this package does not read as stored
// evidence, and nil for a published one. A verifier asks it before reading a record's
// fields, since a newer version may state fields this release does not know.
func CheckVersion(version int) error {
	_, err := readable(version, false)
	return err
}

// readable returns the spec of a record version a verifier accepts: every published
// version for stored evidence, Version alone for a live answer.
func readable(version int, live bool) (spec, error) {
	s, ok := published[version]
	switch {
	case !ok:
		return spec{}, fmt.Errorf("%w: version %d; this verifier reads versions %s (a higher number means a newer plimsoll wrote it, so upgrade the verifier; zero or less, no release did)", ErrVersion, version, publishedList())
	case live && version != Version:
		return spec{}, fmt.Errorf("%w: the daemon answered with version %d; this client requires version %d of a live answer", ErrVersion, version, Version)
	}
	return s, nil
}

// statesOnly checks that r is a kind of call its version records, states no field the
// version does not cover, names one of the five tiers (none, process, container, kernel,
// vm: never "unknown" or empty, whatever floor the request named), does not end before it
// starts, answered or not (at or below LastWallClockEndVersion, as a retired reading), names a typed instance, states a bounded qualification and a
// daemon version of the module version form, and matches its own digest.
func (s spec) statesOnly(r sandbox.RunRecord) error {
	for _, f := range ShownFields(r) {
		if !ValidText(f[1]) {
			return fmt.Errorf("%w: the record's %s is not UTF-8 or holds a control or bidirectional format character", ErrMismatch, f[0])
		}
	}
	switch unanswered := r.Unanswered != ""; {
	case unanswered && !s.unanswered:
		return fmt.Errorf("%w: a version %d record cannot record an unanswered call", ErrMismatch, r.Version)
	case !unanswered && !s.answered:
		return fmt.Errorf("%w: a version %d record records only an unanswered call", ErrMismatch, r.Version)
	case unanswered == (r.ResultSHA256 != ""):
		return fmt.Errorf("%w: a record states a result or, for an unanswered call, an error code, exactly one", ErrMismatch)
	case unanswered && !unansweredCodes[r.Unanswered]:
		return fmt.Errorf("%w: an unanswered call's record names %q, not a Connect code", ErrMismatch, r.Unanswered)
	case sandbox.ParseIsolationClass(r.Isolation) == sandbox.IsolationUnknown:
		return fmt.Errorf("%w: the record's isolation %q is not a tier (none, process, container, kernel or vm)", ErrMismatch, r.Isolation)
	case r.Ended.Before(r.Started) && r.Version <= LastWallClockEndVersion:
		return retiredEndBeforeStart{}
	case r.Ended.Before(r.Started):
		return fmt.Errorf("%w: the record ends before it starts", ErrMismatch)
	case !sandbox.ValidInstance(r.Instance):
		return fmt.Errorf("%w: the record's instance %q is not a typed reference", ErrMismatch, r.Instance)
	case len(r.IsolationQualification) > MaxQualificationBytes:
		return fmt.Errorf("%w: the record's isolation qualification is over %d bytes", ErrMismatch, MaxQualificationBytes)
	case !ValidDaemonVersion(r.DaemonVersion):
		return fmt.Errorf("%w: the record's daemon version %q is not a module version or (devel)", ErrMismatch, r.DaemonVersion)
	}
	for _, name := range recordFieldOrder {
		if f := recordFields[name]; !s.covers(name) && f.set(r) {
			return fmt.Errorf("%w: a version %d record does not cover %s, so it cannot state one", ErrMismatch, r.Version, name)
		}
	}
	if d := Digest(r); r.SHA256 != d {
		return fmt.Errorf("%w: record digest %s, its fields digest to %s", ErrMismatch, r.SHA256, d)
	}
	return nil
}

// recordFieldOrder is every field a record digest can cover, in the current version's
// order (then any other, sorted), so statesOnly names the same uncovered field on every
// run rather than whichever a map's order reaches first.
var recordFieldOrder = func() []string {
	order := slices.Clone(published[Version].fields)
	for _, name := range slices.Sorted(maps.Keys(recordFields)) {
		if !slices.Contains(order, name) {
			order = append(order, name)
		}
	}
	return order
}()

// publishedList names the published versions, lowest first.
func publishedList() string {
	versions := make([]int, 0, len(published))
	for v := range published {
		versions = append(versions, v)
	}
	slices.Sort(versions)
	parts := make([]string, len(versions))
	for i, v := range versions {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}

// recordDomain is the record digest's domain for an encoding version: version 4 is
// "plimsoll.run-record.v4".
func recordDomain(version int) string {
	return "plimsoll.run-record.v" + strconv.Itoa(version)
}

// SessionFingerprint is the SHA-256 of a session ID, the value a session call's
// record carries. The ID is a capability, so it is never recorded itself.
func SessionFingerprint(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

// ToWire puts a record on the wire.
func ToWire(r sandbox.RunRecord) *plimsollv1.RunRecord {
	return &plimsollv1.RunRecord{
		Version:                uint32(r.Version),
		RequestSha256:          r.RequestSHA256,
		ResultSha256:           r.ResultSHA256,
		Provider:               r.Provider,
		Isolation:              r.Isolation,
		Environment:            r.Environment,
		SoftwareIdentity:       r.SoftwareIdentity,
		SoftwareRuleId:         r.SoftwareRuleID,
		Policy:                 r.Policy,
		StartedUnixMs:          r.Started.UnixMilli(),
		EndedUnixMs:            r.Ended.UnixMilli(),
		Session:                r.Session,
		Sequence:               r.Sequence,
		PreviousSha256:         r.PreviousSHA256,
		Unanswered:             r.Unanswered,
		Instance:               r.Instance,
		IsolationQualification: r.IsolationQualification,
		Warm:                   r.Warm,
		DaemonVersion:          r.DaemonVersion,
		RecordSha256:           r.SHA256,
	}
}

// FromWire reads a record off the wire, unchecked.
func FromWire(m *plimsollv1.RunRecord) sandbox.RunRecord {
	return sandbox.RunRecord{
		Version:                int(m.GetVersion()),
		RequestSHA256:          m.GetRequestSha256(),
		ResultSHA256:           m.GetResultSha256(),
		Provider:               m.GetProvider(),
		Isolation:              m.GetIsolation(),
		Environment:            m.GetEnvironment(),
		SoftwareIdentity:       m.GetSoftwareIdentity(),
		SoftwareRuleID:         m.GetSoftwareRuleId(),
		Policy:                 m.GetPolicy(),
		Started:                time.UnixMilli(m.GetStartedUnixMs()).UTC(),
		Ended:                  time.UnixMilli(m.GetEndedUnixMs()).UTC(),
		Session:                m.GetSession(),
		Sequence:               m.GetSequence(),
		PreviousSHA256:         m.GetPreviousSha256(),
		Unanswered:             m.GetUnanswered(),
		Instance:               m.GetInstance(),
		IsolationQualification: m.GetIsolationQualification(),
		Warm:                   m.GetWarm(),
		DaemonVersion:          m.GetDaemonVersion(),
		SHA256:                 m.GetRecordSha256(),
	}
}

// ErrMismatch means a record does not match the request and response it came
// with: a digest, the evidence, or the record's own digest differs from what the
// caller computes. The run may have executed, so it is never a retry signal.
var ErrMismatch = errors.New("record: the run record does not match the request and result it came with")

// Stamp completes r as the record of resp and returns it in wire form: the
// version, the result's digest, the evidence resp carries (provider, tier and its
// qualification, outer environment, selected software identity, instance, whether a
// waiting pool sandbox ran it, and the daemon's version) and the record's own digest. The
// caller sets what only it knows: the request's digest (RunRequestDigest or
// SessionRunRequestDigest), the software rule's ID, the policy, the start and end,
// and a session call's place in its chain. Stamp reads resp and never changes it, so
// a record cannot state evidence its response does not. Call it on the finished
// response, since the result digest covers it.
func Stamp(r sandbox.RunRecord, resp *plimsollv1.RunResponse) *plimsollv1.RunRecord {
	r.Version = Version
	r.ResultSHA256 = ResultDigest(resp)
	r.Provider = resp.GetSandbox()
	r.Isolation = resp.GetIsolation()
	r.Environment = resp.GetEnvironment()
	r.SoftwareIdentity = resp.GetSoftwareIdentity()
	r.Instance = resp.GetInstance()
	r.IsolationQualification = resp.GetIsolationQualification()
	r.Warm = resp.GetWarm()
	r.DaemonVersion = resp.GetDaemonVersion()
	r.SHA256 = Digest(r)
	return ToWire(r)
}

// StampUnanswered completes r as the record of a session call that may have run but
// ended in the error whose Connect code is code: no result digest, the code, and the
// record's own digest. The caller sets everything else, the evidence included (the
// qualification the session stated at open among it), since there is no response to
// read it from.
func StampUnanswered(r sandbox.RunRecord, code string) *plimsollv1.RunRecord {
	r.Version = Version
	r.ResultSHA256 = ""
	r.Unanswered = code
	r.SHA256 = Digest(r)
	return ToWire(r)
}

// unansweredCodes are the Connect codes an unanswered call's record may name: every
// code but "ok", in Connect's spelling.
var unansweredCodes = map[string]bool{
	"canceled": true, "unknown": true, "invalid_argument": true, "deadline_exceeded": true,
	"not_found": true, "already_exists": true, "permission_denied": true, "resource_exhausted": true,
	"failed_precondition": true, "aborted": true, "out_of_range": true, "unimplemented": true,
	"internal": true, "unavailable": true, "data_loss": true, "unauthenticated": true,
}

// UnansweredCodes returns the codes an unanswered call's record may name, sorted, for the
// generator that writes the clients' copies.
func UnansweredCodes() []string {
	return slices.Sorted(maps.Keys(unansweredCodes))
}

// CheckUnanswered verifies the record an unanswered session call's error carries:
// the version, no result digest, a Connect code, the digest of the request the caller
// sent, the record's own digest, and that it continues the chain the caller has seen
// (as CheckSessionCall). The call may have run; the record says only that it is in
// the chain.
func CheckUnanswered(req *plimsollv1.SessionRunRequest, m *plimsollv1.RunRecord, fingerprint string, prevSeq uint64, prev string) (*sandbox.RunRecord, error) {
	if m == nil {
		return nil, ErrNoRecord
	}
	r := FromWire(m)
	if err := checkUnanswered(SessionRunRequestDigest(req), sessionRequestKind(req), req.GetProtocol(), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), r, true); err != nil {
		return nil, err
	}
	switch {
	case r.Session != fingerprint:
		return nil, fmt.Errorf("%w: the record names session %s, the call was sent to %s", ErrChain, r.Session, fingerprint)
	case r.Sequence != prevSeq+1 || r.PreviousSHA256 != prev:
		return nil, fmt.Errorf("%w: call %d after %q, the caller's last was call %d, %q", ErrChain, r.Sequence, r.PreviousSHA256, prevSeq, prev)
	}
	return &r, nil
}

// CheckUnansweredExchange verifies an unanswered call's record against the stored
// request it came with (the call as a Run request, record.AsRunRequest), as
// CheckExchange does for an answered call: everything but its place in the chain, under
// any published version.
func CheckUnansweredExchange(req *plimsollv1.RunRequest, r sandbox.RunRecord) error {
	return checkUnanswered(RunRequestDigest(req), requestKind(req), req.GetProtocol(), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), r, false)
}

// checkUnanswered is what an unanswered record states that a caller can recompute
// from the request it sent, and that its evidence meets the request's floor and
// software rule, as check requires of an answered record. Live, the record must be the
// current version; stored, any published version that records an unanswered call.
func checkUnanswered(requestDigest, kind string, protocol uint32, floor string, rule sandbox.SoftwareRule, r sandbox.RunRecord, live bool) error {
	minimum, err := floorOf(floor)
	if err != nil {
		return err
	}
	s, err := readable(r.Version, live)
	if err != nil {
		return err
	}
	if err := s.recordsKind(kind, protocol, r.Version); err != nil {
		return err
	}
	if r.Unanswered == "" {
		return fmt.Errorf("%w: an unanswered call's record states a result or no error code", ErrMismatch)
	}
	if err := s.statesOnly(r); err != nil {
		return err
	}
	switch {
	case r.RequestSHA256 != requestDigest:
		return fmt.Errorf("%w: request digest %s, the request sent digests to %s", ErrMismatch, r.RequestSHA256, requestDigest)
	case r.SoftwareRuleID != rule.ID() || !rule.Allows(r.SoftwareIdentity):
		return fmt.Errorf("%w: the record's software rule is not the request's, or its software is not in it", ErrMismatch)
	}
	return sandbox.CheckResultIsolation(sandbox.ParseIsolationClass(r.Isolation), minimum)
}

// ErrVersion means a record uses an encoding this package does not read: one a newer
// plimsoll wrote, or, for a live answer, any but the current version. It is never a
// statement that the record was forged.
var ErrVersion = errors.New("record: unknown run record version")

// ErrNoRecord means an answered run came back without its record. A daemon states
// one on every answer, so the answer did not come from a daemon that keeps that
// promise; the run may have executed, so it is never a retry signal either.
var ErrNoRecord = errors.New("record: the response carries no run record")

// Check verifies the record a Run response carries against the request the
// caller sent and the response it received, and returns it. A response with no
// record is ErrNoRecord.
func Check(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) (*sandbox.RunRecord, error) {
	r, err := check(RunRequestDigest(req), requestKind(req), req.GetFiles(), req.GetProtocol(), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), resp, true)
	if err != nil {
		return nil, err
	}
	if r.Session != "" || r.Sequence != 0 || r.PreviousSHA256 != "" {
		return nil, fmt.Errorf("%w: a single run's record carries session fields", ErrMismatch)
	}
	return r, nil
}

// CheckExchange verifies a record against a stored exchange, single run or session
// call alike, under any published version: the digests, the evidence and the record's
// own digest. A session call's place in its chain needs the chain around it, which
// CheckSessionCall (live) and attest.VerifyBundle (stored) check.
func CheckExchange(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) (*sandbox.RunRecord, error) {
	return check(RunRequestDigest(req), requestKind(req), req.GetFiles(), req.GetProtocol(), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), resp, false)
}

// CheckSessionCall verifies a session call's record against the request sent and
// the response received, and that it continues the chain the caller has seen:
// the session's fingerprint, the next sequence number after prevSeq, and prev as
// the previous record's digest ("" and 0 before the first call). A gap means the
// daemon executed a call this caller did not make: someone else holds the
// session ID.
func CheckSessionCall(req *plimsollv1.SessionRunRequest, resp *plimsollv1.RunResponse, fingerprint string, prevSeq uint64, prev string) (*sandbox.RunRecord, error) {
	r, err := check(SessionRunRequestDigest(req), sessionRequestKind(req), req.GetFiles(), req.GetProtocol(), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), resp, true)
	if err != nil {
		return nil, err
	}
	switch {
	case r.Session != fingerprint:
		return nil, fmt.Errorf("%w: the record names session %s, the call was sent to %s", ErrChain, r.Session, fingerprint)
	case r.Sequence != prevSeq+1 || r.PreviousSHA256 != prev:
		return nil, fmt.Errorf("%w: call %d after %q, the caller's last was call %d, %q", ErrChain, r.Sequence, r.PreviousSHA256, prevSeq, prev)
	}
	return r, nil
}

// ErrChain means a session call's record does not continue the chain its caller
// has seen: another holder of the session ID made a call, or a record was
// dropped or replayed.
var ErrChain = errors.New("record: the session's chain of records is broken")

// check verifies everything a record states that the caller can recompute, given
// the request digest of what it sent, and that the evidence it states meets the
// request's isolation floor and software rule. A record below the floor is refused
// here, before anything signs or keeps it, as sandbox.ErrIsolationEvidenceMismatch.
// Live, the record must be the current version; stored, any published version that
// records an answered call, checked by that version's rules. files is a file call's
// request, whose operation its answer must be.
func check(requestDigest, kind string, files *plimsollv1.FilesRun, protocol uint32, floor string, rule sandbox.SoftwareRule, resp *plimsollv1.RunResponse, live bool) (*sandbox.RunRecord, error) {
	if err := rule.Validate(); err != nil {
		return nil, fmt.Errorf("%w: invalid software rule: %v", ErrMismatch, err)
	}
	minimum, err := floorOf(floor)
	if err != nil {
		return nil, err
	}
	if resp.GetRecord() == nil {
		return nil, ErrNoRecord
	}
	r := FromWire(resp.GetRecord())
	s, err := readable(r.Version, live)
	if err != nil {
		return nil, err
	}
	if r.Unanswered != "" {
		return nil, fmt.Errorf("%w: an answered call's record states an unanswered code", ErrMismatch)
	}
	if err := s.statesOnly(r); err != nil {
		return nil, err
	}
	if err := s.recordsKind(kind, protocol, r.Version); err != nil {
		return nil, err
	}
	if got := resultKind(resp); got == "" || got != kind {
		what := "no result"
		if got != "" {
			what = "a " + got + " result"
		}
		return nil, fmt.Errorf("%w: a %s request answered with %s", ErrMismatch, kind, what)
	}
	if kind == "files" {
		if err := filesAnswer(resp.GetFiles(), filesRunOp(files), true); err != nil {
			return nil, err
		}
	}
	switch {
	case r.RequestSHA256 != requestDigest:
		return nil, fmt.Errorf("%w: request digest %s, the request sent digests to %s", ErrMismatch, r.RequestSHA256, requestDigest)
	case r.ResultSHA256 != resultDigest(resp, s.result):
		return nil, fmt.Errorf("%w: result digest %s, the result received digests to %s under %s, the result domain of a version %d record", ErrMismatch, r.ResultSHA256, resultDigest(resp, s.result), s.result.domain(), r.Version)
	}
	if err := s.answerStates(r, resp); err != nil {
		return nil, err
	}
	if s.evidence && (r.SoftwareRuleID != rule.ID() || !rule.Allows(r.SoftwareIdentity)) {
		return nil, fmt.Errorf("%w: selected software or admission rule differs from the request and response", ErrMismatch)
	}
	if err := sandbox.CheckResultIsolation(sandbox.ParseIsolationClass(r.Isolation), minimum); err != nil {
		return nil, err
	}
	return &r, nil
}

// recordsKind is ErrMismatch for a call of a kind a record of this version cannot record:
// a files call, sent under protocol 9 or later, is recorded only by a version whose result
// domain covers the files kind (6 and later). No release wrote another.
func (s spec) recordsKind(kind string, protocol uint32, version int) error {
	if kind != "files" {
		return nil
	}
	if !slices.Contains(s.result.kinds(), kind) {
		return fmt.Errorf("%w: a version %d record cannot record a files call; its result domain %s does not cover the kind", ErrMismatch, version, s.result.domain())
	}
	if protocol < FirstFilesProtocol {
		return fmt.Errorf("%w: a files call states protocol %d; file calls start at protocol %d", ErrMismatch, protocol, FirstFilesProtocol)
	}
	return nil
}

// answerStates checks that a response states the evidence its record states, field by
// field as the record's version covers them: the provider and tier, the environment,
// the instance, the qualification, whether a waiting sandbox ran it, the daemon's version
// and the software identity.
func (s spec) answerStates(r sandbox.RunRecord, resp *plimsollv1.RunResponse) error {
	switch {
	case r.Provider != resp.GetSandbox() || r.Isolation != resp.GetIsolation():
		return fmt.Errorf("%w: the record names %s at %q, the response %s at %q", ErrMismatch, r.Provider, r.Isolation, resp.GetSandbox(), resp.GetIsolation())
	case s.evidence && r.Environment != resp.GetEnvironment():
		return fmt.Errorf("%w: record environment differs from response", ErrMismatch)
	case s.covers("instance") && r.Instance != resp.GetInstance():
		return fmt.Errorf("%w: the record's instance %q is not the response's", ErrMismatch, r.Instance)
	case s.covers("isolation_qualification") && r.IsolationQualification != resp.GetIsolationQualification():
		return fmt.Errorf("%w: the record's isolation qualification is not the response's", ErrMismatch)
	case s.covers("warm") && r.Warm != resp.GetWarm():
		return fmt.Errorf("%w: the record states warm %t, the response %t", ErrMismatch, r.Warm, resp.GetWarm())
	case s.covers("daemon_version") && r.DaemonVersion != resp.GetDaemonVersion():
		return fmt.Errorf("%w: the record's daemon version %q is not the response's %q", ErrMismatch, r.DaemonVersion, resp.GetDaemonVersion())
	case s.evidence && r.SoftwareIdentity != resp.GetSoftwareIdentity():
		return fmt.Errorf("%w: selected software or admission rule differs from the request and response", ErrMismatch)
	}
	return nil
}

// filesAnswer is ErrMismatch for a file call's result whose outcome, error and answer do
// not agree (docs/run-records.md, "A file call's answer"): completed with no error carries
// exactly one answer, of the operation the request asked (when known) and with no errno
// name; completed with an error carries none; timed_out, protocol_error and runner_failed
// carry no answer, no error and no errno name; no other outcome is a file call's. A
// read_many item carries its bytes or its error, never both, and no errno name without an
// error. A result with two answers cannot be held here (a oneof); the JSON clients refuse
// it while computing the digest, and protojson refuses to decode it.
func filesAnswer(f *plimsollv1.FilesResult, asked string, known bool) error {
	answer := filesAnswerOp(f)
	switch f.GetOutcome() {
	case plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED:
		switch {
		case f.GetError() != plimsollv1.FilesError_FILES_ERROR_UNSPECIFIED:
			if answer != "" {
				return fmt.Errorf("%w: a file call's result states the error %d and carries a %s answer", ErrMismatch, f.GetError(), answer)
			}
			return nil
		case f.GetErrno() != "":
			return fmt.Errorf("%w: a file call's result states no error and an errno name", ErrMismatch)
		case answer == "":
			return fmt.Errorf("%w: a completed file call's result states no error and carries no answer", ErrMismatch)
		case known && answer != asked:
			what := asked
			if what == "" {
				what = "no operation's"
			}
			return fmt.Errorf("%w: a %s call answered with a %s answer", ErrMismatch, what, answer)
		}
		for i, it := range f.GetReadMany().GetItems() {
			if it.GetError() != plimsollv1.FilesError_FILES_ERROR_UNSPECIFIED && (len(it.GetContent()) != 0 || it.GetSizeAtOpen() != 0) {
				return fmt.Errorf("%w: read_many item %d states the error %d and carries bytes", ErrMismatch, i, it.GetError())
			}
			if it.GetError() == plimsollv1.FilesError_FILES_ERROR_UNSPECIFIED && it.GetErrno() != "" {
				return fmt.Errorf("%w: read_many item %d states no error and an errno name", ErrMismatch, i)
			}
		}
		return nil
	case plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR, plimsollv1.ProjectOutcome_PROJECT_OUTCOME_RUNNER_FAILED:
		if answer != "" || f.GetError() != plimsollv1.FilesError_FILES_ERROR_UNSPECIFIED || f.GetErrno() != "" {
			return fmt.Errorf("%w: a file call that ended with the outcome %d states an error, an errno name or an answer", ErrMismatch, f.GetOutcome())
		}
		return nil
	}
	return fmt.Errorf("%w: the outcome %d is not one a file call has", ErrMismatch, f.GetOutcome())
}

// filesRunOp is the word of the operation a file call's request asks, "" for none;
// filesAnswerOp is that of the answer a file call's result carries.
func filesRunOp(f *plimsollv1.FilesRun) string {
	switch f.GetOp().(type) {
	case *plimsollv1.FilesRun_Stat:
		return "stat"
	case *plimsollv1.FilesRun_Read:
		return "read"
	case *plimsollv1.FilesRun_Write:
		return "write"
	case *plimsollv1.FilesRun_List:
		return "list"
	case *plimsollv1.FilesRun_ReadMany:
		return "read_many"
	case *plimsollv1.FilesRun_MakeDir:
		return "make_dir"
	case *plimsollv1.FilesRun_Remove:
		return "remove"
	case *plimsollv1.FilesRun_Rename:
		return "rename"
	}
	return ""
}

func filesAnswerOp(f *plimsollv1.FilesResult) string {
	switch f.GetAnswer().(type) {
	case *plimsollv1.FilesResult_Stat:
		return "stat"
	case *plimsollv1.FilesResult_Read:
		return "read"
	case *plimsollv1.FilesResult_Write:
		return "write"
	case *plimsollv1.FilesResult_List:
		return "list"
	case *plimsollv1.FilesResult_ReadMany:
		return "read_many"
	case *plimsollv1.FilesResult_MakeDir:
		return "make_dir"
	case *plimsollv1.FilesResult_Remove:
		return "remove"
	case *plimsollv1.FilesResult_Rename:
		return "rename"
	}
	return ""
}

// CheckLostAnswer verifies the answer an attach returned for a lost call
// (AttachSessionResponse.lost_answer) against that call's record, which the caller has
// already checked against its checkpoint and the request digest it named: the answer
// must carry exactly that record, which must be a live answered call's, and a result of
// a session call's kind whose result digest is the record's, stating the evidence the
// record states. The request itself is not at hand, only its digest, so the record's
// request digest and software rule stand for it; the record's tier was checked against
// the session's evidence with the record.
func CheckLostAnswer(resp *plimsollv1.RunResponse, lost *plimsollv1.RunRecord) error {
	if resp.GetRecord() == nil {
		return ErrNoRecord
	}
	if !proto.Equal(resp.GetRecord(), lost) {
		return fmt.Errorf("%w: the lost call's answer carries another record than the lost call's", ErrMismatch)
	}
	r := FromWire(lost)
	s, err := readable(r.Version, true)
	if err != nil {
		return err
	}
	if r.Unanswered != "" {
		return fmt.Errorf("%w: an answer came for a call whose record states it ended unanswered (%s)", ErrMismatch, r.Unanswered)
	}
	if err := s.statesOnly(r); err != nil {
		return err
	}
	switch kind := resultKind(resp); kind {
	case "javascript", "project", "cell":
	case "files":
		// The request is not at hand, so the operation it asked is not either: the answer
		// is checked against every other part of the rule.
		if err := filesAnswer(resp.GetFiles(), "", false); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: the lost call's answer holds no result of a session call's kind", ErrMismatch)
	}
	if got := resultDigest(resp, s.result); r.ResultSHA256 != got {
		return fmt.Errorf("%w: result digest %s, the lost call's answer digests to %s", ErrMismatch, r.ResultSHA256, got)
	}
	return s.answerStates(r, resp)
}

// floorOf reads a request's isolation floor as the daemon does: empty is none, and
// anything but process, container, kernel or vm is a request no daemon runs, so a
// record for it is refused.
func floorOf(floor string) (sandbox.IsolationClass, error) {
	if floor == "" {
		return sandbox.IsolationUnknown, nil
	}
	if c := sandbox.ParseIsolationClass(floor); c >= sandbox.IsolationProcess {
		return c, nil
	}
	return sandbox.IsolationUnknown, fmt.Errorf("%w: the request's isolation floor %q is not one a daemon accepts", ErrMismatch, floor)
}
