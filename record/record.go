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
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/softwarewire"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Version is the encoding version of every record this package writes: every field,
// every time. An unanswered session call's record is the same encoding with the result
// digest empty and unanswered set. A live answer must carry it; stored evidence may carry
// any published version.
const Version = 4

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
	// From v0.23.0: both kinds, and the instance.
	4: {fields: []string{"request_sha256", "result_sha256", "unanswered", "provider", "isolation", "environment",
		"policy", "software_identity", "software_rule_id", "instance", "started_unix_ms", "ended_unix_ms", "session",
		"sequence", "previous_sha256"}, answered: true, unanswered: true, evidence: true},
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
}

func (s spec) covers(field string) bool { return slices.Contains(s.fields, field) }

// recordField is one field a record digest can cover: how it is encoded, and whether a
// record states it (a field a version does not cover must be empty, or the record would
// state evidence nothing signed).
type recordField struct {
	put func(*encoder, string, sandbox.RunRecord)
	set func(sandbox.RunRecord) bool
}

var recordFields = map[string]recordField{
	"request_sha256":    {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.RequestSHA256) }, func(r sandbox.RunRecord) bool { return r.RequestSHA256 != "" }},
	"result_sha256":     {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.ResultSHA256) }, func(r sandbox.RunRecord) bool { return r.ResultSHA256 != "" }},
	"unanswered":        {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Unanswered) }, func(r sandbox.RunRecord) bool { return r.Unanswered != "" }},
	"provider":          {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Provider) }, func(r sandbox.RunRecord) bool { return r.Provider != "" }},
	"isolation":         {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Isolation) }, func(r sandbox.RunRecord) bool { return r.Isolation != "" }},
	"environment":       {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Environment) }, func(r sandbox.RunRecord) bool { return r.Environment != "" }},
	"policy":            {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Policy) }, func(r sandbox.RunRecord) bool { return r.Policy != "" }},
	"software_identity": {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.SoftwareIdentity) }, func(r sandbox.RunRecord) bool { return r.SoftwareIdentity != "" }},
	"software_rule_id":  {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.SoftwareRuleID) }, func(r sandbox.RunRecord) bool { return r.SoftwareRuleID != "" }},
	"instance":          {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Instance) }, func(r sandbox.RunRecord) bool { return r.Instance != "" }},
	"started_unix_ms":   {func(e *encoder, n string, r sandbox.RunRecord) { e.int(n, r.Started.UnixMilli()) }, func(r sandbox.RunRecord) bool { return !r.Started.IsZero() }},
	"ended_unix_ms":     {func(e *encoder, n string, r sandbox.RunRecord) { e.int(n, r.Ended.UnixMilli()) }, func(r sandbox.RunRecord) bool { return !r.Ended.IsZero() }},
	"session":           {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.Session) }, func(r sandbox.RunRecord) bool { return r.Session != "" }},
	"sequence":          {func(e *encoder, n string, r sandbox.RunRecord) { e.uint(n, r.Sequence) }, func(r sandbox.RunRecord) bool { return r.Sequence != 0 }},
	"previous_sha256":   {func(e *encoder, n string, r sandbox.RunRecord) { e.str(n, r.PreviousSHA256) }, func(r sandbox.RunRecord) bool { return r.PreviousSHA256 != "" }},
}

// Each encoding opens with its domain string, so a digest of one kind can never
// equal a digest of another, whatever the fields hold. A request sent under protocol 1
// (v0.10.0 to v0.11.1, read for their records) has the first request encoding: no
// software rule.
const (
	requestDomain   = "plimsoll.run-request.v2"
	requestDomainV1 = "plimsoll.run-request.v1"
	resultDomain    = "plimsoll.run-result.v1"
)

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
		m.GetSoftwareRule(), m.GetJavascript(), m.GetProject(), m.GetModule(), m.GetCell())
}

// SessionRunRequestDigest is the request digest of a session call: the same
// fields as a Run request's, so a call and a run of the same payload share a
// digest. The session ID is left out: it is a capability, and the record carries
// the session's fingerprint instead.
func SessionRunRequestDigest(m *plimsollv1.SessionRunRequest) string {
	return requestDigest(m.GetProtocol(), m.GetMinimumIsolation(), m.GetTimeoutMs(),
		m.GetSoftwareRule(), m.GetJavascript(), m.GetProject(), nil, m.GetCell())
}

// AsRunRequest is a session call's request as the Run request with the same
// digest, without the session ID: the form a harness stores and replays. A cell's
// stored form is a Run request with a cell payload, which Run itself refuses.
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
	}
	return out
}

func requestDigest(protocol uint32, floor string, timeoutMs int32, rule *plimsollv1.SoftwareRule,
	js *plimsollv1.JavaScriptRun, p *plimsollv1.ProjectRun, mod *plimsollv1.ModuleRun, cell *plimsollv1.CellRun) string {
	first := protocol < 2
	domain := requestDomain
	if first {
		domain = requestDomainV1
	}
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
	default:
		e.str("kind", "")
	}
	return e.sum()
}

// ResultDigest is the result digest of a Run response: the result as sent, which
// is what a replay of a deterministic workload reproduces. Durations are left out
// (they differ on every run), and so is advice, which is analysis of the run
// rather than its output. Provider and tier are the record's evidence fields.
func ResultDigest(m *plimsollv1.RunResponse) string {
	e := newEncoder(resultDomain)
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
	default:
		e.str("kind", "")
	}
	return e.sum()
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

// readable returns the spec of a record version a verifier accepts: every published
// version for stored evidence, Version alone for a live answer.
func readable(version int, live bool) (spec, error) {
	s, ok := published[version]
	switch {
	case !ok:
		return spec{}, fmt.Errorf("%w: version %d; this verifier reads versions %s, so a newer plimsoll wrote it: upgrade the verifier", ErrVersion, version, publishedList())
	case live && version != Version:
		return spec{}, fmt.Errorf("%w: the daemon answered with version %d; this client requires version %d of a live answer", ErrVersion, version, Version)
	}
	return s, nil
}

// statesOnly checks that r is a kind of call its version records, states no field the
// version does not cover, names a typed instance, and matches its own digest.
func (s spec) statesOnly(r sandbox.RunRecord) error {
	switch unanswered := r.Unanswered != ""; {
	case unanswered && !s.unanswered:
		return fmt.Errorf("%w: a version %d record cannot record an unanswered call", ErrMismatch, r.Version)
	case !unanswered && !s.answered:
		return fmt.Errorf("%w: a version %d record records only an unanswered call", ErrMismatch, r.Version)
	case unanswered == (r.ResultSHA256 != ""):
		return fmt.Errorf("%w: a record states a result or, for an unanswered call, an error code, exactly one", ErrMismatch)
	case unanswered && !unansweredCodes[r.Unanswered]:
		return fmt.Errorf("%w: an unanswered call's record names %q, not a Connect code", ErrMismatch, r.Unanswered)
	case !sandbox.ValidInstance(r.Instance):
		return fmt.Errorf("%w: the record's instance %q is not a typed reference", ErrMismatch, r.Instance)
	}
	for name, f := range recordFields {
		if !s.covers(name) && f.set(r) {
			return fmt.Errorf("%w: a version %d record does not cover %s, so it cannot state one", ErrMismatch, r.Version, name)
		}
	}
	if d := Digest(r); r.SHA256 != d {
		return fmt.Errorf("%w: record digest %s, its fields digest to %s", ErrMismatch, r.SHA256, d)
	}
	return nil
}

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
		Version:          uint32(r.Version),
		RequestSha256:    r.RequestSHA256,
		ResultSha256:     r.ResultSHA256,
		Provider:         r.Provider,
		Isolation:        r.Isolation,
		Environment:      r.Environment,
		SoftwareIdentity: r.SoftwareIdentity,
		SoftwareRuleId:   r.SoftwareRuleID,
		Policy:           r.Policy,
		StartedUnixMs:    r.Started.UnixMilli(),
		EndedUnixMs:      r.Ended.UnixMilli(),
		Session:          r.Session,
		Sequence:         r.Sequence,
		PreviousSha256:   r.PreviousSHA256,
		Unanswered:       r.Unanswered,
		Instance:         r.Instance,
		RecordSha256:     r.SHA256,
	}
}

// FromWire reads a record off the wire, unchecked.
func FromWire(m *plimsollv1.RunRecord) sandbox.RunRecord {
	return sandbox.RunRecord{
		Version:          int(m.GetVersion()),
		RequestSHA256:    m.GetRequestSha256(),
		ResultSHA256:     m.GetResultSha256(),
		Provider:         m.GetProvider(),
		Isolation:        m.GetIsolation(),
		Environment:      m.GetEnvironment(),
		SoftwareIdentity: m.GetSoftwareIdentity(),
		SoftwareRuleID:   m.GetSoftwareRuleId(),
		Policy:           m.GetPolicy(),
		Started:          time.UnixMilli(m.GetStartedUnixMs()).UTC(),
		Ended:            time.UnixMilli(m.GetEndedUnixMs()).UTC(),
		Session:          m.GetSession(),
		Sequence:         m.GetSequence(),
		PreviousSHA256:   m.GetPreviousSha256(),
		Unanswered:       m.GetUnanswered(),
		Instance:         m.GetInstance(),
		SHA256:           m.GetRecordSha256(),
	}
}

// ErrMismatch means a record does not match the request and response it came
// with: a digest, the evidence, or the record's own digest differs from what the
// caller computes. The run may have executed, so it is never a retry signal.
var ErrMismatch = errors.New("record: the run record does not match the request and result it came with")

// Stamp completes r as the record of resp and returns it in wire form: the
// version, the result's digest, the evidence resp carries (provider, tier, outer
// environment, selected software identity and instance) and the record's own digest. The
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
	r.SHA256 = Digest(r)
	return ToWire(r)
}

// StampUnanswered completes r as the record of a session call that may have run but
// ended in the error whose Connect code is code: no result digest, the code, and the
// record's own digest. The caller sets everything else, the evidence included, since
// there is no response to read it from.
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
	if err := checkUnanswered(SessionRunRequestDigest(req), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), r, true); err != nil {
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
	return checkUnanswered(RunRequestDigest(req), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), r, false)
}

// checkUnanswered is what an unanswered record states that a caller can recompute
// from the request it sent, and that its evidence meets the request's floor and
// software rule, as check requires of an answered record. Live, the record must be the
// current version; stored, any published version that records an unanswered call.
func checkUnanswered(requestDigest, floor string, rule sandbox.SoftwareRule, r sandbox.RunRecord, live bool) error {
	minimum, err := floorOf(floor)
	if err != nil {
		return err
	}
	s, err := readable(r.Version, live)
	if err != nil {
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
	r, err := check(RunRequestDigest(req), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), resp, true)
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
	return check(RunRequestDigest(req), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), resp, false)
}

// CheckSessionCall verifies a session call's record against the request sent and
// the response received, and that it continues the chain the caller has seen:
// the session's fingerprint, the next sequence number after prevSeq, and prev as
// the previous record's digest ("" and 0 before the first call). A gap means the
// daemon executed a call this caller did not make: someone else holds the
// session ID.
func CheckSessionCall(req *plimsollv1.SessionRunRequest, resp *plimsollv1.RunResponse, fingerprint string, prevSeq uint64, prev string) (*sandbox.RunRecord, error) {
	r, err := check(SessionRunRequestDigest(req), req.GetMinimumIsolation(), softwarewire.FromWire(req.GetSoftwareRule()), resp, true)
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
// records an answered call, checked by that version's rules.
func check(requestDigest, floor string, rule sandbox.SoftwareRule, resp *plimsollv1.RunResponse, live bool) (*sandbox.RunRecord, error) {
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
	switch {
	case r.RequestSHA256 != requestDigest:
		return nil, fmt.Errorf("%w: request digest %s, the request sent digests to %s", ErrMismatch, r.RequestSHA256, requestDigest)
	case r.ResultSHA256 != ResultDigest(resp):
		return nil, fmt.Errorf("%w: result digest %s, the result received digests to %s", ErrMismatch, r.ResultSHA256, ResultDigest(resp))
	case r.Provider != resp.GetSandbox() || r.Isolation != resp.GetIsolation():
		return nil, fmt.Errorf("%w: the record names %s at %q, the response %s at %q", ErrMismatch, r.Provider, r.Isolation, resp.GetSandbox(), resp.GetIsolation())
	case s.evidence && r.Environment != resp.GetEnvironment():
		return nil, fmt.Errorf("%w: record environment differs from response", ErrMismatch)
	case s.covers("instance") && r.Instance != resp.GetInstance():
		return nil, fmt.Errorf("%w: the record's instance %q is not the response's", ErrMismatch, r.Instance)
	case s.evidence && (r.SoftwareIdentity != resp.GetSoftwareIdentity() || r.SoftwareRuleID != rule.ID() || !rule.Allows(r.SoftwareIdentity)):
		return nil, fmt.Errorf("%w: selected software or admission rule differs from the request and response", ErrMismatch)
	}
	if err := sandbox.CheckResultIsolation(sandbox.ParseIsolationClass(r.Isolation), minimum); err != nil {
		return nil, err
	}
	return &r, nil
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
