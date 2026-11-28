package record

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// stampedAs is resp with a record of the given version whose result digest is
// resultSHA256, its own digest sealed again, as a daemon of that version would state it.
func stampedAs(version int, requestSHA256, resultSHA256 string, resp *plimsollv1.RunResponse, session bool) *plimsollv1.RunResponse {
	r := sandbox.RunRecord{
		Version: version, RequestSHA256: requestSHA256, ResultSHA256: resultSHA256,
		Provider: resp.GetSandbox(), Isolation: resp.GetIsolation(), DaemonVersion: resp.GetDaemonVersion(),
		Started: time.UnixMilli(1790000000000), Ended: time.UnixMilli(1790000000012),
	}
	if session {
		r.Session, r.Sequence = SessionFingerprint("00112233445566778899aabbccddeeff"), 1
	}
	r.SHA256 = Digest(r)
	out := proto.Clone(resp).(*plimsollv1.RunResponse)
	out.Record = ToWire(r)
	return out
}

// The record's version fixes the result domain: a version 6 record states the result
// digest under plimsoll.run-result.v2, and one that names version 6 but states the digest
// under plimsoll.run-result.v1 (what a version 5 daemon computed) is refused, live and as
// stored evidence, whose fields and own digest are otherwise in order.
func TestVersion6RecordHashesItsResultUnderTheSecondDomain(t *testing.T) {
	req, resp := jsRequest(), jsResponse()
	v1, v2 := ResultDigestFor(resp, 5), ResultDigestFor(resp, 6)
	if v1 == v2 || ResultDigest(resp) != v2 {
		t.Fatalf("the two domains give %s and %s, the current version %s", v1, v2, ResultDigest(resp))
	}
	good := stampedAs(6, RunRequestDigest(req), v2, resp, false)
	if _, err := Check(req, good); err != nil {
		t.Fatalf("a version 6 record of the result under v2: %v", err)
	}
	forged := stampedAs(6, RunRequestDigest(req), v1, resp, false)
	if _, err := Check(req, forged); !errors.Is(err, ErrMismatch) {
		t.Errorf("live, a version 6 record of the result under v1: %v, want ErrMismatch", err)
	}
	if _, err := CheckExchange(req, forged); !errors.Is(err, ErrMismatch) {
		t.Errorf("stored, a version 6 record of the result under v1: %v, want ErrMismatch", err)
	}
}

// A version 5 exchange, as a daemon of v0.28.0 to v0.29.x answered, still verifies as
// stored evidence, its result under plimsoll.run-result.v1; a live answer of version 5 is
// refused as a version, never as a forgery.
func TestVersion5EvidenceStillVerifies(t *testing.T) {
	req, resp := jsRequest(), jsResponse()
	old := stampedAs(5, RunRequestDigest(req), ResultDigestFor(resp, 5), resp, false)
	if _, err := CheckExchange(req, old); err != nil {
		t.Fatalf("a stored version 5 exchange: %v", err)
	}
	if _, err := Check(req, old); !errors.Is(err, ErrVersion) {
		t.Errorf("a live version 5 answer: %v, want ErrVersion", err)
	}
	// Its result digest under v2 is not what a version 5 record states.
	if _, err := CheckExchange(req, stampedAs(5, RunRequestDigest(req), ResultDigestFor(resp, 6), resp, false)); !errors.Is(err, ErrMismatch) {
		t.Errorf("a version 5 record of the result under v2: %v, want ErrMismatch", err)
	}
}

// A file call's record: from protocol 9, under record version 6. Every operation's request
// and answer in the golden file checks as a session call; a record of a version before 6,
// whose result domain does not cover the kind, is refused even with every digest matching,
// and so is a file call stating protocol 8, whose request domain does not cover it.
func TestFilesCallsAreRecordedFromVersion6AndProtocol9(t *testing.T) {
	ops := []string{"stat", "read", "write", "list", "read_many", "make_dir", "remove", "rename"}
	for _, op := range ops {
		req := fixture("files "+op+" request", &plimsollv1.SessionRunRequest{})
		resp := fixture("files "+op+" result", &plimsollv1.RunResponse{})
		if req.GetProtocol() != FirstFilesProtocol || req.GetFiles() == nil || resp.GetFiles() == nil {
			t.Fatalf("%s: the golden request states protocol %d and files %v, the answer files %v", op, req.GetProtocol(), req.GetFiles() != nil, resp.GetFiles() != nil)
		}
		live := stampedAs(6, SessionRunRequestDigest(req), ResultDigest(resp), resp, true)
		if _, err := CheckSessionCall(req, live, SessionFingerprint(req.GetSessionId()), 0, ""); err != nil {
			t.Errorf("%s: a version 6 record of a file call: %v", op, err)
		}
		if _, err := CheckExchange(AsRunRequest(req), live); err != nil {
			t.Errorf("%s: the stored form of a file call: %v", op, err)
		}
		if err := CheckLostAnswer(live, live.GetRecord()); err != nil {
			t.Errorf("%s: a lost file call's answer: %v", op, err)
		}
		old := stampedAs(5, SessionRunRequestDigest(req), ResultDigestFor(resp, 5), resp, true)
		if _, err := CheckExchange(AsRunRequest(req), old); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: a version 5 record of a file call: %v, want ErrMismatch", op, err)
		}
	}
	req := fixture("files request stating protocol 8", &plimsollv1.SessionRunRequest{})
	resp := fixture("files stat result", &plimsollv1.RunResponse{})
	if _, err := CheckExchange(AsRunRequest(req), stampedAs(6, SessionRunRequestDigest(req), ResultDigest(resp), resp, true)); !errors.Is(err, ErrMismatch) {
		t.Errorf("a file call stating protocol 8: %v, want ErrMismatch", err)
	}
	// Under plimsoll.run-request.v2 a files payload is no kind, the encoding of a request
	// with no payload; under v3 it is the files kind.
	empty := proto.Clone(req).(*plimsollv1.SessionRunRequest)
	empty.Payload = nil
	if SessionRunRequestDigest(req) != SessionRunRequestDigest(empty) {
		t.Errorf("a protocol 8 files request digests as something other than no kind")
	}
	at9 := proto.Clone(req).(*plimsollv1.SessionRunRequest)
	at9.Protocol = FirstFilesProtocol
	empty.Protocol = FirstFilesProtocol
	if SessionRunRequestDigest(at9) == SessionRunRequestDigest(empty) {
		t.Errorf("a protocol 9 files request digests as no kind")
	}
	// Under plimsoll.run-result.v1 a files result is no kind.
	none := &plimsollv1.RunResponse{Sandbox: resp.GetSandbox(), Isolation: resp.GetIsolation()}
	if ResultDigestFor(resp, 5) != ResultDigestFor(none, 5) || ResultDigest(resp) == ResultDigest(none) {
		t.Errorf("a files result is no kind under v1 and the files kind under v2")
	}
}

// The files answer rule (docs/run-records.md, "A file call's answer") holds on every path
// a record is checked with its request, live and stored: an answer of another operation
// than asked, or one beside an error, is refused though every digest matches. The shared
// cases (files-answer) hold the session call's and the lost answer's.
func TestFilesAnswerRuleOnEveryPathWithTheRequest(t *testing.T) {
	req := fixture("files stat request", &plimsollv1.SessionRunRequest{})
	other := fixture("files read result", &plimsollv1.RunResponse{})
	beside := proto.Clone(fixture("files stat result", &plimsollv1.RunResponse{})).(*plimsollv1.RunResponse)
	beside.GetFiles().Error, beside.GetFiles().Errno = plimsollv1.FilesError_FILES_ERROR_NOT_FOUND, "ENOENT"
	for name, resp := range map[string]*plimsollv1.RunResponse{"another operation's answer": other, "an answer beside an error": beside} {
		live := stampedAs(6, SessionRunRequestDigest(req), ResultDigest(resp), resp, true)
		if _, err := CheckSessionCall(req, live, SessionFingerprint(req.GetSessionId()), 0, ""); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s, a session call: %v, want ErrMismatch", name, err)
		}
		if _, err := CheckExchange(AsRunRequest(req), live); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s, stored: %v, want ErrMismatch", name, err)
		}
		single := stampedAs(6, RunRequestDigest(AsRunRequest(req)), ResultDigest(resp), resp, false)
		if _, err := Check(AsRunRequest(req), single); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s, a single run: %v, want ErrMismatch", name, err)
		}
	}
}

// A file call's request and answer carry the operation: an answer naming another operation
// than asked, or a request of one operation hashed as another, moves a digest, so a record
// of one cannot stand for the other.
func TestFilesOperationsAreDistinctInTheDigests(t *testing.T) {
	seen := map[string]string{}
	for _, name := range []string{"stat", "read", "write", "list", "read_many", "make_dir", "remove", "rename"} {
		for _, side := range []string{"request", "result"} {
			var d string
			if side == "request" {
				d = SessionRunRequestDigest(fixture("files "+name+" request", &plimsollv1.SessionRunRequest{}))
			} else {
				d = ResultDigest(fixture("files "+name+" result", &plimsollv1.RunResponse{}))
			}
			if other, ok := seen[d]; ok {
				t.Errorf("files %s %s digests as %s", name, side, other)
			}
			seen[d] = name + " " + side
		}
	}
	// The three answers with nothing in them differ by the operation's word alone.
	a := fixture("files make_dir result", &plimsollv1.RunResponse{})
	b := proto.Clone(a).(*plimsollv1.RunResponse)
	b.GetFiles().Answer = &plimsollv1.FilesResult_Remove{Remove: &plimsollv1.FilesDone{}}
	if ResultDigest(a) == ResultDigest(b) {
		t.Errorf("make_dir and remove answers digest alike")
	}
}
