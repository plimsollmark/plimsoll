package clientsuite

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/internal/softwarewire"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandboxtest"
)

// The daemons and vectors every client's attach checks share (session reattach, steps R2
// to R4 of the sessions builds plan): the Go client's tests call ServeReattach and
// ServeAttachLiar, and the table serves both for the Python and TypeScript suites.

// ReattachToken is the one bearer token the reattach daemon and the attach liar accept.
// Attach needs an authenticated caller: open development mode refuses it.
const ReattachToken = "client-suite-reattach-token"

// DropAnswerTrace is the trace ID of a session call the reattach daemon runs and then
// cuts the connection of, so the call ran and its answer never reaches the client.
const DropAnswerTrace = "drop-answer"

// HeadMismatchTrace is the trace ID of a session call the attach liar sends on to the real
// handler with its head's count raised by one and another last record digest, so the daemon
// refuses it as a head mismatch
// (not dispatched, reason request, the daemon's head as a SessionHeadMismatch detail): the
// refusal a client gets when another holder of the session ran a call between its own.
// A client must stop the session: its next call is refused before it is sent. The liar
// counts the calls that reach it (GET /test/session-calls?session=<fingerprint>).
const HeadMismatchTrace = "head-mismatch"

// CheckpointVectors is the shared checkpoint vectors: a JSON object whose "valid" and
// "invalid" lists hold {"name", "json"}, every client parsing each valid text into a
// checkpoint and refusing each invalid one. The reattach daemon serves it at GET
// /test/checkpoint-vectors.
//
//go:embed testdata/checkpoint-vectors.json
var CheckpointVectors []byte

// Reattach is a served reattach daemon.
type Reattach struct {
	URL      string
	Token    string
	Provider *sandboxtest.Sessions
}

// ProviderCalls is how many snippets and cells the provider ran, across its sessions.
func (d Reattach) ProviderCalls() int {
	n := 0
	for _, s := range d.Provider.Opened() {
		n += s.Calls()
	}
	return n
}

// ServeReattach serves the real handler over the in-memory session provider, behind
// ReattachToken, for t. A SessionRun whose trace ID is DropAnswerTrace runs, and then its
// connection is cut before any byte of the answer is written. GET /test/calls answers
// {"calls": n} with ProviderCalls; GET /test/checkpoint-vectors answers with
// CheckpointVectors.
func ServeReattach(t *testing.T) Reattach {
	t.Helper()
	d := Reattach{Token: ReattachToken, Provider: &sandboxtest.Sessions{}}
	svc := sessionService(d.Provider, rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute, KeptAnswerBytes: keptAnswerBytes, KeptAnswersTotalBytes: keptAnswersTotalBytes})
	d.URL = serveDropping(t, svc, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /test/calls", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]int{"calls": d.ProviderCalls()})
		})
		mux.HandleFunc("GET /test/checkpoint-vectors", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(CheckpointVectors)
		})
	})
	return d
}

// keptAnswerBytes is the served daemons' cap on a kept answer: the daemon's default, so a
// lost call's answer comes back on an attach across its gap.
const keptAnswerBytes = 4 << 20

// keptAnswersTotalBytes is the served daemons' bound on every session's kept answers
// together: the daemon's default.
const keptAnswersTotalBytes = 64 << 20

func serveReattach(t *testing.T) []string {
	d := ServeReattach(t)
	return []string{d.URL, d.Token}
}

// serveDropping serves h behind ReattachToken with the dropped-answer rule in front.
func serveDropping(t *testing.T, h plimsollv1connect.SandboxServiceHandler, extra func(*http.ServeMux)) string {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := rpc.NewHandler(h, connect.WithInterceptors(rpc.AuthInterceptor(verifier{token: ReattachToken})))
	mux.Handle(path, dropAnswers(handler))
	if extra != nil {
		extra(mux)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// dropAnswers runs a SessionRun whose trace ID is DropAnswerTrace to its end and then
// closes its connection, so the client gets no answer at all; every other request
// passes through. The request is read as Connect sends it, binary or JSON.
func dropAnswers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/SessionRun") {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if sessionRunTrace(r.Header.Get("Content-Type"), body) != DropAnswerTrace {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(httptest.NewRecorder(), r)
		if conn, _, herr := w.(http.Hijacker).Hijack(); herr == nil {
			_ = conn.Close()
		}
	})
}

func sessionRunTrace(contentType string, body []byte) string {
	media, _, _ := mime.ParseMediaType(contentType)
	var m plimsollv1.SessionRunRequest
	switch media {
	case "application/proto":
		if proto.Unmarshal(body, &m) != nil {
			return ""
		}
	case "application/json":
		if (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &m) != nil {
			return ""
		}
	default:
		return ""
	}
	return m.GetTraceId()
}

// --- the attach liar -----------------------------------------------------------------

// AttachForgeries names the attach answers the attach liar forges, each the honest answer
// with one thing changed, which a client must refuse without closing the session. An
// attach whose trace ID is "forge-" and one of these gets it. The liar serves the list at
// GET /test/forgeries.
var AttachForgeries = []string{
	"no-info",               // no session in the answer
	"no-checkpoint",         // no checkpoint in the answer
	"fingerprint",           // another session's fingerprint
	"session-id",            // an ID whose SHA-256 is not the fingerprint
	"generation",            // a generation two past the checkpoint's, in both places
	"info-generation",       // a session whose generation is not its returned checkpoint's
	"checkpoint-generation", // a returned checkpoint whose generation is not the session's
	"calls",
	"last",
	"provider",
	"isolation",     // a stronger tier than the checkpoint's
	"weaker",        // the tier process, below the session's floor
	"identity",      // other software
	"qualification", // another sentence beside the tier
	"floor",         // another floor stated at open
	"rule",          // another software rule stated at open
	"expiry",
	"idle",
	"unasked-lost-record", // the honest answer, carrying the session's last record as a lost call's
	"unasked-lost-answer", // the honest answer, carrying the session's last answer as a lost call's, with no lost record
}

// AttachLostForgeries names the explained-gap answers the attach liar forges, for an attach
// that names a lost call (lost_request_sha256) from a checkpoint one call behind the
// session's last record: each is the honest answer (forge-lost-none) with one thing
// changed. A record changed and sealed again has its own digest recomputed, so only the
// check the forgery names can catch it. The liar serves the list at GET /test/lost-forgeries.
var AttachLostForgeries = []string{
	"lost-missing",    // no lost record, the head one call ahead
	"lost-unsealed",   // the record's end time changed, its digest not recomputed
	"lost-request",    // another request digest, sealed again
	"lost-previous",   // a record that does not follow the checkpoint, sealed again
	"lost-sequence",   // a record numbered past the checkpoint's next call, sealed again
	"lost-session",    // another session's record, sealed again
	"lost-evidence",   // a record naming another provider than the session stated at open, sealed again
	"lost-version",    // a version 4 record, sealed again
	"lost-head",       // a new head whose last record is not the lost record
	"lost-head-calls", // a new head that counts the checkpoint's calls, not one more
	// A record states a result digest or an unanswered code, exactly one, and the code is
	// one of the closed set (record.UnansweredCodes): an adapter builds what it tells a
	// model from which of the two a lost record states (finding release-76, 2026-11-19).
	"lost-result-and-code", // a result digest and an unanswered code, sealed again
	"lost-no-result",       // neither a result digest nor an unanswered code, sealed again
	"lost-unknown-code",    // an unanswered code outside the closed set, sealed again
	// The lost call's answer (AttachSessionResponse.lost_answer) is believed only when it
	// carries the lost record and its result digests to the record's.
	"lost-answer-result", // the answer's output changed, so its result digest is not the record's
	"lost-answer-record", // the answer carrying another record than the lost one (its end time changed, sealed again)
}

// AttachLiar is a served attach liar.
type AttachLiar struct {
	URL   string
	Token string
	liar  *attachLiar
}

// Closes is how many CloseSession requests reached the liar for the session with this
// fingerprint.
func (d AttachLiar) Closes(fingerprint string) int {
	d.liar.mu.Lock()
	defer d.liar.mu.Unlock()
	return d.liar.closes[fingerprint]
}

// SessionCalls is how many SessionRun requests reached the liar for the session with this
// fingerprint, refused ones included.
func (d AttachLiar) SessionCalls(fingerprint string) int {
	d.liar.mu.Lock()
	defer d.liar.mu.Unlock()
	return d.liar.calls[fingerprint]
}

// Forge is the liar's answer to an attach whose trace ID is "forge-"+name, built from the
// session's open answer and the attach's checkpoint, without touching the session: the
// honest answer for name "none", or nil when the liar did not open that session.
func (d AttachLiar) Forge(req *plimsollv1.AttachSessionRequest, name string) *plimsollv1.AttachSessionResponse {
	return d.liar.forge(req, name)
}

// ServeAttachLiar serves the reattach daemon's handler (its own provider, behind
// ReattachToken) with AttachSession answered by the liar: an attach whose trace ID is
// "forge-<name>" (AttachForgeries, or "none") gets the answer the daemon would give with
// that one thing forged, and the session is left as it was, so one checkpoint serves for
// every forgery; one whose trace ID is "forge-lost-<name>" (AttachLostForgeries, or
// "lost-none") gets the explained-gap answer the daemon would give an attach one call
// behind the session's last record, forged the same way; any other attach reaches the
// real handler. GET /test/forgeries and GET /test/lost-forgeries answer with the lists;
// GET /test/closes?session=<fingerprint> answers {"closes": n}.
func ServeAttachLiar(t *testing.T) AttachLiar {
	t.Helper()
	l := &attachLiar{
		SandboxService: sessionService(&sandboxtest.Sessions{}, rpc.SessionConfig{MaxSessions: 16, Lifetime: time.Minute, IdleTimeout: time.Minute, KeptAnswerBytes: keptAnswerBytes, KeptAnswersTotalBytes: keptAnswersTotalBytes}),
		opened:         map[string]*plimsollv1.OpenSessionResponse{},
		closes:         map[string]int{},
		last:           map[string]*plimsollv1.RunRecord{},
		answers:        map[string]*plimsollv1.RunResponse{},
		calls:          map[string]int{},
	}
	d := AttachLiar{Token: ReattachToken, liar: l}
	d.URL = serveDropping(t, l, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /test/forgeries", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(AttachForgeries)
		})
		mux.HandleFunc("GET /test/lost-forgeries", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(AttachLostForgeries)
		})
		mux.HandleFunc("GET /test/closes", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]int{"closes": d.Closes(r.URL.Query().Get("session"))})
		})
		mux.HandleFunc("GET /test/session-calls", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]int{"calls": d.SessionCalls(r.URL.Query().Get("session"))})
		})
	})
	return d
}

func serveAttachLiar(t *testing.T) []string { return []string{ServeAttachLiar(t).URL} }

type attachLiar struct {
	*rpc.SandboxService
	mu     sync.Mutex
	opened map[string]*plimsollv1.OpenSessionResponse // by fingerprint
	closes map[string]int
	last   map[string]*plimsollv1.RunRecord // each session's last record, answered or not
	// answers is each session's last answer, absent after an unanswered call.
	answers map[string]*plimsollv1.RunResponse
	calls   map[string]int // the session calls that reached the liar, by fingerprint
}

// SessionRun keeps each session's last record, from the answer or, for a call that may
// have run, from the error's unanswered record (a dropped answer's included: the drop is
// in front of this handler), and its last answer. A call whose trace ID is
// HeadMismatchTrace goes on with its head's count raised by one.
func (l *attachLiar) SessionRun(ctx context.Context, req *connect.Request[plimsollv1.SessionRunRequest]) (*connect.Response[plimsollv1.SessionRunResponse], error) {
	fingerprint := record.SessionFingerprint(req.Msg.GetSessionId())
	l.mu.Lock()
	l.calls[fingerprint]++
	l.mu.Unlock()
	if req.Msg.GetTraceId() == HeadMismatchTrace && req.Msg.GetHead() != nil {
		req.Msg.Head.Calls++
		req.Msg.Head.LastRecordSha256 = record.SessionFingerprint("a record this client never saw")
	}
	resp, err := l.SandboxService.SessionRun(ctx, req)
	var rec *plimsollv1.RunRecord
	if err == nil {
		rec = resp.Msg.GetRun().GetRecord()
		l.mu.Lock()
		l.answers[fingerprint] = proto.Clone(resp.Msg.GetRun()).(*plimsollv1.RunResponse)
		l.mu.Unlock()
	} else {
		var ce *connect.Error
		if errors.As(err, &ce) {
			for _, d := range ce.Details() {
				if v, derr := d.Value(); derr == nil {
					if u, ok := v.(*plimsollv1.UnansweredCall); ok {
						rec = u.GetRecord()
					}
				}
			}
		}
	}
	if rec != nil {
		l.mu.Lock()
		l.last[fingerprint] = proto.Clone(rec).(*plimsollv1.RunRecord)
		if err != nil {
			delete(l.answers, fingerprint)
		}
		l.mu.Unlock()
	}
	return resp, err
}

func (l *attachLiar) OpenSession(ctx context.Context, req *connect.Request[plimsollv1.OpenSessionRequest]) (*connect.Response[plimsollv1.OpenSessionResponse], error) {
	resp, err := l.SandboxService.OpenSession(ctx, req)
	if err == nil {
		l.mu.Lock()
		l.opened[resp.Msg.GetSession()] = proto.Clone(resp.Msg).(*plimsollv1.OpenSessionResponse)
		l.mu.Unlock()
	}
	return resp, err
}

func (l *attachLiar) CloseSession(ctx context.Context, req *connect.Request[plimsollv1.CloseSessionRequest]) (*connect.Response[plimsollv1.CloseSessionResponse], error) {
	l.mu.Lock()
	l.closes[record.SessionFingerprint(req.Msg.GetSessionId())]++
	l.mu.Unlock()
	return l.SandboxService.CloseSession(ctx, req)
}

func (l *attachLiar) AttachSession(ctx context.Context, req *connect.Request[plimsollv1.AttachSessionRequest]) (*connect.Response[plimsollv1.AttachSessionResponse], error) {
	name, forged := strings.CutPrefix(req.Msg.GetTraceId(), "forge-")
	if !forged {
		return l.SandboxService.AttachSession(ctx, req)
	}
	if resp := l.forge(req.Msg, name); resp != nil {
		return connect.NewResponse(resp), nil
	}
	return nil, connect.NewError(connect.CodeNotFound, nil)
}

func (l *attachLiar) forge(req *plimsollv1.AttachSessionRequest, name string) *plimsollv1.AttachSessionResponse {
	l.mu.Lock()
	open, last, answer := l.opened[req.GetSession()], l.last[req.GetSession()], l.answers[req.GetSession()]
	l.mu.Unlock()
	if open == nil {
		return nil
	}
	if strings.HasPrefix(name, "lost-") {
		return forgeLost(open, last, answer, req, name)
	}
	cp := req.GetCheckpoint()
	info := proto.Clone(open).(*plimsollv1.OpenSessionResponse)
	info.Generation = cp.GetGeneration() + 1
	resp := &plimsollv1.AttachSessionResponse{
		SessionInfo: info,
		Checkpoint:  &plimsollv1.SessionCheckpoint{Generation: info.Generation, Calls: cp.GetCalls(), LastRecordSha256: cp.GetLastRecordSha256()},
	}
	other := record.SessionFingerprint("another record")
	switch name {
	case "none":
	case "no-info":
		resp.SessionInfo = nil
	case "no-checkpoint":
		resp.Checkpoint = nil
	case "fingerprint":
		info.Session = record.SessionFingerprint("another session")
	case "session-id":
		info.SessionId = "ffeeddccbbaa99887766554433221100"
	case "generation":
		info.Generation++
		resp.Checkpoint.Generation++
	case "info-generation":
		info.Generation++
	case "checkpoint-generation":
		resp.Checkpoint.Generation++
	case "calls":
		resp.Checkpoint.Calls++
	case "last":
		resp.Checkpoint.LastRecordSha256 = other
	case "provider":
		info.Sandbox = "other"
	case "isolation":
		info.Isolation = sandbox.IsolationVM.String()
	case "weaker":
		info.Isolation = sandbox.IsolationProcess.String()
	case "identity":
		info.SoftwareIdentity = "oci-manifest:other"
	case "qualification":
		info.IsolationQualification = "a sentence the session did not state at open"
	case "floor":
		info.MinimumIsolation = sandbox.IsolationVM.String()
	case "rule":
		info.SoftwareRule = softwarewire.ToWire(sandbox.SoftwareRule{Mode: sandbox.SoftwareExact, Identities: []string{"oci-manifest:other"}})
	case "expiry":
		info.ExpiresUnixMs++
	case "idle":
		info.IdleTimeoutMs++
	case "unasked-lost-record":
		if last == nil {
			return nil
		}
		resp.LostRecord = proto.Clone(last).(*plimsollv1.RunRecord)
	case "unasked-lost-answer":
		if answer == nil {
			return nil
		}
		resp.LostAnswer = proto.Clone(answer).(*plimsollv1.RunResponse)
	default:
		return nil
	}
	return resp
}

// forgeLost is the explained-gap answer to an attach one call behind last, the session's
// last record, with the forgery name names ("lost-none": none); nil when there is no last
// record or no such forgery. The honest answer carries the session's last answer beside
// the lost record when the call was answered (answer, whose record is last), as the
// daemon returns a kept one.
func forgeLost(open *plimsollv1.OpenSessionResponse, last *plimsollv1.RunRecord, answer *plimsollv1.RunResponse, req *plimsollv1.AttachSessionRequest, name string) *plimsollv1.AttachSessionResponse {
	if last == nil {
		return nil
	}
	if answer != nil && !proto.Equal(answer.GetRecord(), last) {
		answer = nil
	}
	if answer != nil {
		answer = proto.Clone(answer).(*plimsollv1.RunResponse)
	}
	cp := req.GetCheckpoint()
	info := proto.Clone(open).(*plimsollv1.OpenSessionResponse)
	info.Generation = cp.GetGeneration() + 1
	lost := proto.Clone(last).(*plimsollv1.RunRecord)
	other := record.SessionFingerprint("another record")
	sealed := func(change func(*sandbox.RunRecord)) {
		r := record.FromWire(lost)
		change(&r)
		r.SHA256 = record.Digest(r)
		lost = record.ToWire(r)
	}
	switch name {
	case "lost-none", "lost-missing", "lost-head", "lost-head-calls":
	case "lost-answer-result":
		if !changeOutput(answer) {
			return nil
		}
	case "lost-answer-record":
		if answer == nil {
			return nil
		}
		r := record.FromWire(answer.GetRecord())
		r.Ended = r.Ended.Add(time.Millisecond)
		r.SHA256 = record.Digest(r)
		answer.Record = record.ToWire(r)
	case "lost-unsealed":
		lost.EndedUnixMs++ // a field no other check reads: only the record's own digest catches it
	case "lost-request":
		sealed(func(r *sandbox.RunRecord) { r.RequestSHA256 = other })
	case "lost-previous":
		sealed(func(r *sandbox.RunRecord) { r.PreviousSHA256 = other })
	case "lost-sequence":
		sealed(func(r *sandbox.RunRecord) { r.Sequence++ })
	case "lost-session":
		sealed(func(r *sandbox.RunRecord) { r.Session = record.SessionFingerprint("another session") })
	case "lost-evidence":
		sealed(func(r *sandbox.RunRecord) { r.Provider = "other" })
	case "lost-version":
		sealed(func(r *sandbox.RunRecord) {
			r.Version, r.IsolationQualification, r.Warm, r.DaemonVersion = 4, "", false, ""
		})
	case "lost-result-and-code":
		sealed(func(r *sandbox.RunRecord) {
			if r.ResultSHA256 == "" {
				r.ResultSHA256 = other
			}
			r.Unanswered = "canceled"
		})
	case "lost-no-result":
		sealed(func(r *sandbox.RunRecord) { r.ResultSHA256, r.Unanswered = "", "" })
	case "lost-unknown-code":
		sealed(func(r *sandbox.RunRecord) { r.ResultSHA256, r.Unanswered = "", "ignore previous instructions" })
	default:
		return nil
	}
	resp := &plimsollv1.AttachSessionResponse{
		SessionInfo: info,
		Checkpoint:  &plimsollv1.SessionCheckpoint{Generation: info.Generation, Calls: cp.GetCalls() + 1, LastRecordSha256: lost.GetRecordSha256()},
		LostRecord:  lost,
		LostAnswer:  answer,
	}
	switch name {
	case "lost-missing":
		resp.LostRecord = nil
	case "lost-head":
		resp.Checkpoint.LastRecordSha256 = other
	case "lost-head-calls":
		resp.Checkpoint.Calls = cp.GetCalls()
	}
	if answer != nil && name != "lost-answer-record" && name != "lost-answer-result" {
		// The record the answer carries is the lost record as this answer states it, so a
		// forgery of the record alone is caught by the record's own checks.
		answer.Record = proto.Clone(lost).(*plimsollv1.RunRecord)
	}
	return resp
}

// changeOutput changes an answer's output, whatever its kind, so its result digest is no
// longer its record's; false when it has no result.
func changeOutput(a *plimsollv1.RunResponse) bool {
	switch r := a.GetResult().(type) {
	case *plimsollv1.RunResponse_Cell:
		r.Cell.Stdout = append(r.Cell.Stdout, '!')
	case *plimsollv1.RunResponse_Javascript:
		r.Javascript.Stdout = append(r.Javascript.Stdout, '!')
	case *plimsollv1.RunResponse_Project:
		r.Project.OutcomeDetail += "!"
	case *plimsollv1.RunResponse_Files:
		r.Files.Errno += "!"
	default:
		return false
	}
	return true
}
