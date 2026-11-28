package rpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/wireenum"
	"github.com/plimsollmark/plimsoll/sandbox"
)

var updateAnswers = flag.Bool("update-answers", false, "rewrite protocol/testdata/answers.json from the daemon's error path")

const answersFile = "../../protocol/testdata/answers.json"

var faultID = regexp.MustCompile(`internal error [0-9a-f]{16}`)

var contextID = regexp.MustCompile(`\(error [0-9a-f]{16};`)

// answerCase is one daemon answer every client must read the same way: the HTTP status,
// the body, whether the request ID's echo matches ("match", "missing" or "other"), the
// not-dispatched header, and the verdict. The Go, Python and TypeScript clients each run
// every case through their own decoding (review D5, 2026-10-23: the accept and reject
// logic was ported three times, with vectors for the digests alone).
type answerCase struct {
	Name        string `json:"name"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType"`
	Body        string `json:"body"`
	Echo        string `json:"echo"`
	Mark        string `json:"mark,omitempty"`
	Expect      struct {
		Code           string `json:"code"`
		NotDispatched  string `json:"notDispatched"`
		SessionEnded   string `json:"sessionEnded"`
		AnswerNotBound bool   `json:"answerNotBound"`
		// CapacityLimit is the limit a capacity refusal states, as the clients name it
		// ("unknown" when none is stated or the client cannot name it); empty on every
		// other answer.
		CapacityLimit string `json:"capacityLimit"`
	} `json:"expect"`
}

// written is the status and body the daemon's own error writer gives err.
func written(t *testing.T, err *connect.Error) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/plimsoll.v1.SandboxService/Describe", nil)
	req.Header.Set("Content-Type", "application/proto")
	rec := httptest.NewRecorder()
	if werr := connect.NewErrorWriter().Write(rec, req, err); werr != nil {
		t.Fatal(werr)
	}
	return rec.Code, rec.Body.String()
}

// withDetail is err's body with a detail of typeName whose value is raw bytes, so a
// case can carry a detail no daemon writes.
func withDetail(t *testing.T, code connect.Code, message, typeName string, raw []byte) (int, string) {
	t.Helper()
	status, body := written(t, connect.NewError(code, errors.New(message)))
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	m["details"] = []any{map[string]any{"type": typeName, "value": base64.RawStdEncoding.EncodeToString(raw)}}
	b, _ := json.Marshal(m)
	return status, string(b)
}

func detailBytes(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func buildAnswerCases(t *testing.T) []answerCase {
	var cases []answerCase
	add := func(name string, status int, contentType, body, echo, mark, code, nd, end string, notBound bool) {
		c := answerCase{Name: name, Status: status, ContentType: contentType, Body: body, Echo: echo, Mark: mark}
		c.Expect.Code, c.Expect.NotDispatched, c.Expect.SessionEnded, c.Expect.AnswerNotBound = code, nd, end, notBound
		if nd == "capacity" {
			c.Expect.CapacityLimit = "unknown"
		}
		cases = append(cases, c)
	}
	// limited is add for a capacity refusal that states limit.
	limited := func(name string, status int, body, limit string) {
		add(name, status, "application/json", body, "match", "", "resource_exhausted", "capacity", "", false)
		cases[len(cases)-1].Expect.CapacityLimit = limit
	}
	js := "application/json"
	s, b := written(t, refuseCapacity(sandbox.CapacityRuns, errors.New("sandbox is at capacity, retry shortly")))
	limited("at capacity", s, b, "runs")
	add("at capacity, but the echo is missing", s, js, b, "missing", "", "resource_exhausted", "", "", true)
	add("at capacity, but the echo names another request", s, js, b, "other", "", "resource_exhausted", "", "", true)
	// Each limit the daemon states, written by the site that refuses for it (finding
	// release-115): a client tells them apart by the detail alone.
	for _, l := range answerLimits(t) {
		s, b = written(t, l.err)
		limited("at capacity: "+l.name, s, b, l.limit)
	}
	// The call's own time, run out while it waited for its session's turn: answered as
	// its timeout, deadline_exceeded, limit deadline (finding release-122), so a client
	// reads the limit off a refusal that is not resource_exhausted too.
	turn := &sessionEntry{turn: make(chan struct{}, 1), waiting: make(chan struct{}, 1)}
	turn.turn <- struct{}{}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	_, err := turn.takeTurn(expired)
	cancel()
	if wireenum.CapacityLimitFromWire(wireLimit(err)) != sandbox.CapacityDeadline {
		t.Fatalf("a call whose own time ran out waiting for its turn states %v", wireLimit(err))
	}
	var gaveUp *connect.Error
	if !errors.As(err, &gaveUp) {
		t.Fatalf("no connect error: %v", err)
	}
	s, b = written(t, gaveUp)
	add("the call's own time ran out before any of it was sent", s, js, b, "match", "", "deadline_exceeded", "capacity", "", false)
	cases[len(cases)-1].Expect.CapacityLimit = "deadline"
	s, b = withDetail(t, connect.CodeResourceExhausted, "sandbox is at capacity, retry shortly", "plimsoll.v1.NotDispatched",
		detailBytes(t, &plimsollv1.NotDispatched{Reason: plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY}))
	limited("at capacity, from a daemon that states no limit", s, b, "unknown")
	s, b = withDetail(t, connect.CodeResourceExhausted, "refused", "plimsoll.v1.NotDispatched",
		detailBytes(t, &plimsollv1.NotDispatched{Reason: plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY, Limit: 99}))
	limited("at capacity, for a limit this client cannot name", s, b, "unknown")
	s, b = withDetail(t, connect.CodeResourceExhausted, "refused", "plimsoll.v1.NotDispatched",
		detailBytes(t, &plimsollv1.NotDispatched{Reason: plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST, Limit: plimsollv1.CapacityLimit_CAPACITY_LIMIT_RATE}))
	add("a limit on a refusal that is not for capacity", s, js, b, "match", "", "resource_exhausted", "request", "", false)
	s, b = written(t, refuse(connect.CodeResourceExhausted, sandbox.RefusalRequest, errors.New("request body declares 9000000 bytes, over the 8388608-byte limit")))
	add("an over-size request", s, js, b, "match", "", "resource_exhausted", "request", "", false)
	s, b = written(t, refuse(connect.CodeFailedPrecondition, sandbox.RefusalIsolation, sandbox.ErrInsufficientIsolation))
	add("below the isolation floor", s, js, b, "match", "", "failed_precondition", "isolation", "", false)
	s, b = written(t, refuse(connect.CodeUnimplemented, sandbox.RefusalProtocol, errors.New("protocol 3 is not 4")))
	add("another protocol", s, js, b, "match", "", "unimplemented", "protocol", "", false)
	s, b = written(t, refuse(connect.CodeUnauthenticated, sandbox.RefusalPermission, errors.New("unauthenticated")))
	add("no credential", s, js, b, "match", "", "unauthenticated", "permission", "", false)
	ended := mapSandboxErr(sandbox.RefuseEndedSession(&sandbox.SessionEndedError{Reason: sandbox.SessionExpired, Detail: "the session's lifetime ran out", Public: true}))
	var ce *connect.Error
	if !errors.As(ended, &ce) {
		t.Fatal("a session's end did not map to a connect error")
	}
	s, b = written(t, ce)
	add("a session that ended", s, js, b, "match", "", connect.CodeOf(ended).String(), "request", "expired", false)
	// A call whose head is not the session's, as checkHead writes it: marked, with the
	// daemon's head beside the mark.
	mismatch := (&sessionEntry{generation: 1, calls: 1, last: strings.Repeat("ab", 32)}).checkHead(&plimsollv1.SessionCheckpoint{Generation: 1})
	if !errors.As(mismatch, &ce) {
		t.Fatal("a head mismatch is not a connect error")
	}
	s, b = written(t, ce)
	add("a call whose head is not the session's", s, js, b, "match", "", "failed_precondition", "request", "", false)
	if !errors.As(mapSandboxErr(errors.New("the runner vanished")), &ce) {
		t.Fatal("an internal fault did not map to a connect error")
	}
	s, b = written(t, ce)
	// The fault's ID is fresh on every answer; the file keeps a fixed one.
	b = faultID.ReplaceAllString(b, "internal error 0000000000000000")
	add("an internal fault, which may have run", s, js, b, "match", "", "internal", "", "", false)
	// A call canceled or out of time whose session also ended: the code is the context's,
	// and the end travels beside it (finding release-89).
	for _, c := range []struct {
		name string
		ctx  error
		code string
	}{{"a deadline that came with the session's end", context.DeadlineExceeded, "deadline_exceeded"}, {"a cancellation that came with the session's end", context.Canceled, "canceled"}} {
		if !errors.As(mapSandboxErr(errors.Join(c.ctx, &sandbox.SessionEndedError{Reason: sandbox.SessionMainProcessEnded, Detail: "the main process exited", Public: true})), &ce) {
			t.Fatal("a context error with a session's end did not map to a connect error")
		}
		s, b = written(t, ce)
		// The ID of the detail kept for the log is fresh on every answer; the file keeps a fixed one.
		b = contextID.ReplaceAllString(b, "(error 0000000000000000;")
		add(c.name, s, js, b, "match", "", c.code, "", "main_process_ended", false)
	}

	// Answers no daemon of this version writes.
	s, b = withDetail(t, connect.CodeResourceExhausted, "refused", "plimsoll.v1.NotDispatched", detailBytes(t, &plimsollv1.NotDispatched{Reason: 99}))
	add("a refusal reason this client cannot name", s, js, b, "match", "", "resource_exhausted", "unknown", "", false)
	raw := append(detailBytes(t, &plimsollv1.NotDispatched{Reason: plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY}),
		0x29, 1, 2, 3, 4, 5, 6, 7, 8, // field 5, fixed64
		0x20, 7) // field 4, varint
	s, b = withDetail(t, connect.CodeResourceExhausted, "refused", "plimsoll.v1.NotDispatched", raw)
	add("a refusal with fields a newer daemon added", s, js, b, "match", "", "resource_exhausted", "capacity", "", false)
	s, b = withDetail(t, connect.CodeFailedPrecondition, "ended", "plimsoll.v1.SessionEnded", nil)
	add("a session end with no reason", s, js, b, "match", "", "failed_precondition", "", "unknown", false)
	s, b = withDetail(t, connect.CodeResourceExhausted, "refused", "plimsoll.v1.NotDispatched", []byte{0x08})
	add("an undecodable refusal detail", s, js, b, "match", "", "resource_exhausted", "", "", false)
	// A refusal detail whose base64 holds a stray character: "CAY" is capacity, and a
	// reader that skips the "!" would mark a call nothing ran in (finding hunt-quality-93).
	// The code is the HTTP status's and the body's alike, so the case holds the mark alone:
	// on a 429, Go reads the status's code where the Python and TypeScript clients keep the
	// body's, which is the rest of that finding.
	s, b = withDetail(t, connect.CodeUnavailable, "refused", "plimsoll.v1.NotDispatched", nil)
	if !strings.Contains(b, `"value":""`) {
		t.Fatalf("the detail's value is not where the case puts its base64: %s", b)
	}
	b = strings.Replace(b, `"value":""`, `"value":"CAY!"`, 1)
	add("a refusal detail whose base64 holds a stray character", s, js, b, "match", "", "unavailable", "", "", false)
	s, b = written(t, connect.NewError(connect.CodeInvalidArgument, errors.New("malformed body")))
	add("a refusal before the handler, marked by the header", s, js, b, "match", "request", "invalid_argument", "request", "", false)
	add("a proxy's page, no mark", http.StatusBadGateway, "text/html", "<html><body>502 Bad Gateway</body></html>", "missing", "", "unavailable", "", "", true)
	// A details list holding a JSON null is not a Connect error a client can read: the
	// code is the HTTP status's, and neither the details nor the header mark is believed
	// (finding release-88: the Go client panicked on it).
	withNull := func(code connect.Code, typeName string, raw []byte) (int, string) {
		s, b := withDetail(t, code, "refused", typeName, raw)
		var m map[string]any
		if err := json.Unmarshal([]byte(b), &m); err != nil {
			t.Fatal(err)
		}
		m["details"] = append([]any{nil}, m["details"].([]any)...)
		out, _ := json.Marshal(m)
		return s, string(out)
	}
	add("a details list holding only null", http.StatusInternalServerError, js, `{"code":"internal","details":[null]}`, "match", "", "unknown", "", "", false)
	s, b = withNull(connect.CodeResourceExhausted, "plimsoll.v1.NotDispatched", detailBytes(t, &plimsollv1.NotDispatched{Reason: plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY}))
	add("a null before a refusal detail, marked by the header", s, js, b, "match", "capacity", "unavailable", "", "", false)
	s, b = withNull(connect.CodeFailedPrecondition, "plimsoll.v1.SessionEnded", detailBytes(t, &plimsollv1.SessionEnded{Reason: plimsollv1.SessionEnd_SESSION_END_EXPIRED}))
	add("a null before a session end", s, js, b, "match", "", "internal", "", "", false)
	s, b = withNull(connect.CodeDeadlineExceeded, "plimsoll.v1.UnansweredCall", detailBytes(t, &plimsollv1.UnansweredCall{Record: &plimsollv1.RunRecord{Version: 5, Unanswered: "deadline_exceeded", Sequence: 1}}))
	add("a null before an unanswered call's record", s, js, b, "match", "", "unavailable", "", "", false)
	return cases
}

// The daemon's answers, and adversarial variants of them, are protocol/testdata/answers.json,
// which the three clients read: rewrite it with -update-answers after a change to the
// daemon's error path, and the clients' tests then hold them to it.
func TestAnswersFileIsTheDaemonsErrorPath(t *testing.T) {
	cases := buildAnswerCases(t)
	b, err := json.MarshalIndent(struct {
		About   []string     `json:"about"`
		Answers []answerCase `json:"answers"`
	}{[]string{
		"Daemon answers every client reads the same way: refusals written by the daemon's own",
		"error path (internal/rpc answers_test.go) and variants no daemon of this version writes.",
		"echo: the request ID's echo matches, is missing, or names another request. The Go,",
		"Python and TypeScript clients' tests run every case. Rewrite: go test ./internal/rpc -run",
		"TestAnswersFileIsTheDaemonsErrorPath -update-answers",
	}, cases}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if *updateAnswers {
		if err := os.WriteFile(answersFile, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(answersFile)
	if err != nil {
		t.Fatalf("%v (run with -update-answers to create it)", err)
	}
	if string(got) != string(b) {
		t.Fatal("protocol/testdata/answers.json is not what the daemon's error path writes: run with -update-answers")
	}
}

// answerLimit is a capacity refusal written by the daemon's own site for one limit.
type answerLimit struct {
	name, limit string
	err         *connect.Error
}

// answerLimits makes each daemon limit refuse, by the code that refuses for it, and
// fails when a site states another limit than its own (finding release-115).
func answerLimits(t *testing.T) []answerLimit {
	t.Helper()
	var out []answerLimit
	got := func(name string, want sandbox.CapacityLimit, err error) {
		t.Helper()
		var ce *connect.Error
		if !errors.As(err, &ce) {
			t.Fatalf("%s: no connect error: %v", name, err)
		}
		if connect.CodeOf(ce) != connect.CodeResourceExhausted {
			t.Fatalf("%s: code %v", name, connect.CodeOf(ce))
		}
		reason, marked := notDispatchedOf(ce)
		if !marked || reason != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY {
			t.Fatalf("%s: not marked capacity: %v", name, ce)
		}
		var limit plimsollv1.CapacityLimit
		for _, d := range ce.Details() {
			if v, derr := d.Value(); derr == nil {
				if nd, ok := v.(*plimsollv1.NotDispatched); ok {
					limit = nd.GetLimit()
				}
			}
		}
		if wireenum.CapacityLimitFromWire(limit) != want {
			t.Fatalf("%s: states limit %v, want %v", name, limit, want)
		}
		out = append(out, answerLimit{name, want.String(), ce})
	}
	// The rate: one run a minute, a second run and a second session call both refused.
	l := NewCodeLimiter(4, 4, 1, 1)
	rel, err := l.Acquire(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	rel()
	_, err = l.Acquire(context.Background(), "a")
	got("the caller's runs per minute", sandbox.CapacityRate, err)
	if err := l.Charge("a"); err == nil {
		t.Fatal("a session call past the rate was charged")
	} else if wireLimit(err) != plimsollv1.CapacityLimit_CAPACITY_LIMIT_RATE {
		t.Fatalf("a session call past the rate states %v", wireLimit(err))
	}
	// The daemon's runs in flight, and the caller's.
	l = NewCodeLimiter(1, 1, 0, 0)
	rel, err = l.Hold("a")
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Hold("b")
	got("the daemon's runs in flight", sandbox.CapacityRuns, err)
	rel()
	l = NewCodeLimiter(2, 1, 0, 0)
	if _, err := l.Hold("a"); err != nil {
		t.Fatal(err)
	}
	_, err = l.Hold("a")
	got("the caller's runs in flight", sandbox.CapacityCallerRuns, err)
	// The session places, the caller's and the owner's.
	var r sessionRegistry
	_, err = r.reserve(SessionConfig{MaxSessions: 0}, "a", "", true)
	got("the daemon's session places", sandbox.CapacitySessions, err)
	if _, err := r.reserve(SessionConfig{MaxSessions: 4, MaxPerCaller: 1}, "a", "", true); err != nil {
		t.Fatal(err)
	}
	_, err = r.reserve(SessionConfig{MaxSessions: 4, MaxPerCaller: 1}, "a", "", true)
	got("the caller's session places", sandbox.CapacityCallerSessions, err)
	var o sessionRegistry
	if _, err := o.reserve(SessionConfig{MaxSessions: 4, MaxPerOwner: 1}, "a", "u", true); err != nil {
		t.Fatal(err)
	}
	_, err = o.reserve(SessionConfig{MaxSessions: 4, MaxPerOwner: 1}, "a", "u", true)
	got("the owner's session places, none of which can be closed", sandbox.CapacityOwnerSessions, err)
	// Paid seconds, the caller's and the daemon's.
	_, err = NewSpendCap(0).reserve("a", 10, time.Minute)
	got("the caller's paid seconds", sandbox.CapacityPaidSeconds, err)
	_, err = NewSpendCap(10).reserve("a", 0, time.Minute)
	got("the daemon's paid seconds", sandbox.CapacityPaidSeconds, err)
	// The short lines: a call already waiting for its session's turn.
	e := &sessionEntry{turn: make(chan struct{}, 1), waiting: make(chan struct{}, 1)}
	e.turn <- struct{}{}
	e.waiting <- struct{}{}
	_, err = e.takeTurn(context.Background())
	got("a call already waiting for its session's turn", sandbox.CapacityQueue, err)
	// The provider's own capacity.
	got("the provider's own capacity", sandbox.CapacityProvider, mapSandboxErr(sandbox.RefuseNoWarmSandbox()))
	return out
}

// wireLimit is the limit err's NotDispatched detail states.
func wireLimit(err error) plimsollv1.CapacityLimit {
	var ce *connect.Error
	if errors.As(err, &ce) {
		for _, d := range ce.Details() {
			if v, derr := d.Value(); derr == nil {
				if nd, ok := v.(*plimsollv1.NotDispatched); ok {
					return nd.GetLimit()
				}
			}
		}
	}
	return plimsollv1.CapacityLimit_CAPACITY_LIMIT_UNSPECIFIED
}
