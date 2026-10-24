package rpc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

var updateAnswers = flag.Bool("update-answers", false, "rewrite protocol/testdata/answers.json from the daemon's error path")

const answersFile = "../../protocol/testdata/answers.json"

var faultID = regexp.MustCompile(`internal error [0-9a-f]{16}`)

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
		cases = append(cases, c)
	}
	js := "application/json"
	s, b := written(t, refuse(connect.CodeResourceExhausted, sandbox.RefusalCapacity, errors.New("sandbox is at capacity, retry shortly")))
	add("at capacity", s, js, b, "match", "", "resource_exhausted", "capacity", "", false)
	add("at capacity, but the echo is missing", s, js, b, "missing", "", "resource_exhausted", "", "", true)
	add("at capacity, but the echo names another request", s, js, b, "other", "", "resource_exhausted", "", "", true)
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
	if !errors.As(mapSandboxErr(errors.New("the runner vanished")), &ce) {
		t.Fatal("an internal fault did not map to a connect error")
	}
	s, b = written(t, ce)
	// The fault's ID is fresh on every answer; the file keeps a fixed one.
	b = faultID.ReplaceAllString(b, "internal error 0000000000000000")
	add("an internal fault, which may have run", s, js, b, "match", "", "internal", "", "", false)

	// Answers no daemon of this version writes.
	s, b = withDetail(t, connect.CodeResourceExhausted, "refused", "plimsoll.v1.NotDispatched", detailBytes(t, &plimsollv1.NotDispatched{Reason: 99}))
	add("a refusal reason this client cannot name", s, js, b, "match", "", "resource_exhausted", "unknown", "", false)
	raw := append(detailBytes(t, &plimsollv1.NotDispatched{Reason: plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY}),
		0x29, 1, 2, 3, 4, 5, 6, 7, 8, // field 5, fixed64
		0x18, 7) // field 3, varint
	s, b = withDetail(t, connect.CodeResourceExhausted, "refused", "plimsoll.v1.NotDispatched", raw)
	add("a refusal with fields a newer daemon added", s, js, b, "match", "", "resource_exhausted", "capacity", "", false)
	s, b = withDetail(t, connect.CodeFailedPrecondition, "ended", "plimsoll.v1.SessionEnded", nil)
	add("a session end with no reason", s, js, b, "match", "", "failed_precondition", "", "unknown", false)
	s, b = withDetail(t, connect.CodeResourceExhausted, "refused", "plimsoll.v1.NotDispatched", []byte{0x08})
	add("an undecodable refusal detail", s, js, b, "match", "", "resource_exhausted", "", "", false)
	s, b = written(t, connect.NewError(connect.CodeInvalidArgument, errors.New("malformed body")))
	add("a refusal before the handler, marked by the header", s, js, b, "match", "request", "invalid_argument", "request", "", false)
	add("a proxy's page, no mark", http.StatusBadGateway, "text/html", "<html><body>502 Bad Gateway</body></html>", "missing", "", "unavailable", "", "", true)
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
