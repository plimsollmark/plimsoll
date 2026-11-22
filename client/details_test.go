package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	neturl "net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// detailJSON is a Connect error detail as the daemon writes it: the type name and the
// message's bytes in unpadded base64.
func detailJSON(t *testing.T, m proto.Message) string {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"type":%q,"value":%q}`, "plimsoll.v1."+string(m.ProtoReflect().Descriptor().Name()), base64.RawStdEncoding.EncodeToString(b))
}

// An error answer whose details list holds a JSON null made the client panic inside
// connect-go's ErrorDetail.Value (finding release-88). It is an answer the client cannot
// read: whatever the null sits beside (a refusal, a session's end, an unanswered call's
// record) and whatever the header marks, the error carries the HTTP status's code and
// nothing else, so the call reads "may have run". Each answer goes through Describe and
// through Exchange, the run path.
func TestAnAnswerWithANullDetailIsBelievedInNothing(t *testing.T) {
	nd := detailJSON(t, &plimsollv1.NotDispatched{Reason: plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST})
	se := detailJSON(t, &plimsollv1.SessionEnded{Reason: plimsollv1.SessionEnd_SESSION_END_EXPIRED, Detail: "d"})
	ua := detailJSON(t, &plimsollv1.UnansweredCall{Record: &plimsollv1.RunRecord{Version: 5, Unanswered: "deadline_exceeded", Sequence: 1}})
	bodies := []string{
		`{"code":"internal","details":[null]}`,
		`{"code":"internal","details":[null,null]}`,
		`{"code":"failed_precondition","message":"m","details":[null,` + nd + `]}`,
		`{"code":"failed_precondition","message":"m","details":[` + nd + `,null]}`,
		`{"code":"failed_precondition","message":"m","details":[null,` + se + `]}`,
		`{"code":"deadline_exceeded","message":"m","details":[` + ua + `,null]}`,
		`{"code":"resource_exhausted","message":"m","details":[` + nd + `,` + se + `,null,` + ua + `]}`,
	}
	answers := []struct {
		status int
		mark   string
		code   connect.Code
	}{
		{http.StatusInternalServerError, "", connect.CodeUnknown},
		{http.StatusBadRequest, "request", connect.CodeInternal},
		{http.StatusTooManyRequests, "capacity", connect.CodeUnavailable},
		{http.StatusServiceUnavailable, "capacity", connect.CodeUnavailable},
		{http.StatusNotFound, "", connect.CodeUnimplemented},
	}
	calls := map[string]func(*Remote) error{
		"Describe": func(r *Remote) error { _, err := r.Describe(context.Background()); return err },
		"Exchange": func(r *Remote) error {
			_, _, err := r.Exchange(context.Background(), &plimsollv1.RunRequest{
				Protocol: protocol.Number,
				Payload:  &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}},
			})
			return err
		},
	}
	for _, body := range bodies {
		for _, a := range answers {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(protocol.RequestIDHeader, r.Header.Get(protocol.RequestIDHeader))
				if a.mark != "" {
					w.Header().Set(protocol.NotDispatchedHeader, a.mark)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(a.status)
				_, _ = w.Write([]byte(body))
			}))
			for name, call := range calls {
				what := fmt.Sprintf("%s, HTTP %d marked %q, %s", name, a.status, a.mark, body)
				err := func() (err error) {
					defer func() {
						if p := recover(); p != nil {
							err = fmt.Errorf("panic: %v", p)
						}
					}()
					return call(newRemote(t, srv.URL))
				}()
				switch {
				case err == nil:
					t.Errorf("%s: no error", what)
				case strings.HasPrefix(err.Error(), "panic: "):
					t.Errorf("%s: %v", what, err)
				case !errors.Is(err, errNullDetail):
					t.Errorf("%s: %v, want errNullDetail", what, err)
				case connect.CodeOf(err) != a.code:
					t.Errorf("%s: code %v, want %v, the HTTP status's", what, connect.CodeOf(err), a.code)
				}
				if reason, marked := sandbox.NotDispatchedReason(err); marked {
					t.Errorf("%s: believed not dispatched (%v)", what, reason)
				}
				if end := sandbox.SessionEndReason(err); end != sandbox.SessionOpen {
					t.Errorf("%s: believed the session ended (%v)", what, end)
				}
				if rec := unansweredDetail(err); rec != nil {
					t.Errorf("%s: believed an unanswered call's record", what)
				}
			}
			srv.Close()
		}
	}
}

// A session call answered with a null detail beside a not-dispatched mark is a call
// that may have run: the session believes neither the mark nor an end, and sends nothing
// more (finding release-88).
func TestASessionCallAnsweredWithANullDetailMayHaveRun(t *testing.T) {
	url, p := sessionServer(t)
	nd := detailJSON(t, &plimsollv1.NotDispatched{Reason: plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_REQUEST})
	se := detailJSON(t, &plimsollv1.SessionEnded{Reason: plimsollv1.SessionEnd_SESSION_END_EXPIRED})
	target, err := neturl.Parse(url)
	if err != nil {
		t.Fatal(err)
	}
	daemon := httputil.NewSingleHostReverseProxy(target)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/SessionRun") {
			w.Header().Set(protocol.RequestIDHeader, r.Header.Get(protocol.RequestIDHeader))
			w.Header().Set(protocol.NotDispatchedHeader, "request")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"failed_precondition","message":"m","details":[null,` + nd + `,` + se + `]}`))
			return
		}
		daemon.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	s, err := newRemote(t, proxy.URL).OpenSession(context.Background(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if !errors.Is(err, errNullDetail) || connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("the call: %v, want errNullDetail coded internal", err)
	}
	if _, marked := sandbox.NotDispatchedReason(err); marked {
		t.Fatalf("the call is believed not dispatched: %v", err)
	}
	if s.Ended() != nil {
		t.Fatalf("an end was believed: %v", s.Ended())
	}
	if stopped := s.Stopped(); !errors.Is(stopped, ErrSessionUnanswered) {
		t.Fatalf("Stopped = %v, want ErrSessionUnanswered", stopped)
	}
	_, err = s.RunJavaScript(context.Background(), sandbox.Request{Code: "2"})
	if reason, marked := sandbox.NotDispatchedReason(err); !errors.Is(err, ErrSessionUnanswered) || !marked || reason != sandbox.RefusalRequest {
		t.Fatalf("the next call: %v, want ErrSessionUnanswered marked request", err)
	}
	if n := p.Opened()[0].Calls(); n != 0 {
		t.Fatalf("the daemon ran %d calls, want 0", n)
	}
}

// A call canceled or out of time whose session also ended keeps both: the context's
// error and the session's end (finding release-89; the daemon's mapSandboxErr attaches
// the SessionEnded detail whatever the code).
func TestASessionEndBesideACanceledOrDeadlineCodeIsKept(t *testing.T) {
	for _, c := range []struct {
		code connect.Code
		ctx  error
	}{{connect.CodeCanceled, context.Canceled}, {connect.CodeDeadlineExceeded, context.DeadlineExceeded}} {
		ce := connect.NewError(c.code, errors.New("m"))
		d, err := connect.NewErrorDetail(&plimsollv1.SessionEnded{Reason: plimsollv1.SessionEnd_SESSION_END_MAIN_PROCESS_ENDED, Detail: "the main process exited"})
		if err != nil {
			t.Fatal(err)
		}
		ce.AddDetail(d)
		got := restoreSandboxError(ce)
		if !errors.Is(got, c.ctx) || !errors.Is(got, sandbox.ErrSessionEnded) || sandbox.SessionEndReason(got) != sandbox.SessionMainProcessEnded {
			t.Errorf("%v: %v, want %v and the session's end (main_process_ended)", c.code, got, c.ctx)
		}
		var se *sandbox.SessionEndedError
		if !errors.As(got, &se) || se.Detail != "the main process exited" {
			t.Errorf("%v: the end's detail is lost: %v", c.code, got)
		}
		if _, marked := sandbox.NotDispatchedReason(got); marked {
			t.Errorf("%v: marked not dispatched with no mark sent", c.code)
		}
		// Without an end, the error is as it was: the context's sentinel alone.
		if plain := restoreSandboxError(connect.NewError(c.code, errors.New("m"))); !errors.Is(plain, c.ctx) || errors.Is(plain, sandbox.ErrSessionEnded) {
			t.Errorf("%v without an end: %v", c.code, plain)
		}
	}
}

// The same class on a success: a JSON answer (a caller may choose connect.WithProtoJSON)
// is read by protojson, which refuses a null in a list and reads a null message as unset,
// and the client reads every field through nil-safe getters. A null element, a null
// member and an empty message each end in an error or in zero values, never a panic.
func TestSuccessAnswersWithNullsOrEmptyMessagesDoNotPanic(t *testing.T) {
	serve := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(protocol.RequestIDHeader, r.Header.Get(protocol.RequestIDHeader))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
	}
	noPanic := func(call func() error) (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("panic: %v", p)
			}
		}()
		return call()
	}
	for _, body := range []string{
		`{}`, `{"javascript":null}`, `{"javascript":{}}`, `{"javascript":{"advice":[null]}}`, `{"javascript":{"advice":[{}]}}`,
		`{"project":null}`, `{"project":{}}`, `{"project":{"steps":[null]}}`, `{"project":{"steps":[{}],"artifacts":[{}]}}`,
		`{"project":{"artifacts":[null]}}`, `{"project":{"advice":[null]}}`,
		`{"module":{}}`, `{"module":{"runs":[null]}}`, `{"module":{"runs":[{}]}}`, `{"cell":{}}`,
		`{"record":null}`, `{"record":{}}`, `{"javascript":{},"record":{}}`,
	} {
		srv := serve(body)
		r := newRemote(t, srv.URL, WithConnectOptions(connect.WithProtoJSON()))
		for name, call := range map[string]func() error{
			"RunJavaScript": func() error { _, err := r.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); return err },
			"RunProject": func() error {
				_, err := r.RunProject(context.Background(), sandbox.ProjectRequest{Steps: []string{"true"}})
				return err
			},
		} {
			if err := noPanic(call); err == nil || strings.HasPrefix(err.Error(), "panic: ") {
				t.Errorf("%s, %s: %v, want an error and no panic", name, body, err)
			}
		}
		srv.Close()
	}
	for _, body := range []string{
		`{}`, `{"javascriptEnvironment":null,"resources":null}`, `{"sessionEnvironment":{},"resources":{}}`,
		`{"projectEnvironment":{"languages":[null]}}`, `{"javascriptEnvironment":{"languages":[]}}`,
	} {
		srv := serve(body)
		r := newRemote(t, srv.URL, WithConnectOptions(connect.WithProtoJSON()))
		if err := noPanic(func() error { _, err := r.Describe(context.Background()); return err }); err != nil && strings.HasPrefix(err.Error(), "panic: ") {
			t.Errorf("Describe, %s: %v", body, err)
		}
		srv.Close()
	}
}
