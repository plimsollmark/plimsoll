package rpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// A caller is shown only text plimsoll composed (a security scan of 2026-10-16): a
// deadline that interrupted an HTTP request carries the request's URL, and a typed
// refusal can carry an exec's stderr, so both reach the caller as an ID whose text the
// log holds.
func TestCallerSeesOnlyComposedErrorText(t *testing.T) {
	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	defer slog.SetDefault(prev)
	idOf := regexp.MustCompile(`error ([0-9a-f]{16})`)
	kept := func(t *testing.T, err error, code connect.Code, secret, want string) {
		t.Helper()
		if connect.CodeOf(err) != code {
			t.Fatalf("code %v, want %v: %v", connect.CodeOf(err), code, err)
		}
		msg := err.Error()
		if strings.Contains(msg, secret) || !strings.Contains(msg, want) {
			t.Fatalf("the caller sees %q (want %q, never %q)", msg, want, secret)
		}
		m := idOf.FindStringSubmatch(msg)
		if m == nil {
			t.Fatalf("no error ID in %q", msg)
		}
		for _, line := range strings.Split(logged.String(), "\n") {
			if strings.Contains(line, "error_id="+m[1]) && strings.Contains(line, secret) {
				return
			}
		}
		t.Fatalf("the log has no line for error %s holding %q:\n%s", m[1], secret, logged.String())
	}

	// E2B's create, its run context's deadline passed: net/http's error names the URL.
	timedOut := &url.Error{Op: "Post", URL: "https://api.e2b.private.example/sandboxes", Err: context.DeadlineExceeded}
	kept(t, mapSandboxErr(timedOut), connect.CodeDeadlineExceeded, "e2b.private.example", "the deadline passed before the call finished")
	// Docker Cloud's and OpenShell's deadlineAware: the context's error beside the transport's.
	kept(t, mapSandboxErr(fmt.Errorf("%w: %v", context.Canceled, errors.New("dial unix /run/private.sock"))), connect.CodeCanceled, "/run/private.sock", "the call was canceled before it finished")
	// A bare context error says nothing more, so it gets the sentence alone, and no log line.
	before := logged.Len()
	if err := mapSandboxErr(sandbox.RefuseGaveUp(canceledCtx())); err.Error() != "canceled: the call was canceled before it finished" {
		t.Fatalf("a bare cancellation reads %q", err.Error())
	} else if wireMark(err) != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_CAPACITY {
		t.Fatal("a refusal lost its not-dispatched mark")
	}
	if logged.Len() != before {
		t.Fatalf("a bare cancellation was logged: %s", logged.String()[before:])
	}

	// A typed refusal keeps its own words; the part its provider marked private is an ID.
	launch := sandbox.NotDispatched(sandbox.RefusalEnvironment, fmt.Errorf("%w: the interpreter could not start: %w", sandbox.ErrUnsupported,
		sandbox.Private(errors.New("Error response from daemon: unix:///var/run/private-docker.sock"))))
	err := mapSandboxErr(launch)
	kept(t, err, connect.CodeUnimplemented, "private-docker.sock", "the interpreter could not start: the daemon's log holds its detail (error ")
	if got := wireMark(err); got != plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ENVIRONMENT {
		t.Fatalf("the refusal's mark is %v", got)
	}
	// A wrapper that renders the marked text otherwise (here quoted): it is not found
	// verbatim, so nothing of the message is shown.
	quoted := fmt.Errorf("%w: %w", sandbox.ErrInvalidRequest, quoting{sandbox.Private(errors.New("tab\there /home/private"))})
	kept(t, mapSandboxErr(quoted), connect.CodeInvalidArgument, "/home/private", "a refusal whose detail the daemon's log holds")
	// Unmarked, a typed refusal is shown whole: it is the caller's own request.
	if err := mapSandboxErr(fmt.Errorf("%w: file 2 of 3: ENOSPC", sandbox.ErrInvalidRequest)); !strings.HasSuffix(err.Error(), "file 2 of 3: ENOSPC") {
		t.Fatalf("an unmarked refusal lost its text: %v", err)
	}
}

// wireMark is the NotDispatched detail's reason on a mapped error, or unspecified.
func wireMark(err error) plimsollv1.NotDispatchedReason {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSPECIFIED
	}
	for _, d := range ce.Details() {
		if v, _ := d.Value(); v != nil {
			if nd, ok := v.(*plimsollv1.NotDispatched); ok {
				return nd.GetReason()
			}
		}
	}
	return plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSPECIFIED
}

type quoting struct{ err error }

func (q quoting) Error() string { return strconv.Quote(q.err.Error()) }
func (q quoting) Unwrap() error { return q.err }

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
