package rpc

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// A session's end detail reaches a caller only when its provider marked it public: docker's or
// a vendor's raw error text (here the daemon's socket path) is told as an error ID, in the
// message and in the typed detail, and the daemon's log keeps it under that ID.
func TestASessionEndsRawDetailStaysInTheLog(t *testing.T) {
	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	defer slog.SetDefault(prev)

	raw := "the container could not be read back: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
	err := mapSandboxErr(fmt.Errorf("call 3: %w", &sandbox.SessionEndedError{Reason: sandbox.SessionBoundaryFailed, Detail: raw}))
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("not a connect error: %v", err)
	}
	detail := endDetail(t, ce)
	for _, said := range []string{ce.Message(), detail} {
		if strings.Contains(said, "docker.sock") || !strings.Contains(said, "the daemon's log holds its detail (error ") {
			t.Errorf("told the caller %q", said)
		}
	}
	if !strings.Contains(logged.String(), "docker.sock") || !strings.Contains(logged.String(), "kept from the caller") {
		t.Errorf("the log does not hold the detail: %s", logged.String())
	}

	public := "the container is exited: it ran out of memory (the sandbox's limit is 1024m)"
	err = mapSandboxErr(&sandbox.SessionEndedError{Reason: sandbox.SessionMainProcessEnded, Detail: public, Public: true})
	if !errors.As(err, &ce) || !strings.Contains(ce.Message(), public) || endDetail(t, ce) != public {
		t.Errorf("a public detail was not told as it is: %v", err)
	}
}

func endDetail(t *testing.T, ce *connect.Error) string {
	t.Helper()
	for _, d := range ce.Details() {
		if v, err := d.Value(); err == nil {
			if se, ok := v.(*plimsollv1.SessionEnded); ok {
				return se.GetDetail()
			}
		}
	}
	t.Fatal("no SessionEnded detail")
	return ""
}
