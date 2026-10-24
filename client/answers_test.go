package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The daemon answers in protocol/testdata/answers.json, which the Python and TypeScript
// clients read too, come back from this client as the file says: served over HTTP, each
// with its echo and header, and read through the client's own path (review D5,
// 2026-10-23).
func TestEveryClientReadsTheSharedAnswersAlike(t *testing.T) {
	b, err := os.ReadFile("../protocol/testdata/answers.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Answers []struct {
			Name, ContentType, Body, Echo, Mark string
			Status                              int
			Expect                              struct {
				Code, NotDispatched, SessionEnded string
				AnswerNotBound                    bool
			}
		}
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Answers) < 10 {
		t.Fatalf("%d shared answers", len(file.Answers))
	}
	for _, a := range file.Answers {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch a.Echo {
			case "match":
				w.Header().Set(protocol.RequestIDHeader, r.Header.Get(protocol.RequestIDHeader))
			case "other":
				w.Header().Set(protocol.RequestIDHeader, "another-request")
			}
			if a.Mark != "" {
				w.Header().Set(protocol.NotDispatchedHeader, a.Mark)
			}
			w.Header().Set("Content-Type", a.ContentType)
			w.WriteHeader(a.Status)
			_, _ = w.Write([]byte(a.Body))
		}))
		_, err := newRemote(t, srv.URL).Describe(context.Background())
		srv.Close()
		if err == nil {
			t.Errorf("%s: no error", a.Name)
			continue
		}
		reason, marked := sandbox.NotDispatchedReason(err)
		nd := ""
		if marked {
			nd = reason.String()
		}
		end := ""
		if e := sandbox.SessionEndReason(err); e != sandbox.SessionOpen {
			end = e.String()
		}
		got := struct {
			Code, NotDispatched, SessionEnded string
			AnswerNotBound                    bool
		}{connect.CodeOf(err).String(), nd, end, errors.Is(err, ErrAnswerNotBound)}
		if got != a.Expect {
			t.Errorf("%s: read as %+v, want %+v (%v)", a.Name, got, a.Expect, err)
		}
	}
}
