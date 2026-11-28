package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/clientcases"
	"github.com/plimsollmark/plimsoll/internal/clientsuite"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// TestSharedCases is the Go client's runner for the shared cases on the client package's
// paths (internal/clientcases): the checkpoint vectors, the daemon answers of
// protocol/testdata/answers.json, every forged attach answer of the attach liar, and the
// record cases of internal/clientcases/testdata/records.json on the attach-lost path.
// Each verdict is judged at the end against what the files state, so a case this runner
// skips fails as surely as a wrong one.
func TestSharedCases(t *testing.T) {
	var vs []clientcases.Verdict
	say := func(id, path string, says any) { vs = append(vs, clientcases.Say(id, path, says)) }
	ctx := context.Background()

	var cps struct{ Valid, Invalid []struct{ Name, JSON string } }
	if err := json.Unmarshal(clientsuite.CheckpointVectors, &cps); err != nil {
		t.Fatal(err)
	}
	for _, c := range cps.Valid {
		got := "refused"
		if _, err := ParseCheckpoint([]byte(c.JSON)); err == nil {
			got = "parsed"
		}
		say("checkpoint/valid/"+c.Name, clientcases.PathCheckpoint, got)
	}
	for _, c := range cps.Invalid {
		got := "parsed"
		if _, err := ParseCheckpoint([]byte(c.JSON)); errors.Is(err, ErrInvalidCheckpoint) {
			got = "refused"
		}
		say("checkpoint/invalid/"+c.Name, clientcases.PathCheckpoint, got)
	}

	// Each answer served over HTTP with its echo and header, read through Describe, as
	// TestEveryClientReadsTheSharedAnswersAlike reads it.
	b, err := os.ReadFile("../protocol/testdata/answers.json")
	if err != nil {
		t.Fatal(err)
	}
	var answers struct {
		Answers []struct {
			Name, ContentType, Body, Echo, Mark string
			Status                              int
		}
	}
	if err := json.Unmarshal(b, &answers); err != nil {
		t.Fatal(err)
	}
	for _, a := range answers.Answers {
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
		_, err := newRemote(t, srv.URL).Describe(ctx)
		srv.Close()
		if err == nil {
			say("answers/"+a.Name, clientcases.PathErrorAnswer, "accepted")
			continue
		}
		nd := ""
		if reason, marked := sandbox.NotDispatchedReason(err); marked {
			nd = reason.String()
		}
		end := ""
		if e := sandbox.SessionEndReason(err); e != sandbox.SessionOpen {
			end = e.String()
		}
		say("answers/"+a.Name, clientcases.PathErrorAnswer, map[string]any{
			"code": connect.CodeOf(err).String(), "notDispatched": nd, "sessionEnded": end, "answerNotBound": errors.Is(err, ErrAnswerNotBound),
			"capacityLimit": capacityLimitName(err),
		})
	}

	// Every forged attach answer, through a whole attach against the attach liar.
	d := clientsuite.ServeAttachLiar(t)
	s, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCell(ctx, cell("1")); err != nil {
		t.Fatal(err)
	}
	cp, err := s.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	attacher := reattachRemote(t, d.URL)
	for _, name := range append(append([]string{}, clientsuite.AttachForgeries...), "none") {
		_, err := attacher.AttachSession(NewTraceContext(ctx, "forge-"+name), cp, AttachOptions{})
		say("attach/forgeries/"+name, clientcases.PathAttachLive, clientcases.SaysOf(err))
	}
	_, gapCp, lost := lostCallSession(t, d.URL, sandbox.IsolationContainer)
	for _, name := range append(append([]string{}, clientsuite.AttachLostForgeries...), "lost-none") {
		_, err := attacher.AttachSession(NewTraceContext(ctx, "forge-"+name), gapCp, AttachOptions{LostRequestSHA256: lost})
		say("attach/lost-forgeries/"+name, clientcases.PathAttachLive, clientcases.SaysOf(err))
	}

	// A call the daemon refuses for its head stops the session: the call after it is
	// refused before it is sent.
	h, err := reattachRemote(t, d.URL).OpenSession(ctx, SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
	if err != nil {
		t.Fatal(err)
	}
	outcome := func(err error) string { o, _, _ := strings.Cut(clientcases.SaysOf(err), "/"); return o }
	_, callErr := h.RunCell(NewTraceContext(ctx, clientsuite.HeadMismatchTrace), cell("1"))
	before := d.SessionCalls(h.Fingerprint())
	_, nextErr := h.RunCell(ctx, cell("1"))
	say("session/head-mismatch", clientcases.PathSessionHead, map[string]any{
		"call": outcome(callErr), "next": outcome(nextErr), "nextSent": d.SessionCalls(h.Fingerprint()) != before,
	})

	// The record cases on the attach-lost path: the lost call's record an attach answer
	// returns, checked by lostRecord, which the attach calls first; the attach refuses
	// every error of it as a broken chain (Remote.AttachSession), as here.
	rb, err := os.ReadFile(filepath.Join("..", clientcases.RecordsFile))
	if err != nil {
		t.Fatal(err)
	}
	var records struct {
		Cases []struct {
			ID    string   `json:"id"`
			Paths []string `json:"paths"`
			Input struct {
				Record     json.RawMessage `json:"record"`
				Checkpoint string          `json:"checkpoint"`
				Lost       string          `json:"lost"`
			} `json:"input"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(rb, &records); err != nil {
		t.Fatal(err)
	}
	for _, c := range records.Cases {
		for _, p := range c.Paths {
			if p != clientcases.PathAttachLost {
				continue
			}
			cp, err := ParseCheckpoint([]byte(c.Input.Checkpoint))
			if err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			m := &plimsollv1.RunRecord{}
			if err := protojson.Unmarshal(c.Input.Record, m); err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			if _, err := lostRecord(cp, c.Input.Lost, m); err != nil {
				err = connect.NewError(connect.CodeDataLoss, fmt.Errorf("%w: the daemon's answer to the attach %s", record.ErrChain, err))
				say(c.ID, p, clientcases.SaysOf(err))
			} else {
				say(c.ID, p, "accept")
			}
		}
	}

	// The shared file-call cases, each a session's calls through RunFiles against the
	// files daemon.
	vs = append(vs, filesCallVerdicts(t)...)

	a, err := clientcases.Load("..")
	if err != nil {
		t.Fatal(err)
	}
	clientcases.Judge(t, a, "go", vs, "client/shared_cases_test.go")
}
