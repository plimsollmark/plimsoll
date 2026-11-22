package rpc

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// e2bOpenFake answers the E2B control plane and envd for one session open whose open
// program ends with exit and stderr: the sandbox is made and read back as the open
// requires, and the open, the session's first program, exits. A template whose node does
// not know --disable-sigusr1 exits 9 (measured on node v20.9.0, E2B's base template's,
// 2026-11-20); the open's own refusal of its machine exits 2 (e2b_session.js, refuse).
func e2bOpenFake(t *testing.T, exit int, stderr string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	var md map[string]string
	var network map[string]any
	frame := func(payload string) []byte {
		b := make([]byte, 5+len(payload))
		binary.BigEndian.PutUint32(b[1:5], uint32(len(payload)))
		copy(b[5:], payload)
		return b
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sandboxes":
			var body struct {
				Metadata map[string]string `json:"metadata"`
				Network  map[string]any    `json:"network"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			md, network = body.Metadata, body.Network
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"sandboxID":"sb-node20","envdAccessToken":"access","trafficAccessToken":"traffic"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/sandboxes/sb-node20":
			mu.Lock()
			rec := map[string]any{"sandboxID": "sb-node20", "templateID": "base", "state": "running", "metadata": md, "network": network}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(rec)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/process.Process/Start":
			w.Header().Set("Content-Type", "application/connect+json")
			_, _ = w.Write(frame(`{"event":{"start":{"pid":42}}}`))
			_, _ = w.Write(frame(`{"event":{"data":{"stderr":"` + base64.StdEncoding.EncodeToString([]byte(stderr)) + `"}}}`))
			_, _ = w.Write(frame(fmt.Sprintf(`{"event":{"end":{"exitCode":%d,"exited":true}}}`, exit)))
			b := frame(`{}`)
			b[0] = 0x2
			_, _ = w.Write(b)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A session open on an E2B template whose node is too old for the signal flag reaches the
// caller as the provider's refusal: Unimplemented, marked not dispatched (unsupported),
// in words that name the node needed, and never as "internal error <id>", which is what
// the open's exit 9 became before (finding rust-native-helper-35).
func TestE2BSessionOnANodeTooOldIsRefusedNotAnInternalError(t *testing.T) {
	srv := e2bOpenFake(t, 9, "node: bad option: --disable-sigusr1\n")
	e := &sandbox.E2B{APIKey: "k", APIBase: srv.URL, EnvdHost: func(string) string { return srv.URL }}
	svc := NewSandboxService(e)
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	_, err := svc.OpenSession(authenticatedContext("alice"), openReq())
	if err == nil {
		t.Fatal("a session opened on a node too old for the signal flag")
	}
	if code := connect.CodeOf(err); code != connect.CodeUnimplemented {
		t.Errorf("code %v (%v); want Unimplemented", code, err)
	}
	wantNotDispatched(t, "a node too old", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_UNSUPPORTED)
	msg := err.Error()
	if strings.Contains(msg, "internal error") {
		t.Errorf("the refusal reached the caller as an internal error: %q", msg)
	}
	for _, want := range []string{"--disable-sigusr1", "node v22.14.0 or later in the 22 line, v23.7.0 or later in the 23 line, or any v24 or later", "e2b/README.md", "Single runs work"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the caller's message %q does not say %q", msg, want)
		}
	}
}

// The open's own refusal of its machine (e2b_session.js, refuse, exit 2: here a guest uid
// that is already an account) reaches the caller as the provider's refusal: Unimplemented,
// marked not dispatched (environment: the template's fault), in the open's words, and
// never as "internal error <id>", which is what it was until 2026-11-20.
func TestE2BSessionOpenRefusalIsNotAnInternalError(t *testing.T) {
	srv := e2bOpenFake(t, 2, "uid/gid 61000 is already an account here: taken\n")
	e := &sandbox.E2B{APIKey: "k", APIBase: srv.URL, EnvdHost: func(string) string { return srv.URL }}
	svc := NewSandboxService(e)
	svc.Sessions = SessionConfig{MaxSessions: 4, Lifetime: time.Minute, IdleTimeout: time.Minute, DiskBytes: 1 << 20}
	_, err := svc.OpenSession(authenticatedContext("alice"), openReq())
	if err == nil {
		t.Fatal("a session opened after the open refused its machine")
	}
	if code := connect.CodeOf(err); code != connect.CodeUnimplemented {
		t.Errorf("code %v (%v); want Unimplemented", code, err)
	}
	wantNotDispatched(t, "the open's refusal", err, plimsollv1.NotDispatchedReason_NOT_DISPATCHED_REASON_ENVIRONMENT)
	msg := err.Error()
	if strings.Contains(msg, "internal error") {
		t.Errorf("the refusal reached the caller as an internal error: %q", msg)
	}
	for _, want := range []string{"uid/gid 61000 is already an account here: taken", "e2b/README.md", "E2B_TEMPLATE"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the caller's message %q does not say %q", msg, want)
		}
	}
}
