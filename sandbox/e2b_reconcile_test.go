package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestE2BOrphanReconcilerKillsOnlyUntrackedStampedSandboxes verifies the three
// safety properties of reconciliation: an untracked sandbox carrying this
// instance's stamp and older than the grace window is killed; a tracked
// (in-flight) sandbox is spared regardless of age; and sandboxes belonging to a
// different instance are never touched even if the server-side metadata filter
// mistakenly returns them.
func TestE2BOrphanReconcilerKillsOnlyUntrackedStampedSandboxes(t *testing.T) {
	var mu sync.Mutex
	var deleted []string
	old := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	young := time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sandboxes":
			if r.Header.Get("X-API-Key") != "k" {
				http.Error(w, "no key", http.StatusUnauthorized)
				return
			}
			// Deliberately include a foreign-instance sandbox to prove the
			// client-side re-check, and a too-young orphan to prove the grace.
			fmt.Fprintf(w, `[
				{"sandboxID":"sb-orphan","startedAt":%q,"metadata":{"sdk":"plimsoll","instance":"inst-1"}},
				{"sandboxID":"sb-live","startedAt":%q,"metadata":{"sdk":"plimsoll","instance":"inst-1"}},
				{"sandboxID":"sb-foreign","startedAt":%q,"metadata":{"sdk":"plimsoll","instance":"other"}},
				{"sandboxID":"sb-young","startedAt":%q,"metadata":{"sdk":"plimsoll","instance":"inst-1"}},
				{"sandboxID":"sb-no-time","metadata":{"sdk":"plimsoll","instance":"inst-1"}}
			]`, old, old, old, young)
		case r.Method == http.MethodDelete:
			mu.Lock()
			deleted = append(deleted, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	e := &E2B{APIKey: "k", APIBase: srv.URL}
	e.instanceID = "inst-1"
	e.trackVM("sb-live")

	killed, err := e.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if killed != 1 || len(deleted) != 1 || deleted[0] != "/sandboxes/sb-orphan" {
		t.Fatalf("killed=%d deleted=%v; want exactly sb-orphan", killed, deleted)
	}
}

// TestE2BReconcileListFiltersByInstanceMetadata verifies the list request itself
// asks the control plane to filter by this instance's stamp, so reconciliation
// scales without downloading every sandbox on the account.
func TestE2BReconcileListFiltersByInstanceMetadata(t *testing.T) {
	var gotMetadata string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMetadata = r.URL.Query().Get("metadata")
		_, _ = io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL}
	e.instanceID = "inst-42"
	if _, err := e.ReconcileOrphans(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotMetadata != "instance=inst-42" {
		t.Fatalf("metadata filter = %q, want instance=inst-42", gotMetadata)
	}
}

// TestE2BCreateStampsInstanceAndTracksID verifies every created sandbox carries
// the reconciliation stamp and is tracked while in flight, and that kill()
// untracks it — the lifecycle the reconciler's kill decision depends on.
func TestE2BCreateStampsInstanceAndTracksID(t *testing.T) {
	var createBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			createBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"sandboxID":"sb-9","envdAccessToken":"a","trafficAccessToken":"t"}`)
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	e := &E2B{APIKey: "k", APIBase: srv.URL}
	vm, err := e.create(context.Background(), 10*time.Second)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var body struct {
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(createBody, &body); err != nil {
		t.Fatal(err)
	}
	if body.Metadata["sdk"] != "plimsoll" || body.Metadata["instance"] != e.instance() {
		t.Fatalf("metadata = %v, want sdk=plimsoll and this instance's stamp", body.Metadata)
	}
	if !e.trackedVM(vm.id) {
		t.Fatal("created sandbox is not tracked in flight")
	}
	e.kill(vm.id)
	if e.trackedVM(vm.id) {
		t.Fatal("killed sandbox is still tracked; the reconciler could never reap a failed teardown")
	}
}

// TestE2BFloodIsUserRunFailure verifies that a guest flooding its output past the
// stream transfer budget is classified as a FAILED USER RUN (non-zero exit,
// truncated output, no returned error) rather than generic infrastructure.
func TestE2BFloodIsUserRunFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/connect+json")
		f, _ := w.(http.Flusher)
		// Emit large valid data frames until well past the transfer budget (which
		// counts frame payload bytes); never send End.
		chunk := []byte(`{"event":{"data":{"stdout":"` + strings.Repeat("QUJD", 300_000) + `"}}}`)
		payload := frame(0, chunk)
		for i := 0; i*len(chunk) <= maxStreamTransferBytes+len(chunk); i++ {
			if _, err := w.Write(payload); err != nil {
				return
			}
			if f != nil {
				f.Flush()
			}
		}
	}))
	defer srv.Close()

	e := &E2B{APIKey: "k", EnvdHost: func(string) string { return srv.URL }}
	out, err := e.runProcess(context.Background(), e2bVM{id: "sb", accessToken: "tok"}, "node", nil, "")
	if err != nil {
		t.Fatalf("flood returned an infrastructure error: %v", err)
	}
	if out.exitCode != exitOutputFlooded {
		t.Fatalf("exit = %d, want %d (output-flood abort)", out.exitCode, exitOutputFlooded)
	}
	if !out.stdoutTruncated || !out.stderrTruncated {
		t.Fatalf("flood result not marked truncated: %+v", out)
	}
}
