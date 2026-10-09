package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestE2BOrphanReconcilerKillsOnlyUntrackedStampedSandboxes verifies the safety
// properties of reconciliation (review F3): a sandbox carrying this instance's stamp
// whose lease key is not tracked is killed at any age and in any state, a fresh or
// paused one included; one whose key is tracked (a create or run in flight) is spared
// at any age; one with no lease key is left to its create timeout; and sandboxes
// belonging to a different instance are never touched by that rule even if the
// server-side metadata filter mistakenly returns them. A session sandbox of any
// instance is killed once it is more than e2bReapMargin past the expiry it declares,
// and spared before that, without a declaration, or while this instance tracks it.
func TestE2BOrphanReconcilerKillsOnlyUntrackedStampedSandboxes(t *testing.T) {
	var mu sync.Mutex
	var deleted []string
	past := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	recent := strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/sandboxes":
			if r.Header.Get("X-API-Key") != "k" {
				http.Error(w, "no key", http.StatusUnauthorized)
				return
			}
			if got := r.URL.Query().Get("state"); got != "running,paused" {
				http.Error(w, "state "+got, http.StatusBadRequest)
				return
			}
			switch r.URL.Query().Get("metadata") {
			case "instance=inst-1":
				// Deliberately include a foreign-instance sandbox to prove the
				// client-side re-check.
				_, _ = io.WriteString(w, `[
					{"sandboxID":"sb-orphan","state":"running","metadata":{"sdk":"plimsoll","instance":"inst-1","lease":"l-orphan"}},
					{"sandboxID":"sb-paused-orphan","state":"paused","metadata":{"sdk":"plimsoll","instance":"inst-1","lease":"l-paused"}},
					{"sandboxID":"sb-live","state":"running","metadata":{"sdk":"plimsoll","instance":"inst-1","lease":"l-live"}},
					{"sandboxID":"sb-slow-create","state":"running","metadata":{"sdk":"plimsoll","instance":"inst-1","lease":"l-slow"}},
					{"sandboxID":"sb-foreign","state":"running","metadata":{"sdk":"plimsoll","instance":"other","lease":"l-foreign"}},
					{"sandboxID":"sb-no-lease","state":"running","metadata":{"sdk":"plimsoll","instance":"inst-1"}}
				]`)
			case "session=1":
				fmt.Fprintf(w, `[
					{"sandboxID":"sb-expired-session","state":"paused","metadata":{"sdk":"plimsoll","instance":"crashed","lease":"l-a","session":"1","expires":%q}},
					{"sandboxID":"sb-in-margin","state":"paused","metadata":{"sdk":"plimsoll","instance":"crashed","lease":"l-b","session":"1","expires":%q}},
					{"sandboxID":"sb-tracked-session","state":"running","metadata":{"sdk":"plimsoll","instance":"inst-1","lease":"l-live","session":"1","expires":%q}},
					{"sandboxID":"sb-no-expiry","state":"paused","metadata":{"sdk":"plimsoll","instance":"crashed","lease":"l-c","session":"1"}},
					{"sandboxID":"sb-not-ours","state":"paused","metadata":{"sdk":"other","instance":"crashed","lease":"l-d","session":"1","expires":%q}}
				]`, past, recent, past, past)
			default:
				http.Error(w, "filter "+r.URL.Query().Get("metadata"), http.StatusBadRequest)
			}
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
	e.leases.Track("l-live")
	e.leases.Track("l-slow") // a create whose answer has not arrived yet

	killed, err := e.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	slices.Sort(deleted)
	want := []string{"/sandboxes/sb-expired-session", "/sandboxes/sb-orphan", "/sandboxes/sb-paused-orphan"}
	if killed != len(want) || !slices.Equal(deleted, want) {
		t.Fatalf("killed=%d deleted=%v; want exactly %v", killed, deleted, want)
	}
}

// TestE2BReconcileListsBothStatesByMetadataAcrossPages verifies the listing asks the
// control plane to filter by this instance's stamp (and, for sessions, by session=1),
// for running and paused sandboxes, and follows every page.
func TestE2BReconcileListsBothStatesByMetadataAcrossPages(t *testing.T) {
	var mu sync.Mutex
	var filters []string
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodDelete {
			deleted = append(deleted, r.URL.Path)
			return
		}
		q := r.URL.Query()
		filters = append(filters, q.Get("metadata")+" state="+q.Get("state")+" next="+q.Get("nextToken"))
		if q.Get("metadata") != "instance=inst-42" {
			_, _ = io.WriteString(w, `[]`)
			return
		}
		if q.Get("nextToken") == "" {
			w.Header().Set("X-Next-Token", "page-2")
			_, _ = io.WriteString(w, `[{"sandboxID":"sb-1","metadata":{"instance":"inst-42","lease":"l-1"}}]`)
			return
		}
		_, _ = io.WriteString(w, `[{"sandboxID":"sb-2","metadata":{"instance":"inst-42","lease":"l-2"}}]`)
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL}
	e.instanceID = "inst-42"
	if n, err := e.ReconcileOrphans(context.Background()); err != nil || n != 2 {
		t.Fatalf("reconcile: killed=%d err=%v, want 2 (one per page)", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"instance=inst-42 state=running,paused next=", "instance=inst-42 state=running,paused next=page-2", "session=1 state=running,paused next="}
	if !slices.Equal(filters, want) {
		t.Fatalf("listings = %q, want %q", filters, want)
	}
}

// TestE2BCreateStampsInstanceAndTracksID verifies every created sandbox carries
// the reconciliation stamp and a lease key that is tracked from before the create
// request is sent until kill() has run, and that a create returning no sandbox
// untracks its key: the lifecycle the reconciler's kill decision depends on.
func TestE2BCreateStampsInstanceAndTracksID(t *testing.T) {
	var createBody []byte
	var stampedMD map[string]string
	var e *E2B
	trackedAtCreate := false
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			createBody, _ = io.ReadAll(r.Body)
			var body struct {
				Metadata map[string]string `json:"metadata"`
			}
			_ = json.Unmarshal(createBody, &body)
			stampedMD = body.Metadata
			trackedAtCreate = e.leases.Tracked(body.Metadata["lease"])
			if fail {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"sandboxID":"sb-9","envdAccessToken":"a","trafficAccessToken":"t"}`)
		case http.MethodGet:
			// Every create reads its new sandbox back and requires its own stamps.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sandboxID": strings.TrimPrefix(r.URL.Path, "/sandboxes/"), "state": "running", "metadata": stampedMD})
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	e = &E2B{APIKey: "k", APIBase: srv.URL}
	vm, err := e.create(context.Background(), 10*time.Second, e2bCreate{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var body struct {
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(createBody, &body); err != nil {
		t.Fatal(err)
	}
	if body.Metadata["sdk"] != "plimsoll" || body.Metadata["instance"] != e.instance() || body.Metadata["lease"] == "" || body.Metadata["lease"] != vm.lease {
		t.Fatalf("metadata = %v, want sdk=plimsoll, this instance's stamp and the sandbox's lease key %q", body.Metadata, vm.lease)
	}
	if !trackedAtCreate {
		t.Fatal("the lease key was not tracked when the create request arrived; a reconcile could kill a create in flight")
	}
	if !e.leases.Tracked(vm.lease) {
		t.Fatal("created sandbox's lease is not tracked in flight")
	}
	e.kill(context.Background(), vm)
	if e.leases.Tracked(vm.lease) || e.leases.Len() != 0 {
		t.Fatal("killed sandbox's lease is still tracked; the reconciler could never reap a failed teardown")
	}
	fail = true
	if _, err := e.create(context.Background(), 10*time.Second, e2bCreate{}); err == nil {
		t.Fatal("a refused create returned a sandbox")
	}
	if !trackedAtCreate || e.leases.Len() != 0 {
		t.Fatalf("a refused create left %d leases tracked", e.leases.Len())
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

// When every delete of a run's microVM fails, kill says so on the run's context
// (TeardownGaveUp), so a caller that meters runs charges the run's whole reservation:
// the microVM bills until its create timeout. A delete that succeeds says nothing.
func TestE2BReportsAKillThatGaveUp(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		e := &E2B{APIKey: "k", APIBase: srv.URL}
		ctx, gaveUp := WatchTeardown(context.Background())
		e.kill(ctx, e2bVM{id: "sb-1"})
		srv.Close()
		if want := status != http.StatusOK; gaveUp() != want {
			t.Errorf("delete answered %d: reported gave up = %v; want %v", status, gaveUp(), want)
		}
	}
}

// A create the control plane answered with no usable sandbox ID leaves a microVM that
// bills until its create timeout with nothing to delete by: create says so on the
// run's context, as a kill that gave up does, so a caller that meters runs charges the
// run's whole reservation.
func TestE2BReportsACreateWithNoUsableID(t *testing.T) {
	for name, body := range map[string]string{
		"no sandbox ID":      `{"envdAccessToken":"a","trafficAccessToken":"t"}`,
		"an ID it won't use": `{"sandboxID":"sb/../x","envdAccessToken":"a","trafficAccessToken":"t"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, body)
				return
			}
			_, _ = io.WriteString(w, `[]`) // the reconciliation's listing finds nothing
		}))
		e := &E2B{APIKey: "k", APIBase: srv.URL}
		ctx, gaveUp := WatchTeardown(context.Background())
		if _, err := e.create(ctx, 10*time.Second, e2bCreate{}); err == nil {
			t.Errorf("%s: create succeeded", name)
		}
		if !gaveUp() {
			t.Errorf("%s: create did not report a microVM it cannot delete", name)
		}
		time.Sleep(50 * time.Millisecond) // let the background reconciliation finish
		srv.Close()
	}
}

// A create whose request reached the control plane but whose answer never came back (a
// connection reset, the run's context ending mid-create) may have made a microVM that
// bills with no ID to delete it by: create reports it as a create with no usable ID does
// and reconciles at once. A create that never reached the control plane reports
// nothing: no microVM can exist.
func TestE2BReportsACreateWhoseAnswerWasLost(t *testing.T) {
	var mu sync.Mutex
	listed := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.ReadAll(r.Body)
			// The request arrived whole; the answer is lost.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		mu.Lock()
		listed++
		mu.Unlock()
		_, _ = io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	e := &E2B{APIKey: "k", APIBase: srv.URL}
	ctx, gaveUp := WatchTeardown(context.Background())
	if _, err := e.create(ctx, 10*time.Second, e2bCreate{}); err == nil {
		t.Fatal("create succeeded with no answer")
	}
	if !gaveUp() {
		t.Error("a create whose answer was lost did not report a microVM it cannot delete")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := listed
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no reconciliation after a create whose answer was lost")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Nothing listening: the request never left, so nothing can bill.
	closed := httptest.NewServer(http.NotFoundHandler())
	base := closed.URL
	closed.Close()
	e = &E2B{APIKey: "k", APIBase: base}
	ctx, gaveUp = WatchTeardown(context.Background())
	if _, err := e.create(ctx, 10*time.Second, e2bCreate{}); err == nil {
		t.Fatal("create succeeded with nothing listening")
	}
	if gaveUp() {
		t.Error("a create that never reached the control plane reported a microVM")
	}

	// A context already done sends nothing.
	e = &E2B{APIKey: "k", APIBase: srv.URL}
	done, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, gaveUp = WatchTeardown(done)
	if _, err := e.create(ctx, 10*time.Second, e2bCreate{}); err == nil {
		t.Fatal("create succeeded on a context already done")
	}
	if gaveUp() {
		t.Error("a create on a context already done reported a microVM")
	}
}

// lostAnswerTransport takes the whole create request, as a control plane would, then
// fails without calling any httptrace hook, as an embedder's transport may.
type lostAnswerTransport struct{ got atomic.Int32 }

func (l *lostAnswerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}
	if r.Method == http.MethodPost {
		l.got.Add(1)
	}
	return nil, errors.New("response lost")
}

// A create sent through a transport that never reports the request written, and lost
// there, may still have made a microVM: the error, not the hook, decides.
func TestE2BReportsALostCreateWithoutTraceHooks(t *testing.T) {
	tr := &lostAnswerTransport{}
	e := &E2B{APIKey: "k", APIBase: "https://api.example.invalid", HTTP: &http.Client{Transport: tr}}
	ctx, gaveUp := WatchTeardown(context.Background())
	if _, err := e.create(ctx, 10*time.Second, e2bCreate{}); err == nil {
		t.Fatal("create succeeded with its answer lost")
	}
	if tr.got.Load() != 1 {
		t.Fatalf("the transport saw %d creates; want 1", tr.got.Load())
	}
	if !gaveUp() {
		t.Error("a create lost inside a transport without trace hooks did not report a microVM it cannot delete")
	}
	if e.leases.Len() != 0 {
		t.Errorf("a lost create left %d leases tracked; the reconciler could never reap its microVM", e.leases.Len())
	}
}

// The control plane's answer decides only when it is a refusal: a 4xx made nothing.
// A 5xx (a proxy timing out after the control plane started a VM) or a 2xx other than
// 200 and 201 proves nothing about creation, so the run is charged as a lost create.
func TestE2BCreateAnswerDecidesOnlyWhenARefusal(t *testing.T) {
	for _, tc := range []struct {
		status int
		lost   bool
	}{
		{http.StatusBadRequest, false},
		{http.StatusForbidden, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
		{http.StatusAccepted, true},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(tc.status)
				return
			}
			_, _ = io.WriteString(w, `[]`) // the reconciliation's listing finds nothing
		}))
		e := &E2B{APIKey: "k", APIBase: srv.URL}
		ctx, gaveUp := WatchTeardown(context.Background())
		if _, err := e.create(ctx, 10*time.Second, e2bCreate{}); err == nil {
			t.Errorf("HTTP %d: create succeeded", tc.status)
		}
		if gaveUp() != tc.lost {
			t.Errorf("HTTP %d: reported a microVM it cannot delete = %v; want %v", tc.status, gaveUp(), tc.lost)
		}
		if e.leases.Len() != 0 {
			t.Errorf("HTTP %d: %d leases left tracked", tc.status, e.leases.Len())
		}
		time.Sleep(50 * time.Millisecond) // let a background reconciliation finish
		srv.Close()
	}
}
