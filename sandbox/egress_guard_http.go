package sandbox

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The guard envelope contains one broker request. The broker applies its own
// 1 MiB request-body limit after decoding the JSON body; this outer limit also
// bounds malformed envelopes before they reach the provider.
const maxEgressGuardEnvelopeBytes = 2 << 20

// defaultEgressGuardInFlight bounds concurrent envelope decoding when an embedder
// does not size it. A guest makes its host calls one at a time (each host.* call is
// awaited), so in-flight guard requests track live granted runs, not call volume.
const defaultEgressGuardInFlight = 64

// defaultEgressGuardPerRun is how many of the shared slots one run's credential may
// hold at once when the embedder does not say. plimsolld sizes the shared pool at
// twice its run limit and passes 2, so every live run always has its share: one run
// that opens many requests and dribbles their bodies waits on its own turns instead
// of leaving other runs with none.
const defaultEgressGuardPerRun = 2

// egressGuardTurnWait bounds how long a run's request waits for one of its own turns.
// Its calls are serialized behind its own slow ones, never behind another run's.
const egressGuardTurnWait = 10 * time.Second

// egressGuardBodyDeadline is how long an admitted request has to deliver its envelope
// (at most 2 MiB). The server's 30 s read timeout would let a run hold its slots that
// long while sending nothing; 10 s carries a full envelope at under 2 Mbit/s.
var egressGuardBodyDeadline = 10 * time.Second

type egressGuardEnvelope struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
}

// EgressGuardHTTPHandler is the canonical HTTP framing over EgressGuardCall:
// one POST per brokered call, the per-run credential in EgressGuardHeader, and a
// JSON envelope of {method, path, body}. Guard credentials only exist in the
// process that opened the run, so whatever serves the public guard URL must
// host the same provider instance that launches runs — the daemon does exactly
// this, and the live verification harness serves the same handler.
//
// The guard URL is reachable by anyone who can route to it, so the order of the
// steps is the security property, not an optimization: credential first (a
// constant-work lookup), then the run's own admission (at most maxHostConcurrent of
// its requests in the handler, the broker's own per-run cap, and at most perRun of
// them past this point), then a shared slot, and only then the request body, read
// under egressGuardBodyDeadline. An unauthenticated flood is refused having bought
// one map lookup each; it never reaches the 2 MiB read or the JSON decode, and it can
// never occupy a slot. maxInFlight caps concurrent decode work for authenticated
// callers (<=0 uses defaultEgressGuardInFlight), and perRun keeps one run from taking
// every slot (<=0 uses defaultEgressGuardPerRun); size maxInFlight to at least perRun
// times the number of runs that can be live at once. The bounds live here rather than
// in one server's wiring so every embedder that serves this handler gets them.
func EgressGuardHTTPHandler(guard EgressGuardCapable, guardPath string, maxInFlight, perRun int) http.Handler {
	if maxInFlight <= 0 {
		maxInFlight = defaultEgressGuardInFlight
	}
	if perRun <= 0 {
		perRun = defaultEgressGuardPerRun
	}
	slots := make(chan struct{}, maxInFlight)
	runs := &guardRuns{perRun: perRun, byToken: map[string]*guardRun{}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != guardPath || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		token := r.Header.Get(EgressGuardHeader)
		if !guard.EgressGuardKnownToken(token) {
			// Same status and shape EgressGuardCall would have returned, so pre-body
			// rejection is indistinguishable from the authoritative one.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unknown or expired egress guard credential"}` + "\n"))
			return
		}
		run, ok := runs.admit(token)
		if !ok {
			http.Error(w, "host api broker is at capacity", http.StatusTooManyRequests)
			return
		}
		defer runs.leave(token, run)
		turn := time.NewTimer(egressGuardTurnWait)
		select {
		case run.turns <- struct{}{}:
			turn.Stop()
			defer func() { <-run.turns }()
		case <-turn.C:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "egress guard is at capacity for this run", http.StatusServiceUnavailable)
			return
		case <-r.Context().Done():
			turn.Stop()
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			// Shed rather than queue: a queued request holds its body and its
			// connection open, which is the cost being bounded.
			w.Header().Set("Retry-After", "1")
			http.Error(w, "egress guard is at capacity", http.StatusServiceUnavailable)
			return
		}
		// Not every connection supports a deadline (a test's recorder does not); the
		// server's read timeout still bounds those.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(egressGuardBodyDeadline))
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEgressGuardEnvelopeBytes))
		if err != nil {
			http.Error(w, "egress guard request too large or too slow", http.StatusRequestEntityTooLarge)
			return
		}
		var in egressGuardEnvelope
		if err := json.Unmarshal(raw, &in); err != nil || strings.TrimSpace(in.Method) == "" || in.Path == "" {
			http.Error(w, "invalid egress guard request", http.StatusBadRequest)
			return
		}
		resp := guard.EgressGuardCall(r.Context(), token, in.Method, in.Path, append([]byte(nil), in.Body...))
		if resp.ContentType != "" {
			w.Header().Set("Content-Type", resp.ContentType)
		}
		status := resp.Status
		if status < 100 || status > 599 {
			status = http.StatusBadGateway
		}
		w.WriteHeader(status)
		_, _ = w.Write(resp.Body)
	})
}

// guardRuns tracks each live credential's requests in the handler: how many there
// are, and the turns that bound how many hold a shared slot. A run's entry goes when
// its last request leaves, so the map holds only runs with a request in flight.
type guardRuns struct {
	perRun  int
	mu      sync.Mutex
	byToken map[string]*guardRun
}

type guardRun struct {
	admitted int
	turns    chan struct{}
}

func (g *guardRuns) admit(token string) (*guardRun, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	run := g.byToken[token]
	if run == nil {
		run = &guardRun{turns: make(chan struct{}, g.perRun)}
		g.byToken[token] = run
	}
	if run.admitted >= maxHostConcurrent {
		return nil, false
	}
	run.admitted++
	return run, true
}

func (g *guardRuns) leave(token string, run *guardRun) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if run.admitted--; run.admitted == 0 {
		delete(g.byToken, token)
	}
}
