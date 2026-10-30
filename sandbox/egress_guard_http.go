package sandbox

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/internal/unreadbody"
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

// EgressGuardRawPath is the route segment under a provider's guard path that carries a
// standard client's request as it is: a target of guardPath + "/raw" + <target> reaches
// the broker core as <target>. A provider hands guardEndpoint.URL + EgressGuardRawPath
// to a guest as a client library's base URL.
const EgressGuardRawPath = "/raw"

// EgressGuardHTTPHandler is the canonical HTTP framing over EgressGuardCall. It serves
// two framings over one credential (EgressGuardHeader) and one set of limits. The JSON
// envelope at guardPath, one POST per call carrying {method, path, body}, is what the
// injected host.* client sends. The raw route under guardPath + "/raw/" carries a
// standard client's request as it is: the method, the target that follows the prefix
// (cut from RequestURI as it arrived, so an encoded or non-canonical target reaches the
// core whole and is refused there), the headers (of which the grant's pass list
// decides), and the body, capped at the broker's own request limit. Guard credentials
// only exist in the process that opened the run, so whatever serves the public guard URL
// must host the same provider instance that launches runs — the daemon does exactly
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
	rawPrefix := guardPath + EgressGuardRawPath + "/"
	// Every refusal below answers without reading the body. On HTTP/1.x Go's server
	// would read a small unread body before writing that answer, so a caller with no
	// credential could hold each refusal until the read timeout by sending its body
	// slowly; unreadbody closes the connection instead.
	return unreadbody.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every answer written here is the guard's own, so each carries the no-retry
		// mark a standard client reads (brokerNoRetryHeader); an upstream's answer,
		// written by writeBrokerResponse below, never does.
		w.Header().Set(brokerNoRetryHeader, "false")
		var call GuardRequest
		raw := false
		target := requestTarget(r.RequestURI)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == guardPath && r.URL.RawQuery == "":
		case strings.HasPrefix(target, rawPrefix):
			// The target as sent, not URL.Path: the core's approve-equals-wire check
			// needs the bytes the client wrote, and r.URL has already decoded them.
			raw = true
			call = GuardRequest{Method: r.Method, RawTarget: target[len(guardPath)+len(EgressGuardRawPath):], Headers: r.Header}
		default:
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
		// The raw route's body is the request body itself: the broker reads it under the
		// matched route's limit (the default, or the profile's raised one for an upload
		// route), so here it is bounded only by the most any profile may allow; the
		// envelope's cap covers the JSON around a body of the default size.
		bodyCap := int64(maxEgressGuardEnvelopeBytes)
		if raw {
			bodyCap = MaxRouteRequestBytes
		}
		if r.ContentLength > bodyCap {
			// Refused at constant cost, like the credential: the MaxBytesReader below
			// trips only once the bytes arrive, so a declared 100 MB held a slot until
			// the body deadline.
			http.Error(w, "egress guard request too large", http.StatusRequestEntityTooLarge)
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
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(egressGuardBodyDeadline))
		if raw {
			// The body is not read here: the broker reads it under the route's limit and
			// passes an upload through as it arrives, with the deadline moved out by
			// egressGuardBodyDeadline at each piece, so a stalled upload is cut and a long
			// one is not. One byte past the ceiling lets the broker see that a body at the
			// ceiling has more.
			call.Body = readDeadlineReader{r: http.MaxBytesReader(w, r.Body, bodyCap+1), rc: rc, idle: egressGuardBodyDeadline}
			call.ContentLength = r.ContentLength
		} else {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bodyCap))
			if err != nil {
				http.Error(w, "egress guard request too large or too slow", http.StatusRequestEntityTooLarge)
				return
			}
			var in egressGuardEnvelope
			if err := json.Unmarshal(body, &in); err != nil || strings.TrimSpace(in.Method) == "" || in.Path == "" {
				http.Error(w, "invalid egress guard request", http.StatusBadRequest)
				return
			}
			call = GuardRequest{Method: in.Method, RawTarget: in.Path, Body: bytes.NewReader(in.Body), ContentLength: int64(len(in.Body))}
		}
		call.Stream = httpSink{w}
		resp := guard.EgressGuardCall(r.Context(), token, call)
		if resp.Streamed {
			return // the sink wrote it piece by piece
		}
		if !resp.FromBroker {
			w.Header().Del(brokerNoRetryHeader)
		}
		writeBrokerResponse(w, brokerResponse{Status: resp.Status, ContentType: resp.ContentType, Body: resp.Body, FromBroker: resp.FromBroker})
	}))
}

// requestTarget is the path-and-query part of a request target as the client wrote it:
// an origin-form target ("/v1/x") unchanged, and for an absolute-form target
// ("https://guard.example/v1/x", which a proxy in front of the guard may send) the part
// from the first "/" after the authority. Anything else (a CONNECT authority, "*") is
// returned as is and matches no route.
func requestTarget(requestURI string) string {
	if strings.HasPrefix(requestURI, "/") {
		return requestURI
	}
	scheme := strings.Index(requestURI, "://")
	if scheme < 0 {
		return requestURI
	}
	rest := requestURI[scheme+3:]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		return rest[slash:]
	}
	return requestURI
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
