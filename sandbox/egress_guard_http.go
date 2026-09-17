package sandbox

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// The guard envelope contains one broker request. The broker applies its own
// 1 MiB request-body limit after decoding the JSON body; this outer limit also
// bounds malformed envelopes before they reach the provider.
const maxEgressGuardEnvelopeBytes = 2 << 20

// defaultEgressGuardInFlight bounds concurrent envelope decoding when an embedder
// does not size it. A guest makes its host calls one at a time (each host.* call is
// awaited), so in-flight guard requests track live granted runs, not call volume.
const defaultEgressGuardInFlight = 64

type egressGuardEnvelope struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
}

// EgressGuardHTTPHandler is the canonical HTTP framing over EgressGuardCall:
// one POST per brokered call, the per-run credential in E2BGuardHeader, and a
// JSON envelope of {method, path, body}. Guard credentials only exist in the
// process that opened the run, so whatever serves the public guard URL must
// host the same provider instance that launches runs — the daemon does exactly
// this, and the live verification harness serves the same handler.
//
// The guard URL is reachable by anyone who can route to it, so the order of the
// first three steps is the security property, not an optimization: credential
// first (a constant-work lookup), then an admission slot, and only then the
// request body. An unauthenticated flood is refused having bought one map
// lookup each; it never reaches the 2 MiB read or the JSON decode, and it can
// never occupy a slot. maxInFlight caps concurrent decode work for authenticated
// callers (<=0 uses defaultEgressGuardInFlight); the bound lives here rather than
// in one server's wiring so every embedder that serves this handler gets it.
func EgressGuardHTTPHandler(guard EgressGuardCapable, guardPath string, maxInFlight int) http.Handler {
	if maxInFlight <= 0 {
		maxInFlight = defaultEgressGuardInFlight
	}
	slots := make(chan struct{}, maxInFlight)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != guardPath || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		token := r.Header.Get(E2BGuardHeader)
		if !guard.EgressGuardKnownToken(token) {
			// Same status and shape EgressGuardCall would have returned, so pre-body
			// rejection is indistinguishable from the authoritative one.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unknown or expired egress guard credential"}` + "\n"))
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
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEgressGuardEnvelopeBytes))
		if err != nil {
			http.Error(w, "egress guard request too large", http.StatusRequestEntityTooLarge)
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
