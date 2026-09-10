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
func EgressGuardHTTPHandler(guard EgressGuardCapable, guardPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != guardPath || r.URL.RawQuery != "" {
			http.NotFound(w, r)
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
		resp := guard.EgressGuardCall(r.Context(), r.Header.Get(E2BGuardHeader), in.Method, in.Path, append([]byte(nil), in.Body...))
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
