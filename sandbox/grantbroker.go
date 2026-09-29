package sandbox

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// HostAPISocketEnv names the environment variable the injected host client reads
// for the Unix socket it sends its calls to.
const HostAPISocketEnv = "HOST_API_SOCKET"

// GrantBroker is one granted run's host-API broker for a provider outside this
// package: the shared enforcement core (the frozen grant, the credential minted
// for this run, the exact-route check, the budgets, the upstream request and the
// metadata-only call trace) behind the HTTP framing the docker provider's socket
// serves, which the injected client speaks. Serve it on connections that carry
// only what the guest sent: everything arriving on them is checked here, and the
// credential never leaves this process.
type GrantBroker struct {
	core *brokerSession
}

// NewGrantBroker mints the run's credential (bounded by timeout) and returns the
// broker. The caller closes it when the run ends.
func NewGrantBroker(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (*GrantBroker, error) {
	if grant == nil {
		return nil, errors.New("host api broker: grant is nil")
	}
	core, err := brokerSessionForGrant(ctx, grant, timeout)
	if err != nil {
		return nil, err
	}
	return &GrantBroker{core: core}, nil
}

// Serve serves the broker on l in the background, with the docker socket's server
// settings, and returns the server so the caller can close it.
func (b *GrantBroker) Serve(l net.Listener) *http.Server {
	srv := newBrokerServer(b.core)
	go func() { _ = srv.Serve(l) }()
	return srv
}

// Trace is the run's call trace so far: route templates, statuses and sizes, never
// a path, body or credential. Nil when the run made no call.
func (b *GrantBroker) Trace() *CallTrace { return b.core.traceSnapshot() }

// Close releases the broker's idle upstream connections.
func (b *GrantBroker) Close() { b.core.Close() }

// HostClientSnippet returns code with the injected host client (and the grant's
// preamble) in front of it; the client sends its calls to the socket named by
// HOST_API_SOCKET. Code is returned unchanged for a nil grant.
func HostClientSnippet(code string, grant *HostAPIGrant) string { return withHostSDK(code, grant) }

// HostClientModule returns the same client as a module the project runner preloads
// into every step (the plan's hostSDK); "" for a nil grant.
func HostClientModule(grant *HostAPIGrant) string { return hostSDKModule(grant) }

// newBrokerServer is the HTTP server every socket-framed broker adapter runs: the
// target is taken from RequestURI, exactly as it arrived, because r.URL.Path has
// already lost percent-encoding and cannot prove approve==wire.
func newBrokerServer(core *brokerSession) *http.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := core.Call(r.Context(), brokerCall{Method: r.Method, RawTarget: r.RequestURI, Body: r.Body})
		w.Header().Set("Content-Type", resp.ContentType)
		w.WriteHeader(resp.Status)
		_, _ = w.Write(resp.Body)
	})
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
