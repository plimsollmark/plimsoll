package remotehttp

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"golang.org/x/net/netutil"
)

// Run binds only the configured loopback listener. It neither configures a tunnel
// nor chooses a public origin. Canceling ctx stops admissions and closes sandboxes.
func (e *Engine) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", e.cfg.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctl, err := listenControl(filepath.Join(e.cfg.StateDir, "control.sock"))
	if err != nil {
		return err
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	e.mu.Lock()
	if e.closed || e.control != nil {
		e.mu.Unlock()
		cancel()
		_ = ctl.Close()
		return errors.New("remote server already started or closed")
	}
	e.control = ctl
	e.runtimeCancel = cancel
	e.runtimeCalls.Add(1)
	e.mu.Unlock()
	defer cancel()
	controlServer := &http.Server{Handler: http.HandlerFunc(e.controlRequest), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 6 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 1024, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = controlServer.Serve(netutil.LimitListener(ctl, 4)) }()
	go e.maintain(runtimeCtx)
	httpServer := e.HTTPServer()
	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(netutil.LimitListener(listener, maxConnections)) }()
	select {
	case err = <-served:
	case <-runtimeCtx.Done():
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	// Close cancels tool calls before HTTP Shutdown waits for their answers.
	closed := make(chan error, 1)
	go func() { closed <- e.Close(cleanup) }()
	shutdownErr := httpServer.Shutdown(cleanup)
	_ = controlServer.Close()
	closeErr := <-closed
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return errors.Join(err, shutdownErr, closeErr)
}

func (e *Engine) maintain(ctx context.Context) {
	defer e.runtimeCalls.Done()
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			e.expire(ctx)
		}
	}
}

// Expiration also closes idle sandboxes. Token refusal alone would leave their
// resources charged until the daemon's independent session lifetime elapsed.
// The tool server's own list of workspaces is the one complete record of them.
func (e *Engine) expire(ctx context.Context) {
	if e.tools == nil {
		return
	}
	ids := e.tools.Grants()
	e.state.mu.Lock()
	var expired []string
	now := e.state.now()
	for _, id := range ids {
		if !activeGrant(&e.state.data, e.state.data.Grants[id], now) {
			expired = append(expired, id)
		}
	}
	e.state.mu.Unlock()
	for _, id := range expired {
		e.cancelGrant(ctx, id)
	}
}

// OperatorResult contains no daemon credential, access token, receipt content or
// browser data. EnrollmentCode is issued only over an owner-only local channel.
type OperatorResult struct {
	ExecutionEnabled bool   `json:"execution_enabled"`
	Disabled         bool   `json:"disabled"`
	Passkeys         int    `json:"passkeys"`
	ActiveGrants     int    `json:"active_grants"`
	CleanupComplete  bool   `json:"cleanup_complete"`
	EnrollmentCode   string `json:"enrollment_code,omitempty"`
	EnrollmentURL    string `json:"enrollment_url,omitempty"`
}

func (e *Engine) status() OperatorResult {
	healthy := e.audit.healthy()
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	r := OperatorResult{Disabled: e.state.failed || e.state.data.Disabled || !healthy, Passkeys: len(e.state.data.Credentials), CleanupComplete: true}
	r.ExecutionEnabled = !e.cfg.Enrollment && e.cfg.ExecutionEnabled && !r.Disabled
	for _, g := range e.state.data.Grants {
		if activeGrant(&e.state.data, g, e.state.now()) {
			r.ActiveGrants++
		}
	}
	return r
}

func (e *Engine) operate(ctx context.Context, command string) (OperatorResult, error) {
	complete := true
	switch command {
	case "status":
	case "enroll":
		code, err := e.EnrollmentCode()
		if err != nil {
			return OperatorResult{}, err
		}
		r := e.status()
		r.EnrollmentCode = code
		r.EnrollmentURL = e.cfg.PublicURL + "/owner/enroll"
		return r, nil
	case "disable":
		var err error
		complete, err = e.Disable(ctx)
		if err != nil {
			return OperatorResult{}, err
		}
	case "enable":
		if e.cfg.Enrollment {
			return OperatorResult{}, errors.New("stop enrollment-only serving and start serve-http before enabling")
		}
		if err := e.Enable(); err != nil {
			return OperatorResult{}, err
		}
	case "reset-owner":
		var err error
		complete, err = e.Disable(ctx)
		if err != nil {
			return OperatorResult{}, err
		}
		if err = e.state.update(resetOwner); err != nil {
			return OperatorResult{}, err
		}
		e.audit.event("owner_reset", "", "")
	default:
		return OperatorResult{}, errors.New("unknown local operator command")
	}
	r := e.status()
	r.CleanupComplete = complete
	return r, nil
}

func resetOwner(d *stateData) error {
	d.Disabled = true
	d.OwnerID = []byte(randomID("owner_"))
	d.Credentials = nil
	d.Clients = map[string]clientRecord{}
	d.Codes = map[string]codeRecord{}
	d.BootstrapHash = ""
	d.BootstrapExpires = time.Time{}
	return nil
}

func (e *Engine) controlRequest(w http.ResponseWriter, r *http.Request) {
	if !e.enter() {
		reject(w, 503)
		return
	}
	defer e.httpCalls.Done()
	securityHeaders(w)
	if r.Method != "POST" || r.URL.Path != "/" || r.URL.RawQuery != "" || r.Host != "local" {
		reject(w, 404)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		Command string `json:"command"`
	}
	if parseJSON(r, &in) != nil {
		reject(w, 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	result, err := e.operate(ctx, in.Command)
	if err != nil {
		jsonReply(w, 503, map[string]string{"error": "local operation failed; inspect state and process status"})
		return
	}
	jsonReply(w, 200, result)
}

// Operator uses the running process when present. Without one, the exclusive
// state lock protects offline disable, status and owner recovery. Enable requires
// the authenticated daemon checks of a running normal server.
func Operator(ctx context.Context, dir, command string) (OperatorResult, error) {
	if err := privateDir(dir); err != nil {
		return OperatorResult{}, err
	}
	result, connected, err := callControl(ctx, filepath.Join(dir, "control.sock"), command)
	if connected || err != nil {
		return result, err
	}
	s, err := openStore(dir, "")
	if err != nil {
		return OperatorResult{}, err
	}
	defer s.close()
	e := newEngine(Config{PublicURL: s.data.Origin, StateDir: dir, Enrollment: true}, s)
	e.audit, err = openAudit(dir)
	if err != nil {
		return OperatorResult{}, err
	}
	defer e.audit.close()
	return e.operate(ctx, command)
}
