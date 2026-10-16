package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/plimsollmark/plimsoll/sandbox"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
)

func grantClients(t *testing.T, cfg server.Config) (*server.Server, *conn, *conn) {
	t.Helper()
	s, c := grantConns(t, cfg, map[string]string{"first": "app_first", "second": "app_second"})
	return s, c["first"], c["second"]
}

// grantConns registers each grant ID under its app group and connects a client to each.
func grantConns(t *testing.T, cfg server.Config, groups map[string]string) (*server.Server, map[string]*conn) {
	t.Helper()
	cfg.RequireGrant = true
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for id, group := range groups {
		if err := s.RegisterGrant(id, group); err != nil {
			t.Fatal(err)
		}
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s.MCP() }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := s.GrantContext(r.Context(), r.URL.Query().Get("test_grant"))
		if err != nil {
			http.Error(w, "not authorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	conns := map[string]*conn{}
	for id := range groups {
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "grant-test", Version: "0"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "?test_grant=" + id}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cs.Close() })
		conns[id] = &conn{t: t, s: s, cs: cs}
	}
	return s, conns
}

func TestConnectorGrantsOwnHandlesRecordsAndCapacityListings(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 8})
	cfg := local(d.URL)
	cfg.MaxSandboxes = 1
	s, a, b := grantClients(t, cfg)
	handle := a.ok("open_sandbox", nil)["sandbox"].(string)
	run := a.ok("run_code", map[string]any{"code": "private data", "sandbox": handle})
	for _, tool := range []string{"run_code", "close_sandbox"} {
		args := map[string]any{"sandbox": handle}
		if tool == "run_code" {
			args["code"] = "read private data"
		}
		if r := b.call(tool, args); !r.IsError {
			t.Fatalf("other grant used %s", tool)
		}
	}
	if r := b.call("get_record", map[string]any{"recordSha256": run["recordSha256"]}); !r.IsError {
		t.Fatal("other grant read record")
	}
	r := b.call("open_sandbox", nil)
	if !r.IsError {
		t.Fatal("process-wide sandbox cap bypassed")
	}
	var f failure
	if err := json.Unmarshal([]byte(text(r)), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.IdleSandboxes) > 0 {
		t.Fatalf("another grant's handles leaked: %v", f.IdleSandboxes)
	}
	if !strings.Contains(f.Summary, "1 of them belong to another connection") {
		t.Fatalf("the refusal did not say another connection holds the cap: %s", f.Summary)
	}
	a.ok("get_record", map[string]any{"recordSha256": run["recordSha256"]})
	if err := s.RevokeGrant(context.Background(), "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantContext(context.Background(), "first"); err == nil {
		t.Fatal("revoked context accepted")
	}
	if err := s.RegisterGrant("first", "app"); err == nil {
		t.Fatal("revoked grant resurrected")
	}
	b.ok("open_sandbox", nil)
}

// With a cap of three, one connection holds at most two: its third open is refused,
// naming only its own idle sandboxes, and another connection still opens one.
func TestOneConnectionNeverFillsTheServer(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 8})
	cfg := local(d.URL)
	cfg.MaxSandboxes = 3
	_, a, b := grantClients(t, cfg)
	own := []string{a.ok("open_sandbox", nil)["sandbox"].(string), a.ok("open_sandbox", nil)["sandbox"].(string)}
	r := a.call("open_sandbox", nil)
	if !r.IsError {
		t.Fatal("one connection took every place in the server")
	}
	var f failure
	if err := json.Unmarshal([]byte(text(r)), &f); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Summary, "at most 2 of this server's 3 sandboxes") {
		t.Fatalf("the refusal did not state the connection's share: %s", f.Summary)
	}
	slices.Sort(own)
	if !slices.Equal(f.IdleSandboxes, own) {
		t.Fatalf("idle sandboxes %v, want this connection's own %v", f.IdleSandboxes, own)
	}
	b.ok("open_sandbox", nil)
}

// Two grants of one app share its part of the cap: approving an app twice does not
// let it fill the server, and another app still opens one.
func TestOneAppNeverFillsTheServerThroughTwoGrants(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 8})
	cfg := local(d.URL)
	cfg.MaxSandboxes = 3
	_, c := grantConns(t, cfg, map[string]string{"chat_one": "app_a", "chat_two": "app_a", "other": "app_b"})
	c["chat_one"].ok("open_sandbox", nil)
	c["chat_two"].ok("open_sandbox", nil)
	r := c["chat_two"].call("open_sandbox", nil)
	if !r.IsError || !strings.Contains(text(r), "one approved app may hold at most 2") {
		t.Fatalf("a second grant of the same app took a third place: %s", text(r))
	}
	c["other"].ok("open_sandbox", nil)
}

func TestRevokeCancelsActiveAndQueuedCallsWithoutStoppingOtherGrant(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 8})
	s, a, b := grantClients(t, local(d.URL))
	handle := a.ok("open_sandbox", nil)["sandbox"].(string)
	blocked := d.Provider.Blocked()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "run_code", Arguments: map[string]any{"code": fakedaemon.Block, "sandbox": handle}})
	}()
	select {
	case <-blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("call did not start")
	}
	queued := make(chan struct{})
	go func() {
		defer close(queued)
		_, _ = a.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "run_code", Arguments: map[string]any{"code": "queued", "sandbox": handle}})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.RevokeGrant(ctx, "first"); err != nil {
		var ended *sandbox.SessionEndedError
		if !errors.As(err, &ended) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		t.Log("revocation reports an unconfirmed close after canceling an unanswered call")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("active call not canceled")
	}
	select {
	case <-queued:
	case <-ctx.Done():
		t.Fatal("queued call not canceled")
	}
	b.ok("run_code", map[string]any{"code": "other grant still works"})
}

// A restarted process has no registered workspace yet. Revocation must still
// prevent an earlier authentication from registering that grant afterward.
func TestRevokeBeforeFirstRegistrationKeepsTombstone(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg := local(d.URL)
	cfg.RequireGrant = true
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	if err = s.RevokeGrant(context.Background(), "revoked_before_first_request"); err != nil {
		t.Fatal(err)
	}
	if err = s.RegisterGrant("revoked_before_first_request", "app"); err == nil {
		t.Fatal("revocation raced first registration and authority returned")
	}
	if err = s.RegisterGrant("independent_grant", "app"); err != nil {
		t.Fatal(err)
	}
}

// Every authorization registers a new grant, so tombstones of revoked grants
// must not count against the workspace cap forever.
// A request that authenticated before its grant was revoked, and arrives after the
// tombstone was forgotten and a new workspace registered under the same ID, is
// refused: its context names the old workspace, not the ID.
func TestALateRequestCannotEnterARevivedWorkspace(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 8})
	cfg := local(d.URL)
	cfg.RequireGrant = true
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	if err = s.RegisterGrant("victim", "app"); err != nil {
		t.Fatal(err)
	}
	stale, err := s.GrantContext(context.Background(), "victim")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeGrant(context.Background(), "victim"); err != nil {
		t.Fatal(err)
	}
	for i := range 255 {
		id := fmt.Sprintf("grant_%d", i)
		if err = s.RegisterGrant(id, "app"); err != nil {
			t.Fatal(err)
		}
		if err = s.RevokeGrant(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	server.AgeTombstones(s, 2*time.Minute)
	// Another registration makes room, which forgets every finished old tombstone.
	if err = s.RegisterGrant("trigger", "app"); err != nil {
		t.Fatal(err)
	}
	if err = s.RegisterGrant("victim", "app"); err != nil {
		t.Fatalf("the forgotten ID could not be registered again: %v", err)
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s.MCP() }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := server.CarryGrant(r.Context(), stale)
		if r.URL.Query().Get("fresh") != "" {
			fresh, err := s.GrantContext(r.Context(), "victim")
			if err != nil {
				http.Error(w, "not authorized", http.StatusUnauthorized)
				return
			}
			ctx = fresh
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer ts.Close()
	connect := func(url string) *conn {
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "late-test", Version: "0"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: url}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cs.Close() })
		return &conn{t: t, s: s, cs: cs}
	}
	r := connect(ts.URL).call("run_code", map[string]any{"code": "late"})
	if !r.IsError || !strings.Contains(text(r), "absent or revoked") {
		t.Fatalf("a request issued for the revoked workspace ran in its successor: %s", text(r))
	}
	connect(ts.URL+"?fresh=1").ok("run_code", map[string]any{"code": "fresh"})
}

func TestFinishedTombstonesMakeRoomForNewGrants(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg := local(d.URL)
	cfg.RequireGrant = true
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	for i := range 256 {
		id := fmt.Sprintf("grant_%d", i)
		if err = s.RegisterGrant(id, "app"); err != nil {
			t.Fatal(err)
		}
		if err = s.RevokeGrant(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.RegisterGrant("too_soon", "app"); err == nil {
		t.Fatal("a fresh tombstone was forgotten")
	}
	server.AgeTombstones(s, 2*time.Minute)
	if err = s.RegisterGrant("after_the_hold", "app"); err != nil {
		t.Fatalf("finished tombstones still hold the cap: %v", err)
	}
	if got := s.Grants(); len(got) != 1 || got[0] != "after_the_hold" {
		t.Fatalf("live workspaces: %v", got)
	}
}
