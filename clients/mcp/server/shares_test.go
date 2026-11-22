package server_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
)

// One approved app that fills its share of the receipts directory is refused alone: the
// other app's next call runs. The directory's limit was once one budget for every app, so
// one app's large calls refused every app's, across restarts (hunt-security-23).
func TestOneAppFillingItsReceiptsShareStopsOnlyItself(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg, _, _ := withReceipts(t, local(d.URL))
	cfg.ReceiptsMaxBytes = 4 << 20
	_, c := grantConns(t, cfg, map[string]string{"first": "app_first", "second": "app_second"})
	files := []any{map[string]any{"path": "data.txt", "content": strings.Repeat("x", 512<<10)}}
	refusedAt := 0
	for i := 1; i <= 16 && refusedAt == 0; i++ {
		res := c["first"].call("run_code", map[string]any{"code": "print(1)", "files": files})
		if !res.IsError {
			continue
		}
		var f failure
		if err := json.Unmarshal([]byte(text(res)), &f); err != nil || f.Ran != "no" || f.Refusal != "capacity" || !strings.Contains(f.Summary, "their share") {
			t.Fatalf("the first app's call %d: %s", i, text(res))
		}
		refusedAt = i
	}
	if refusedAt < 2 {
		t.Fatalf("the first app was refused at call %d; its share should hold more than one call", refusedAt)
	}
	c["second"].ok("run_code", map[string]any{"code": "print(2)", "files": files})
	if f := c["first"].fail("open_sandbox", nil); f.Refusal != "capacity" || !strings.Contains(f.Summary, "their share") {
		t.Errorf("the first app's open past its share: %+v", f)
	}
}

// Over stdio there is one caller, the owner, so no share applies: its calls may fill the
// directory to its limit, as before there were shares.
func TestOverStdioTheOwnersCallsMayFillTheWholeLimit(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	cfg, _, _ := withReceipts(t, local(d.URL))
	cfg.ReceiptsMaxBytes = 4 << 20
	c := connect(t, cfg)
	files := []any{map[string]any{"path": "data.txt", "content": strings.Repeat("x", 512<<10)}}
	for range 4 { // well past half the limit
		c.ok("run_code", map[string]any{"code": "print(1)", "files": files})
	}
}

// One connection's calls never push another connection's records out of get_record: each
// keeps its own last KeptRecords (hunt-security-25).
func TestOneConnectionsCallsKeepAnothersRecords(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{})
	_, c := grantConns(t, local(d.URL), map[string]string{"first": "app_first", "second": "app_second"})
	first := c["first"].ok("run_code", map[string]any{"code": "print(1)"})["recordSha256"]
	var oldest any
	for i := range server.KeptRecords + 1 {
		// Distinct code: two runs of the same code in the same millisecond have one record.
		out := c["second"].ok("run_code", map[string]any{"code": fmt.Sprintf("print(%d)", i)})
		if i == 0 {
			oldest = out["recordSha256"]
		}
	}
	c["first"].ok("get_record", map[string]any{"recordSha256": first})
	if f := c["second"].fail("get_record", map[string]any{"recordSha256": oldest}); f.Refusal != "request" {
		t.Errorf("the second connection's oldest record, past its own %d: %+v", server.KeptRecords, f)
	}
}
