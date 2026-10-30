package server_test

import (
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
)

func runPrint(c *conn) map[string]any {
	return c.ok("run_code", map[string]any{"code": "print(1)", "files": []any{map[string]any{"path": "data/in.csv", "content": "a,b"}}})
}

// On a daemon that keeps a pool with a sandbox waiting, run_code without a handle is
// one Run cell that asks for it (prefer_warm): the daemon runs it there (the fake
// answers a member's cell as "<language> <n>: <code>"), with its files, under a single
// run's record, and makes no fresh run. The summary says how it ran.
func TestRunCodeWithoutAHandleUsesAWarmSandbox(t *testing.T) {
	d := fakedaemon.Serve(t, fakedaemon.Options{Sessions: 4, Pool: 2, Warm: 5})
	c := connect(t, local(d.URL))
	out := runPrint(c)
	if out["stdout"] != "python 1: print(1)" || out["stderr"] != "data/in.csv\n" || out["exitCode"] != float64(0) || out["stateKept"] != false {
		t.Fatalf("run_code: %v", out)
	}
	if summary, _ := out["summary"].(string); !strings.Contains(summary, "had ready before the call and deleted after it") {
		t.Errorf("summary %q does not say the call ran in a sandbox kept ready", summary)
	}
	rec := c.ok("get_record", map[string]any{"recordSha256": out["recordSha256"]})
	if record, _ := rec["record"].(map[string]any); record["session"] != "" || record["sequence"] != float64(0) {
		t.Errorf("the record is not a single run's: %v", rec)
	}
	if opened := d.Provider.Opened(); d.Calls("Run") != 1 || d.Calls("OpenSession") != 0 || len(opened) != 1 || !opened[0].Options.WarmOnly {
		t.Fatalf("%d Run calls, %d opens over RPC, %d members claimed; want one Run that the daemon served from its pool", d.Calls("Run"), d.Calls("OpenSession"), len(opened))
	}
}

// Without a pool, or with none waiting, the same Run cell runs fresh, and a miss is no
// refusal; the summary says the sandbox was fresh.
func TestRunCodeWithoutAMemberRunsFresh(t *testing.T) {
	for _, o := range []fakedaemon.Options{{Sessions: 4, Warm: 5}, {Sessions: 4, Pool: 2}} {
		d := fakedaemon.Serve(t, o)
		c := connect(t, local(d.URL))
		out := runPrint(c)
		if out["stdout"] != "fresh python: print(1)" || out["stderr"] != "data/in.csv\n" || out["exitCode"] != float64(0) {
			t.Fatalf("run_code (pool %d, %d waiting): %v", o.Pool, o.Warm, out)
		}
		if summary, _ := out["summary"].(string); !strings.Contains(summary, "fresh sandbox; nothing is kept") {
			t.Errorf("summary %q", summary)
		}
		if d.Calls("Run") != 1 || d.Calls("OpenSession") != 0 || len(d.Provider.Opened()) != 0 {
			t.Fatalf("%d Run calls, %d opens, %d members; want one Run and no member", d.Calls("Run"), d.Calls("OpenSession"), len(d.Provider.Opened()))
		}
	}
}
