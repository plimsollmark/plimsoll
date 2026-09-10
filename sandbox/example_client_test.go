package sandbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// inventoryMockGateway serves the subset of the example host API that the documented
// domain SDK calls, with the field shapes the SDK's callers destructure.
func inventoryMockGateway(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/warehouses", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"warehouses":[{"id":"w-1","name":"North","active":true},{"id":"w-2","name":"South","active":false}]}`))
	})
	mux.HandleFunc("/v1/warehouses/w-1/items", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"i-1","sku":"AAA","onHand":12},{"id":"i-2","sku":"BBB","onHand":0}]}`))
	})
	mux.HandleFunc("/v1/items/i-1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"i-1","sku":"AAA","onHand":12,"unitCents":"2500"}`))
	})
	return httptest.NewServer(mux)
}

// TestExampleClientE2E runs agent code that uses the committed example domain SDK
// against a mock host API, through the docker provider's brokered host bridge. It is
// the end-to-end check of the code-mode path: grant -> preamble -> host.* -> route
// allowlist -> upstream.
//
// It deliberately loads the SAME file the documentation tells a reader to copy
// (docs/examples/grants/inventory.client.js) rather than a fixture written for the
// test, so documentation that stops working fails the build.
func TestExampleClientE2E(t *testing.T) {
	requireDocker(t)
	preamble, err := os.ReadFile("../docs/examples/grants/inventory.client.js")
	if err != nil {
		t.Fatalf("read example client: %v", err)
	}
	srv := inventoryMockGateway(t)
	defer srv.Close()

	grant := &HostAPIGrant{
		BaseURL: srv.URL,
		Allow: []HostRoute{
			{http.MethodGet, "/v1/warehouses"},
			{http.MethodGet, "/v1/warehouses/*/items"},
			{http.MethodGet, "/v1/items/*"},
		},
		Minter:   StaticToken("test-token"),
		Preamble: string(preamble),
	}
	d := testDocker()
	res, err := d.RunJavaScript(context.Background(), Request{
		Grant: grant,
		Code: `(async () => {
			const hubs = await inventory.warehouses.list();
			const items = await inventory.warehouses.items("w-1");
			const stocked = items.items.filter((i) => i.onHand > 0).length;
			const one = await inventory.items.get("i-1");
			console.log("OUT " + hubs.warehouses.length + "|" + items.items.length + "|" + stocked + "|" + one.sku + "|" + one.unitCents);
		})().catch((e) => { console.error("ERR " + e.message); process.exit(1); });`,
	})
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "OUT 2|2|1|AAA|2500") {
		t.Fatalf("unexpected output: %q (stderr %q)", res.Stdout, res.Stderr)
	}
}

// TestExampleClientRejectsUngrantedRoute proves the SDK's convenience methods cannot
// widen the grant: adjust() is a real method on the documented client, and the route
// it calls is absent from the Allow list above, so the call is refused.
func TestExampleClientRejectsUngrantedRoute(t *testing.T) {
	requireDocker(t)
	preamble, err := os.ReadFile("../docs/examples/grants/inventory.client.js")
	if err != nil {
		t.Fatalf("read example client: %v", err)
	}
	srv := inventoryMockGateway(t)
	defer srv.Close()

	grant := &HostAPIGrant{
		BaseURL:  srv.URL,
		Allow:    []HostRoute{{http.MethodGet, "/v1/items/*"}},
		Minter:   StaticToken("test-token"),
		Preamble: string(preamble),
	}
	d := testDocker()
	res, err := d.RunJavaScript(context.Background(), Request{
		Grant: grant,
		Code: `(async () => {
			try {
				await inventory.items.adjust("i-1", {delta: -1});
				console.log("OUT reached");
			} catch (e) {
				console.log("OUT refused");
			}
		})();`,
	})
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if !strings.Contains(res.Stdout, "OUT refused") {
		t.Fatalf("an ungranted route was reachable through the SDK: %q (stderr %q)", res.Stdout, res.Stderr)
	}
}
