package sandbox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestWasmHostAPIGrantUsesSharedBroker(t *testing.T) {
	type capturedRequest struct {
		method, path, auth, contentType, accept, body string
	}
	captured := make(chan capturedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured <- capturedRequest{
			method:      r.Method,
			path:        r.URL.RequestURI(),
			auth:        r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			accept:      r.Header.Get("Accept"),
			body:        string(body),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	const token = "wasm-bearer-must-stay-in-go"
	grant := &HostAPIGrant{
		BaseURL: upstream.URL,
		Allow:   []HostRoute{{Method: "POST", Path: "/v1/lights/*/on"}},
		Minter:  StaticToken(token),
		Scopes:  []string{"lights:write"},
	}
	w := testWasm()
	if !w.SupportsJavaScriptGrants() {
		t.Fatal("WASM must advertise JavaScript grant support")
	}
	res, err := w.RunJavaScript(context.Background(), Request{
		Code:  `host.post("/v1/lights/kitchen/on", {level: 42}).then(function(v){console.log("grant-ok:" + v.ok)}, function(e){console.log("grant-error:" + e.message)})`,
		Grant: grant,
	})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "grant-ok:true") {
		t.Fatalf("result = exit %d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if strings.Contains(res.Stdout, token) || strings.Contains(res.Stderr, token) {
		t.Fatal("credential leaked into guest-visible output")
	}

	got := <-captured
	if got.method != http.MethodPost || got.path != "/v1/lights/kitchen/on" {
		t.Errorf("upstream request = %s %s, want POST /v1/lights/kitchen/on", got.method, got.path)
	}
	if got.auth != "Bearer "+token {
		t.Errorf("Authorization = %q, want broker-injected bearer", got.auth)
	}
	if got.contentType != "application/json" || got.accept != "application/json" {
		t.Errorf("broker headers = content-type %q accept %q", got.contentType, got.accept)
	}
	if got.body != `{"level":42}` {
		t.Errorf("body = %q, want exact JSON body", got.body)
	}
	if res.CallTrace == nil || len(res.CallTrace.Calls) != 1 {
		t.Fatalf("trace = %+v, want one call", res.CallTrace)
	}
	row := res.CallTrace.Calls[0]
	if row.Route != "/v1/lights/*/on" || row.Method != http.MethodPost || row.Status != http.StatusOK {
		t.Errorf("trace row = %+v, want redacted POST template and 200", row)
	}
}

func TestWasmNativeBridgeCannotBypassRawTargetChecks(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	grant := &HostAPIGrant{
		BaseURL: upstream.URL,
		Allow:   []HostRoute{{Method: "GET", Path: "/v1/lights/*"}},
	}
	// Call the low-level native primitive directly, bypassing the cooperative JS
	// SDK gate. The provider-neutral Go broker must still reject encoded targets.
	res, err := testWasm().RunJavaScript(context.Background(), Request{
		Code:  `var r=__coderunner_host_call(JSON.stringify({method:"GET",path:"/v1/%6cights/kitchen"}));console.log(r.status)`,
		Grant: grant,
	})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "403") {
		t.Fatalf("result = exit %d stdout=%q stderr=%q, want broker denial", res.ExitCode, res.Stdout, res.Stderr)
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("encoded target reached upstream %d times", got)
	}
	if res.CallTrace == nil || res.CallTrace.Denied != 1 || len(res.CallTrace.Calls) != 0 {
		t.Fatalf("trace = %+v, want one metadata-only denial", res.CallTrace)
	}
}

func TestWasmNativeBridgeWithoutGrantFailsClosed(t *testing.T) {
	res, err := testWasm().RunJavaScript(context.Background(), Request{
		Code: `var r=__coderunner_host_call(JSON.stringify({method:"GET",path:"/"}));console.log(r.status)`,
	})
	if err != nil {
		t.Fatalf("RunJavaScript: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "503") {
		t.Fatalf("result = exit %d stdout=%q stderr=%q, want fail-closed 503", res.ExitCode, res.Stdout, res.Stderr)
	}
	if res.CallTrace != nil {
		t.Fatalf("grant-free run produced a trace: %+v", res.CallTrace)
	}
}
