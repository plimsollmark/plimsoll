package rpc

// Call-level fuzzing of the Connect HTTP edge — framing, content types, and
// compression headers — through the SAME middleware stack plimsolld serves
// (authenticate → concurrency bound → raw byte cap → Connect decode). The
// invariants: arbitrary caller bytes always produce an orderly HTTP response
// (no handler panic, no hang), and a request without valid credentials NEVER
// reaches the sandbox, whatever its framing claims. Plain status-code checks
// would be wrong here — the gRPC protocols encode errors as HTTP 200 — so the
// dispatch counter is the oracle.

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
)

// fuzzProcedures are the live procedure paths plus one retired V1 name, which
// must stay unmapped — never executable.
var fuzzProcedures = []string{
	"/plimsoll.v1.SandboxService/RunJavaScriptV2",
	"/plimsoll.v1.SandboxService/RunProjectV2",
	"/plimsoll.v1.SandboxService/Describe",
	"/plimsoll.v1.SandboxService/RunJavaScript",
}

// newFuzzEdge assembles the daemon's exact HTTP middleware stack around a fake
// sandbox and returns the service so tests can read its dispatch counters.
func newFuzzEdge() (http.Handler, *SandboxService) {
	verifier := fakeVerifier{token: "good", scopes: []string{ScopeCodeRun}}
	svc := NewSandboxService(&fakeSandbox{})
	path, h := plimsollv1connect.NewSandboxServiceHandler(svc,
		connect.WithInterceptors(AuthInterceptor(verifier)),
		connect.WithReadMaxBytes(1<<20),
	)
	mux := http.NewServeMux()
	mux.Handle(path, http.MaxBytesHandler(AuthenticateHTTP(verifier, LimitHTTPConcurrency(4, h)), 1<<20))
	return mux, svc
}

func FuzzHTTPTransport(f *testing.F) {
	edge, svc := newFuzzEdge()

	validJS, _ := proto.Marshal(&plimsollv1.RunJavaScriptV2Request{Code: "1"})
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(validJS)
	_ = zw.Close()

	f.Add(uint8(0), true, "application/proto", "", validJS)
	f.Add(uint8(0), true, "application/proto", "gzip", gz.Bytes())
	f.Add(uint8(0), true, "application/json", "", []byte(`{"code":"1"}`))
	f.Add(uint8(0), true, "application/connect+proto", "", append([]byte{0, 0, 0, 0, byte(len(validJS))}, validJS...))
	f.Add(uint8(0), true, "application/grpc", "", append([]byte{0, 0, 0, 0, byte(len(validJS))}, validJS...))
	f.Add(uint8(1), true, "application/proto", "", []byte("\xff\xff\xff"))
	f.Add(uint8(0), true, "application/proto", "gzip", []byte("not gzip at all"))
	f.Add(uint8(0), false, "application/proto", "", validJS)                              // unauthenticated
	f.Add(uint8(0), false, "application/grpc", "", validJS)                               // unauthenticated, 200-encoding protocol
	f.Add(uint8(3), true, "application/proto", "", validJS)                               // retired V1 route
	f.Add(uint8(2), true, "text/html", "br", []byte("<html>"))                            // junk everywhere
	f.Add(uint8(0), true, "application/connect+proto", "", []byte{0, 255, 255, 255, 255}) // huge envelope claim

	f.Fuzz(func(t *testing.T, proc uint8, auth bool, contentType, encoding string, body []byte) {
		target := fuzzProcedures[int(proc)%len(fuzzProcedures)]
		before, _ := svc.RunCounts()

		req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		if encoding != "" {
			req.Header.Set("Content-Encoding", encoding)
		}
		if auth {
			req.Header.Set("Authorization", "Bearer good")
		}
		rr := httptest.NewRecorder()
		edge.ServeHTTP(rr, req) // a panic here fails the fuzz run outright
		if rr.Code < 200 || rr.Code > 599 {
			t.Fatalf("edge produced a non-HTTP status %d", rr.Code)
		}

		after, _ := svc.RunCounts()
		if !auth && after != before {
			t.Fatalf("unauthenticated %s request dispatched a run (content-type %q)", target, contentType)
		}
		if target == "/plimsoll.v1.SandboxService/RunJavaScript" && after != before {
			t.Fatalf("retired V1 procedure dispatched a run")
		}
	})
}

// TestFuzzEdgeDispatchesValidRequests pins that the fuzz edge is a REAL edge:
// a well-formed authenticated request must actually reach the sandbox, so the
// no-dispatch assertions above cannot pass vacuously.
func TestFuzzEdgeDispatchesValidRequests(t *testing.T) {
	edge, svc := newFuzzEdge()
	body, _ := proto.Marshal(&plimsollv1.RunJavaScriptV2Request{Code: "1"})
	req := httptest.NewRequest(http.MethodPost, "/plimsoll.v1.SandboxService/RunJavaScriptV2", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Authorization", "Bearer good")
	rr := httptest.NewRecorder()
	edge.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid request got %d: %s", rr.Code, rr.Body.String())
	}
	if total, _ := svc.RunCounts(); total != 1 {
		t.Fatalf("dispatched runs = %d, want 1", total)
	}
}
