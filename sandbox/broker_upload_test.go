package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// uploadUpstream stands in for an API that takes uploads: it records each request's
// Content-Type, declared length, the bytes it read and their digest, the error its read
// ended with, and signals firstByte once the first bytes of a body have arrived, so a
// test can show that a body reached the API before the guest had finished sending it.
type uploadUpstream struct {
	mu        sync.Mutex
	seen      []uploadSeen
	firstByte chan struct{}
	calls     atomic.Int64
}

type uploadSeen struct {
	path, contentType string
	declared          int64
	read              int64
	digest            [32]byte
	readErr           error
}

func newUploadUpstream(t *testing.T) (*httptest.Server, *uploadUpstream) {
	t.Helper()
	u := &uploadUpstream{firstByte: make(chan struct{}, 16)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		s := uploadSeen{path: r.URL.Path, contentType: r.Header.Get("Content-Type"), declared: r.ContentLength}
		h := sha256.New()
		buf := make([]byte, 64<<10)
		first := true
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if first {
					first = false
					u.firstByte <- struct{}{}
				}
				s.read += int64(n)
				h.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				s.readErr = err
				break
			}
		}
		copy(s.digest[:], h.Sum(nil))
		u.mu.Lock()
		u.seen = append(u.seen, s)
		u.mu.Unlock()
		if s.readErr != nil {
			return // the request broke off; the connection is gone
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"file-1"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, u
}

func (u *uploadUpstream) last(t *testing.T) uploadSeen {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) == 0 {
		t.Fatal("the upstream saw no request")
	}
	return u.seen[len(u.seen)-1]
}

// socketClient is an HTTP client that dials the broker's Unix socket, as the loopback
// forwarder's connections reach it.
func socketClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
}

// uploadGrant is a profile for an upload route: multipart on POST /v1/files with limit
// bytes a call and total bytes a run, beside a JSON route at the default.
func uploadGrant(baseURL string, limit, total int64) *HostAPIGrant {
	files := HostRoute{Method: "POST", Path: "/v1/files"}
	return &HostAPIGrant{
		BaseURL:              baseURL,
		Allow:                []HostRoute{files, {Method: "POST", Path: "/v1/json"}},
		RouteMaxRequestBytes: map[HostRoute]int64{files: limit},
		RouteContentTypes:    map[HostRoute][]string{files: {"multipart/form-data"}},
		MaxRequestBytes:      total,
	}
}

// zeros is an endless body of zero bytes, for a declared length a test must not allocate.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBrokerPassesAnUploadThroughWithinTheRouteLimit: a 3 MiB multipart body on a route
// whose limit the profile raised reaches the API with the guest's media type and
// boundary, its declared length and every byte; it reaches the API while the guest is
// still sending (the upstream has the first piece before the guest writes the second
// half), so the broker holds a piece, not the body; the row records the bytes sent.
func TestBrokerPassesAnUploadThroughWithinTheRouteLimit(t *testing.T) {
	t.Parallel()
	upstream, seen := newUploadUpstream(t)
	b, err := startDockerBroker(uploadGrant(upstream.URL, 8<<20, 64<<20), "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	body := randomBytes(t, 3<<20)
	half := len(body) / 2
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(body[:half])
		select {
		case <-seen.firstByte:
		case <-time.After(10 * time.Second):
			pw.CloseWithError(errors.New("the upstream did not get the first half within 10 s: the body was buffered"))
			return
		}
		_, _ = pw.Write(body[half:])
		pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, "http://broker/v1/files", pr)
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=plimsoll-7f3a9c; charset=utf-8; extra=dropped")
	req.Header.Set("Authorization", "Bearer dummy-from-the-guest")
	resp, err := socketClient(b.sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get(brokerNoRetryHeader) != "" || string(answer) != `{"id":"file-1"}` {
		t.Fatalf("answer = %d %q %q", resp.StatusCode, resp.Header.Get(brokerNoRetryHeader), answer)
	}
	s := seen.last(t)
	if s.contentType != "multipart/form-data; boundary=plimsoll-7f3a9c; charset=utf-8" {
		t.Errorf("Content-Type at the API = %q", s.contentType)
	}
	if s.declared != int64(len(body)) || s.read != int64(len(body)) || s.digest != sha256.Sum256(body) || s.readErr != nil {
		t.Errorf("the API got declared %d, read %d (err %v), digest match %v", s.declared, s.read, s.readErr, s.digest == sha256.Sum256(body))
	}
	trace := b.core.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 || trace.Calls[0].ReqBytes != len(body) || !trace.Calls[0].Delivered || trace.Calls[0].Route != "/v1/files" {
		t.Fatalf("trace = %+v", trace)
	}
	if got := b.core.sent.Load(); got != int64(len(body)) {
		t.Errorf("the run's request bytes = %d, want %d", got, len(body))
	}
}

// TestBrokerRefusesADeclaredUploadOverTheRouteLimit: a body whose declared length is one
// byte over the route's limit is refused with 413 and the no-retry mark before a byte is
// read; the API never sees it, and the run's total is not charged.
func TestBrokerRefusesADeclaredUploadOverTheRouteLimit(t *testing.T) {
	t.Parallel()
	upstream, seen := newUploadUpstream(t)
	b, err := startDockerBroker(uploadGrant(upstream.URL, 8<<20, 64<<20), "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var reads atomic.Int64
	body := &countingReader{r: bytes.NewReader(make([]byte, 8<<20+1))}
	req, _ := http.NewRequest(http.MethodPost, "http://broker/v1/files", body)
	req.ContentLength = 8<<20 + 1
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	resp, err := socketClient(b.sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || resp.Header.Get(brokerNoRetryHeader) != "false" || !strings.Contains(string(msg), "route's limit") {
		t.Fatalf("answer = %d %q %q", resp.StatusCode, resp.Header.Get(brokerNoRetryHeader), msg)
	}
	reads.Store(body.reads.Load())
	if seen.calls.Load() != 0 {
		t.Errorf("the API saw %d requests, want none", seen.calls.Load())
	}
	if trace := b.core.traceSnapshot(); trace == nil || trace.Denied != 1 || len(trace.Calls) != 0 {
		t.Errorf("trace = %+v", trace)
	}
	if got := b.core.sent.Load(); got != 0 {
		t.Errorf("the run's request bytes = %d, want 0", got)
	}
}

// TestBrokerCutsAnUndeclaredUploadAtTheRouteLimit: a chunked body (no declared length)
// that runs past the route's limit is cut there: the API's read of it fails, so it never
// has a complete body; the guest gets 413 with the no-retry mark; the row records the
// limit as the bytes sent and Delivered false; the run's total is charged what went.
func TestBrokerCutsAnUndeclaredUploadAtTheRouteLimit(t *testing.T) {
	t.Parallel()
	upstream, seen := newUploadUpstream(t)
	const limit = 2 << 20
	b, err := startDockerBroker(uploadGrant(upstream.URL, limit, 64<<20), "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.Copy(pw, bytes.NewReader(make([]byte, limit+1<<20)))
		pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, "http://broker/v1/files", pr)
	req.ContentLength = -1 // chunked
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	resp, err := socketClient(b.sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || resp.Header.Get(brokerNoRetryHeader) != "false" || !strings.Contains(string(msg), "route's limit") {
		t.Fatalf("answer = %d %q %q", resp.StatusCode, resp.Header.Get(brokerNoRetryHeader), msg)
	}
	deadline := time.Now().Add(5 * time.Second)
	for seen.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	for time.Now().Before(deadline) {
		seen.mu.Lock()
		n := len(seen.seen)
		seen.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s := seen.last(t)
	if s.readErr == nil || s.read > limit {
		t.Errorf("the API read %d bytes and its read ended with %v; want a broken request at or under %d", s.read, s.readErr, limit)
	}
	trace := b.core.traceSnapshot()
	if trace == nil || len(trace.Calls) != 1 || trace.Calls[0].Delivered || trace.Calls[0].ReqBytes != limit || trace.Calls[0].Status != 0 {
		t.Fatalf("trace = %+v", trace)
	}
	if got := b.core.sent.Load(); got != limit {
		t.Errorf("the run's request bytes = %d, want the limit %d", got, limit)
	}
}

// TestBrokerRefusesABodyTypeTheRouteDoesNotTake: on a route that lists its media types,
// a body of another type is refused with 415 and the no-retry mark before a byte is
// read or sent; JSON still goes through on every route.
func TestBrokerRefusesABodyTypeTheRouteDoesNotTake(t *testing.T) {
	t.Parallel()
	upstream, seen := newUploadUpstream(t)
	b, err := startDockerBroker(uploadGrant(upstream.URL, 8<<20, 64<<20), "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	client := socketClient(b.sock)
	req, _ := http.NewRequest(http.MethodPost, "http://broker/v1/files", bytes.NewReader(make([]byte, 3<<20)))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType || resp.Header.Get(brokerNoRetryHeader) != "false" {
		t.Fatalf("octet-stream on the files route: %d %q", resp.StatusCode, resp.Header.Get(brokerNoRetryHeader))
	}
	if seen.calls.Load() != 0 {
		t.Fatalf("the API saw %d requests, want none", seen.calls.Load())
	}
	req, _ = http.NewRequest(http.MethodPost, "http://broker/v1/files", strings.NewReader(`{"purpose":"user_data"}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || seen.last(t).contentType != "application/json" {
		t.Fatalf("JSON on the files route: %d, Content-Type at the API %q", resp.StatusCode, seen.last(t).contentType)
	}
	if trace := b.core.traceSnapshot(); trace == nil || trace.Denied != 1 || len(trace.Calls) != 1 {
		t.Errorf("trace = %+v", trace)
	}
}

// TestHostAPIGrantRequestContentType: the rule for the Content-Type the broker sends,
// case by case: the guest's type with its boundary and charset alone when the route
// lists it, application/json for JSON or no header, application/json whatever the guest
// said on a route that lists nothing, and a refusal for a type not listed or a parameter
// that is not a boundary or a charset in form.
func TestHostAPIGrantRequestContentType(t *testing.T) {
	t.Parallel()
	files := HostRoute{Method: "POST", Path: "/v1/files"}
	jsonRoute := HostRoute{Method: "POST", Path: "/v1/json"}
	g := &HostAPIGrant{RouteContentTypes: map[HostRoute][]string{files: {"multipart/form-data", "text/csv"}}}
	cases := []struct {
		route HostRoute
		guest string
		want  string
		ok    bool
	}{
		{files, "", "application/json", true},
		{files, "application/json", "application/json", true},
		{files, "application/json; charset=utf-8", "application/json", true},
		{files, "multipart/form-data; boundary=abc", "multipart/form-data; boundary=abc", true},
		{files, "MULTIPART/FORM-DATA; BOUNDARY=abc", "multipart/form-data; boundary=abc", true},
		{files, `multipart/form-data; boundary="a'()+_,-./:=? b"`, `multipart/form-data; boundary="a'()+_,-./:=? b"`, true},
		{files, "multipart/form-data; boundary=x; name=injected; filename=y", "multipart/form-data; boundary=x", true},
		{files, "text/csv; charset=utf-8", "text/csv; charset=utf-8", true},
		{files, "multipart/form-data; boundary=" + strings.Repeat("a", 70), "multipart/form-data; boundary=" + strings.Repeat("a", 70), true},
		{files, "multipart/form-data; boundary=" + strings.Repeat("a", 71), "", false},
		{files, "multipart/form-data; boundary=", "", false},
		{files, `multipart/form-data; boundary="ends with space "`, "", false},
		{files, `multipart/form-data; boundary="has\"quote"`, "", false},
		{files, "multipart/form-data; boundary=a\r\nX-Injected: y", "", false},
		{files, "multipart/form-data; boundary=a;b", "", false},
		{files, "text/csv; charset=utf-8;x", "", false},
		{files, `text/csv; charset="utf 8"`, "", false},
		{files, "application/octet-stream", "", false},
		{files, "multipart/mixed; boundary=a", "", false},
		{files, "text/plain", "", false},
		{files, "not a type", "", false},
		{jsonRoute, "text/plain", "application/json", true},
		{jsonRoute, "multipart/form-data; boundary=a", "application/json", true},
		{jsonRoute, "", "application/json", true},
	}
	for _, tc := range cases {
		got, ok := g.requestContentType(tc.route, tc.guest)
		if got != tc.want || ok != tc.ok {
			t.Errorf("requestContentType(%s, %q) = %q, %v; want %q, %v", tc.route.Path, tc.guest, got, ok, tc.want, tc.ok)
		}
	}
}

// TestBrokerChargesEveryBodyToTheRunsRequestBudget: the run's total counts every body,
// uploads and JSON alike; a declared upload that would cross it is refused before a
// byte is read, a JSON body that would cross it is refused before it is sent, a body
// that lands exactly on it goes, and the next byte is refused.
func TestBrokerChargesEveryBodyToTheRunsRequestBudget(t *testing.T) {
	t.Parallel()
	upstream, seen := newUploadUpstream(t)
	b, err := startDockerBroker(uploadGrant(upstream.URL, 2<<20, 5<<20), "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	client := socketClient(b.sock)
	post := func(target, contentType string, n int) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, "http://broker"+target, bytes.NewReader(make([]byte, n)))
		req.Header.Set("Content-Type", contentType)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		msg, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(msg)
	}
	const multipart = "multipart/form-data; boundary=x"
	steps := []struct {
		target, contentType string
		n, want             int
		msg                 string
	}{
		{"/v1/files", multipart, 2 << 20, 200, ""},
		{"/v1/files", multipart, 2 << 20, 200, ""},
		{"/v1/json", "application/json", 512 << 10, 200, ""},          // 4.5 MiB in all
		{"/v1/files", multipart, 2 << 20, 413, "exhausted"},           // declared: refused before a byte is read
		{"/v1/json", "application/json", 768 << 10, 413, "exhausted"}, // buffered: refused before it is sent
		{"/v1/json", "application/json", 512 << 10, 200, ""},          // lands exactly on 5 MiB
		{"/v1/json", "application/json", 1, 413, "exhausted"},
	}
	for i, s := range steps {
		status, msg := post(s.target, s.contentType, s.n)
		if status != s.want || !strings.Contains(msg, s.msg) {
			t.Fatalf("step %d (%s, %d bytes): %d %q, want %d containing %q", i, s.target, s.n, status, msg, s.want, s.msg)
		}
	}
	if seen.calls.Load() != 4 {
		t.Errorf("the API saw %d requests, want the 4 that fit", seen.calls.Load())
	}
	if got := b.core.sent.Load(); got != 5<<20 {
		t.Errorf("the run's request bytes = %d, want exactly the budget", got)
	}
	if trace := b.core.traceSnapshot(); trace == nil || trace.Denied != 3 || len(trace.Calls) != 4 {
		t.Errorf("trace = %+v", trace)
	}
}

// TestBrokerSettlesAnUndeclaredUploadToWhatWasSent: an upload with no declared length
// holds the route's whole limit from the run's total while it moves, and gives back
// what it did not use when it ends, so a later declared upload that fits what was
// actually sent is admitted.
func TestBrokerSettlesAnUndeclaredUploadToWhatWasSent(t *testing.T) {
	t.Parallel()
	upstream, _ := newUploadUpstream(t)
	b, err := startDockerBroker(uploadGrant(upstream.URL, 2<<20, 3<<20), "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	client := socketClient(b.sock)
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(make([]byte, 1<<20))
		pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, "http://broker/v1/files", pr)
	req.ContentLength = -1
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chunked 1 MiB upload: %d", resp.StatusCode)
	}
	if got := b.core.sent.Load(); got != 1<<20 {
		t.Fatalf("the run's request bytes after a chunked 1 MiB upload = %d, want 1 MiB (the limit was held, then settled)", got)
	}
	req, _ = http.NewRequest(http.MethodPost, "http://broker/v1/files", bytes.NewReader(make([]byte, 2<<20)))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a declared 2 MiB upload after a settled 1 MiB: %d, want 200 (3 MiB in all, the budget)", resp.StatusCode)
	}
}

// TestBrokerChargesEveryByteAnEarlyAnswerLetsThrough: an API may answer before an
// upload's body is in, and a transport may go on reading the body after RoundTrip has
// returned. The run's total is settled as the call returns, so after it the body hands
// the transport nothing: a second upload admitted on the first's refund cannot be joined
// by the rest of the first, the bytes every transport read never pass the run's total,
// and they are exactly the bytes charged. A call refused after its hold gives it back.
func TestBrokerChargesEveryByteAnEarlyAnswerLetsThrough(t *testing.T) {
	t.Parallel()
	const (
		limit  = 2 << 20
		budget = 3 << 20
		early  = 512 << 10
	)
	var read, calls atomic.Int64 // read: every byte any transport took from a body
	release, finished := make(chan struct{}), make(chan struct{})
	answer := func() *http.Response {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"id":"file-1"}`))}
	}
	transport := brokerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			// The API answers after the first piece; the transport's own goroutine goes
			// on reading the body once the call has returned.
			n, _ := io.CopyN(io.Discard, req.Body, early)
			read.Add(n)
			go func() {
				defer close(finished)
				<-release
				n, _ := io.Copy(io.Discard, req.Body)
				read.Add(n)
				req.Body.Close()
			}()
			return answer(), nil
		}
		n, _ := io.Copy(io.Discard, req.Body)
		read.Add(n)
		req.Body.Close()
		return answer(), nil
	})
	grant := uploadGrant("https://api.internal", limit, budget)
	core, err := newBrokerSession(grant, "tok", transport)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	upload := func(n int64, declared bool) brokerResponse {
		length := n
		if !declared {
			length = -1
		}
		return core.Call(context.Background(), brokerCall{
			Method:        "POST",
			RawTarget:     "/v1/files",
			Headers:       map[string][]string{"Content-Type": {"multipart/form-data; boundary=x"}},
			Body:          io.LimitReader(zeros{}, n),
			ContentLength: length,
		})
	}

	// An undeclared 1.5 MiB upload holds the route's 2 MiB; the API answers after 512 KiB.
	if r := upload(3<<19, false); r.Status != http.StatusOK {
		t.Fatalf("the first upload: %d %q", r.Status, r.Body)
	}
	if got := core.sent.Load(); got != early {
		t.Fatalf("after the early answer the run's request bytes = %d, want the %d the transport was handed", got, early)
	}
	// A declared 2 MiB upload fits what is left (512 KiB + 2 MiB <= 3 MiB) and goes in full.
	if r := upload(2<<20, true); r.Status != http.StatusOK {
		t.Fatalf("the second upload: %d %q", r.Status, r.Body)
	}
	// The first body's transport reads on: it must be handed nothing more.
	close(release)
	<-finished
	if got := read.Load(); got > budget || got != core.sent.Load() {
		t.Fatalf("the transports read %d bytes and the run was charged %d; the total is %d and the two must match", got, core.sent.Load(), budget)
	}
	// What is left of the total is exactly what was not read: 512 KiB lands on it, a byte more does not.
	if r := upload(early, true); r.Status != http.StatusOK {
		t.Fatalf("an upload of exactly what is left: %d %q", r.Status, r.Body)
	}
	if r := upload(1, true); r.Status != http.StatusRequestEntityTooLarge || !strings.Contains(string(r.Body), "exhausted") {
		t.Fatalf("one byte past the total: %d %q", r.Status, r.Body)
	}
	if got := read.Load(); got != budget || core.sent.Load() != budget {
		t.Fatalf("read %d, charged %d, want both exactly the total %d", got, core.sent.Load(), budget)
	}

	// A call refused after its bytes were held (here by the route's call cap) gives them back.
	capped := uploadGrant("https://api.internal", limit, budget)
	capped.RouteMaxCalls = map[HostRoute]int{{Method: "POST", Path: "/v1/files"}: 1}
	core2, err := newBrokerSession(capped, "tok", transport)
	if err != nil {
		t.Fatal(err)
	}
	defer core2.Close()
	call := func(n int64) brokerResponse {
		return core2.Call(context.Background(), brokerCall{
			Method: "POST", RawTarget: "/v1/files",
			Headers:       map[string][]string{"Content-Type": {"multipart/form-data; boundary=x"}},
			Body:          io.LimitReader(zeros{}, n),
			ContentLength: n,
		})
	}
	if r := call(1 << 20); r.Status != http.StatusOK {
		t.Fatalf("the capped route's one call: %d %q", r.Status, r.Body)
	}
	if r := call(1 << 20); r.Status != http.StatusTooManyRequests {
		t.Fatalf("the capped route's second call: %d %q, want 429", r.Status, r.Body)
	}
	if got := core2.sent.Load(); got != 1<<20 {
		t.Fatalf("after a call refused past its hold the run's request bytes = %d, want the 1 MiB that went", got)
	}
}

// TestBrokerBuffersAJSONRouteWithinTheDefaultLimit: a route the profile did not raise
// keeps the 1 MiB limit and the buffered path: a body at the limit goes with its length
// declared to the API, one byte more is refused with 413 and the no-retry mark; a route
// the profile lowered is refused at its own limit.
func TestBrokerBuffersAJSONRouteWithinTheDefaultLimit(t *testing.T) {
	t.Parallel()
	upstream, seen := newUploadUpstream(t)
	grant := uploadGrant(upstream.URL, 8<<20, 64<<20)
	small := HostRoute{Method: "POST", Path: "/v1/small"}
	grant.Allow = append(grant.Allow, small)
	grant.RouteMaxRequestBytes[small] = 64 << 10
	b, err := startDockerBroker(grant, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	client := socketClient(b.sock)
	post := func(target string, n int) *http.Response {
		pr, pw := io.Pipe()
		go func() {
			_, _ = pw.Write(make([]byte, n))
			pw.Close()
		}()
		req, _ := http.NewRequest(http.MethodPost, "http://broker"+target, pr)
		req.ContentLength = -1 // chunked, so the only length the API can see is one the broker set
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := post("/v1/json", maxHostRequestBytes); resp.StatusCode != http.StatusOK || seen.last(t).declared != maxHostRequestBytes {
		t.Fatalf("1 MiB JSON: %d, declared to the API %d", resp.StatusCode, seen.last(t).declared)
	}
	if resp := post("/v1/json", maxHostRequestBytes+1); resp.StatusCode != http.StatusRequestEntityTooLarge || resp.Header.Get(brokerNoRetryHeader) != "false" {
		t.Fatalf("1 MiB + 1 JSON: %d %q", resp.StatusCode, resp.Header.Get(brokerNoRetryHeader))
	}
	if resp := post("/v1/small", 64<<10); resp.StatusCode != http.StatusOK {
		t.Fatalf("64 KiB on the lowered route: %d", resp.StatusCode)
	}
	if resp := post("/v1/small", 64<<10+1); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("64 KiB + 1 on the lowered route: %d", resp.StatusCode)
	}
	if seen.calls.Load() != 2 {
		t.Errorf("the API saw %d requests, want 2", seen.calls.Load())
	}
}

// TestHostAPIGrantValidateUploadFields: the ceilings and shapes of the three upload
// fields are checked at load.
func TestHostAPIGrantValidateUploadFields(t *testing.T) {
	t.Parallel()
	files := HostRoute{Method: "POST", Path: "/v1/files"}
	other := HostRoute{Method: "POST", Path: "/v1/other"}
	base := func(mut func(g *HostAPIGrant)) *HostAPIGrant {
		g := &HostAPIGrant{BaseURL: "https://api.internal", Allow: []HostRoute{files}}
		mut(g)
		return g
	}
	valid := []*HostAPIGrant{
		base(func(g *HostAPIGrant) {}),
		base(func(g *HostAPIGrant) {
			g.RouteMaxRequestBytes = map[HostRoute]int64{files: MaxRouteRequestBytes}
			g.MaxRequestBytes = MaxRequestBytesCeiling
		}),
		base(func(g *HostAPIGrant) { g.RouteMaxRequestBytes = map[HostRoute]int64{files: 1} }),
		base(func(g *HostAPIGrant) { g.RouteMaxRequestBytes = map[HostRoute]int64{files: DefaultMaxRequestBytes} }),
		base(func(g *HostAPIGrant) {
			g.RouteContentTypes = map[HostRoute][]string{files: {"multipart/form-data", "text/csv", "audio/wav"}}
		}),
		base(func(g *HostAPIGrant) { g.MaxRequestBytes = 1 }),
	}
	for i, g := range valid {
		if err := g.Validate(); err != nil {
			t.Errorf("valid grant %d refused: %v", i, err)
		}
	}
	invalid := map[string]*HostAPIGrant{
		"route limit over the ceiling": base(func(g *HostAPIGrant) {
			g.RouteMaxRequestBytes = map[HostRoute]int64{files: MaxRouteRequestBytes + 1}
			g.MaxRequestBytes = MaxRequestBytesCeiling
		}),
		"route limit zero":         base(func(g *HostAPIGrant) { g.RouteMaxRequestBytes = map[HostRoute]int64{files: 0} }),
		"route limit negative":     base(func(g *HostAPIGrant) { g.RouteMaxRequestBytes = map[HostRoute]int64{files: -1} }),
		"route limit not in allow": base(func(g *HostAPIGrant) { g.RouteMaxRequestBytes = map[HostRoute]int64{other: 1 << 20} }),
		"route limit above the run's total": base(func(g *HostAPIGrant) {
			g.RouteMaxRequestBytes = map[HostRoute]int64{files: 300 << 20}
		}),
		"route limit above a set total": base(func(g *HostAPIGrant) {
			g.RouteMaxRequestBytes = map[HostRoute]int64{files: 2 << 20}
			g.MaxRequestBytes = 1 << 20
		}),
		"total over the ceiling": base(func(g *HostAPIGrant) { g.MaxRequestBytes = MaxRequestBytesCeiling + 1 }),
		"total negative":         base(func(g *HostAPIGrant) { g.MaxRequestBytes = -1 }),
		"types not in allow":     base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{other: {"text/csv"}} }),
		"types empty":            base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{files: {}} }),
		"type wildcard":          base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{files: {"multipart/*"}} }),
		"type uppercase":         base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{files: {"Multipart/Form-Data"}} }),
		"type with parameter": base(func(g *HostAPIGrant) {
			g.RouteContentTypes = map[HostRoute][]string{files: {"multipart/form-data; boundary=x"}}
		}),
		"type without subtype": base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{files: {"text"}} }),
		"type json":            base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{files: {"application/json"}} }),
		"type byteranges":      base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{files: {"multipart/byteranges"}} }),
		"type message":         base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{files: {"message/http"}} }),
		"type twice":           base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{files: {"text/csv", "text/csv"}} }),
		"type empty string":    base(func(g *HostAPIGrant) { g.RouteContentTypes = map[HostRoute][]string{files: {""}} }),
	}
	for name, g := range invalid {
		if err := g.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := valid[4].Clone()
	c.RouteContentTypes[files][0] = "changed"
	if valid[4].RouteContentTypes[files][0] != "multipart/form-data" {
		t.Error("Clone shares the content type slices with the original")
	}
}

// TestEgressGuardRawRouteStreamsAnUpload: on the guard's raw route an upload reaches
// the API as it arrives (the upstream has the first half before the client sends the
// second), with its media type, boundary and declared length; a declared length over
// the route's limit is the broker's 413 with the no-retry mark, one over the ceiling
// any profile may set is the guard's own 413, and neither reaches the API.
func TestEgressGuardRawRouteStreamsAnUpload(t *testing.T) {
	t.Parallel()
	upstream, seen := newUploadUpstream(t)
	reg := &guardRegistry{}
	grant := uploadGrant(upstream.URL, 8<<20, 64<<20)
	grant.Minter = StaticToken("minted")
	token, _, cleanup, err := reg.open(context.Background(), grant, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	guard := httptest.NewServer(EgressGuardHTTPHandler(&registryGuard{reg: reg}, "/v1/e2b/guard", 0, 0))
	defer guard.Close()
	body := randomBytes(t, 3<<20)
	half := len(body) / 2
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(body[:half])
		select {
		case <-seen.firstByte:
		case <-time.After(10 * time.Second):
			pw.CloseWithError(errors.New("the upstream did not get the first half within 10 s: the body was buffered"))
			return
		}
		_, _ = pw.Write(body[half:])
		pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, guard.URL+"/v1/e2b/guard/raw/v1/files", pr)
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=plimsoll-7f3a9c")
	req.Header.Set(EgressGuardHeader, token)
	resp, err := guard.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get(brokerNoRetryHeader) != "" || string(answer) != `{"id":"file-1"}` {
		t.Fatalf("answer = %d %q %q", resp.StatusCode, resp.Header.Get(brokerNoRetryHeader), answer)
	}
	s := seen.last(t)
	if s.contentType != "multipart/form-data; boundary=plimsoll-7f3a9c" || s.declared != int64(len(body)) || s.read != int64(len(body)) || s.digest != sha256.Sum256(body) {
		t.Errorf("the API saw %+v", s)
	}
	for _, tc := range []struct {
		declared int64
		want     int
		retry    string
	}{
		{8<<20 + 1, http.StatusRequestEntityTooLarge, "false"},                // the broker's: over the route's limit
		{MaxRouteRequestBytes + 1, http.StatusRequestEntityTooLarge, "false"}, // the guard's: over any profile's ceiling
	} {
		req, _ := http.NewRequest(http.MethodPost, guard.URL+"/v1/e2b/guard/raw/v1/files", io.LimitReader(zeros{}, tc.declared))
		req.ContentLength = tc.declared
		req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		req.Header.Set(EgressGuardHeader, token)
		resp, err := guard.Client().Do(req)
		if err != nil {
			// The guard answered and closed before the body went: Go's client reports the
			// answer when it has one, so an error here is a failure.
			t.Fatalf("declared %d: %v", tc.declared, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want || resp.Header.Get(brokerNoRetryHeader) != tc.retry {
			t.Errorf("declared %d: %d %q, want %d %q", tc.declared, resp.StatusCode, resp.Header.Get(brokerNoRetryHeader), tc.want, tc.retry)
		}
	}
	if seen.calls.Load() != 1 {
		t.Errorf("the API saw %d requests, want the one that fit", seen.calls.Load())
	}
}
