package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
	"unicode/utf8"
)

// overrideStandIn is an upstream that honors method and path override the way the
// frameworks read do (Symfony's getMethod with parameter override on, Laravel's JSON
// request bag, Rack::MethodOverride's form and multipart read, IIS's X-Original-URL):
// on a POST, the method is X-HTTP-Method-Override, else a top-level _method of a JSON,
// form or multipart body; the path is X-Original-URL when present. A body is JSON by
// Laravel's own test, isJson, which searches the whole Content-Type header, parameters
// included, for "/json" or "+json" (hunt-security-11). It records what it acted on,
// and acts on nothing when the body did not arrive whole.
type overrideStandIn struct {
	mu    sync.Mutex
	acted []string // "METHOD /path"
	types []string // the Content-Type of each request it received
}

func (s *overrideStandIn) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			return nil, err // a body that broke off: nothing runs
		}
	}
	method, path := req.Method, req.URL.Path
	if method == http.MethodPost {
		mediaType, params, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if h := req.Header.Get("X-HTTP-Method-Override"); h != "" {
			method = strings.ToUpper(h)
		} else {
			var field string
			switch {
			case laravelIsJSON(req.Header.Get("Content-Type")):
				var m map[string]any
				if json.Unmarshal(bytes.TrimPrefix(body, utf8BOM), &m) == nil {
					field, _ = m["_method"].(string)
				}
			case mediaType == "application/x-www-form-urlencoded":
				if q, err := url.ParseQuery(string(body)); err == nil {
					field = q.Get("_method")
				}
			case mediaType == "multipart/form-data":
				if form, err := multipart.NewReader(bytes.NewReader(body), params["boundary"]).ReadForm(1 << 20); err == nil {
					if v := form.Value["_method"]; len(v) > 0 {
						field = v[0]
					}
					_ = form.RemoveAll() // a file part past the memory limit went to disk
				}
			}
			if field != "" {
				method = strings.ToUpper(field)
			}
		}
	}
	if p := req.Header.Get("X-Original-URL"); p != "" {
		path = p
	}
	s.mu.Lock()
	s.acted = append(s.acted, method+" "+path)
	s.types = append(s.types, req.Header.Get("Content-Type"))
	s.mu.Unlock()
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
}

// laravelIsJSON is Laravel's InteractsWithContentTypes::isJson (11.x):
//
//	Str::contains($this->header('CONTENT_TYPE') ?? '', ['/json', '+json'])
func laravelIsJSON(contentType string) bool {
	return strings.Contains(contentType, "/json") || strings.Contains(contentType, "+json")
}

func (s *overrideStandIn) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.acted
	s.acted, s.types = nil, nil
	return out
}

// takeTypes is the Content-Type of each request received since the last take.
func (s *overrideStandIn) takeTypes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.types...)
}

var commentsRoute = HostRoute{Method: "POST", Path: "/v1/items/*/comments"}

func overrideGrant() *HostAPIGrant {
	upload := HostRoute{Method: "POST", Path: "/v1/items/*/attachments"}
	return &HostAPIGrant{
		BaseURL:     "https://api.example",
		Allow:       []HostRoute{commentsRoute, upload},
		PassHeaders: []string{"anthropic-version"},
		RouteContentTypes: map[HostRoute][]string{
			commentsRoute: {"application/x-www-form-urlencoded", "multipart/form-data", "application/vnd.api+json", "text/plain"},
			upload:        {"application/x-www-form-urlencoded", "multipart/form-data"},
		},
		RouteMaxRequestBytes: map[HostRoute]int64{upload: 4 << 20},
	}
}

// TestBrokerOverrideStandInNeverActsOnAnOverride is the security hunt's stand-in case
// (hunt-security-5) made a test: a grant of only POST to the comments route, an
// upstream that honors every override the frameworks read, and calls that name one in
// each place. The upstream acts on POST /v1/items/42/comments or on nothing, never on
// another method or path; the trace holds only the route template and counts.
func TestBrokerOverrideStandInNeverActsOnAnOverride(t *testing.T) {
	t.Parallel()
	standIn := &overrideStandIn{}
	core, err := newBrokerSession(overrideGrant(), "tok", standIn)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	const target = "/v1/items/42/comments"
	const asGranted = "POST " + target
	wantDenied, delivered := 0, 0
	for _, c := range []struct {
		name, contentType, body string
		headers                 map[string][]string
		target                  string
		status                  int
		acted                   []string
	}{
		// The body field, JSON (Laravel): refused before anything is sent.
		{name: "json _method", body: `{"_method":"DELETE"}`, status: 403},
		{name: "json _method beside other fields", body: `{"text":"hi","_method":"DELETE"}`, status: 403},
		{name: "json duplicate keys", body: `{"_method":"POST","_method":"DELETE"}`, status: 403},
		{name: "json escaped key", body: `{"\u005fmethod":"DELETE"}`, status: 403},
		{name: "json other case", body: `{"_METHOD":"DELETE"}`, status: 403},
		{name: "json byte order mark", body: "\ufeff{\"_method\":\"DELETE\"}", status: 403},
		{name: "json +json type", contentType: "application/vnd.api+json", body: `{"_method":"DELETE"}`, status: 403},
		{name: "json guest sent no type", contentType: "-", body: `{"_method":"DELETE"}`, status: 403},
		{name: "json not json", body: `{"_method":"DELETE"`, status: 400},
		{name: "json nested passes", body: `{"text":"hi","meta":{"_method":"DELETE"}}`, status: 200, acted: []string{asGranted}},
		{name: "json value passes", body: `{"text":"_method"}`, status: 200, acted: []string{asGranted}},
		{name: "json array passes", body: `[{"_method":"DELETE"}]`, status: 200, acted: []string{asGranted}},
		{name: "json longer key passes", body: `{"_methods":"DELETE"}`, status: 200, acted: []string{asGranted}},
		// A body that is not sent as JSON is not read.
		{name: "text passes", contentType: "text/plain", body: "_method=DELETE", status: 200, acted: []string{asGranted}},
		{name: "text with a JSON body passes, sent as text/plain", contentType: "text/plain", body: `{"_method":"DELETE"}`, status: 200, acted: []string{asGranted}},
		// hunt-security-11: a non-JSON type with a parameter that makes Laravel (the
		// stand-in's isJson) read the body as JSON. The broker writes the Content-Type:
		// a charset only from its list, a multipart boundary only when the line it writes
		// does not name JSON, no other parameter.
		{name: "form type with a +json charset", contentType: "application/x-www-form-urlencoded; charset=x+json", body: `{"_method":"DELETE"}`, status: 415},
		{name: "text type with a +json charset", contentType: "text/plain; charset=x+json", body: `{"_method":"DELETE"}`, status: 415},
		{name: "text type with a /json parameter", contentType: `text/plain; x="a/json"`, body: `{"_method":"DELETE"}`, status: 415},
		{name: "multipart type with a +json boundary", contentType: "multipart/form-data; boundary=a+json", body: `{"_method":"DELETE"}`, status: 415},
		{name: "multipart type with a /json boundary", contentType: `multipart/form-data; boundary="x/json"`, body: `{"_method":"DELETE"}`, status: 415},
		{name: "form type with a utf-8 charset passes", contentType: "application/x-www-form-urlencoded; charset=UTF-8", body: "text=hi", status: 200, acted: []string{asGranted}},
		{name: "json with a utf-16 charset", contentType: "application/json; charset=utf-16", body: `{"text":"hi"}`, status: 415},
		// The query string: refused whole, as every query is.
		{name: "query", target: target + "?_method=DELETE", body: `{}`, status: 403},
		// The headers: the guest's never reach the API unless passed, and a grant cannot pass them.
		{name: "method header dropped", body: `{}`, headers: map[string][]string{"X-HTTP-Method-Override": {"DELETE"}}, status: 200, acted: []string{asGranted}},
		{name: "path header dropped", body: `{}`, headers: map[string][]string{"X-Original-URL": {"/admin/users/1"}}, status: 200, acted: []string{asGranted}},
	} {
		if c.status == http.StatusOK {
			delivered++
		} else {
			wantDenied++
		}
		headers := c.headers
		if headers == nil {
			headers = map[string][]string{}
		}
		switch c.contentType {
		case "":
			headers["Content-Type"] = []string{"application/json"}
		case "-":
		default:
			headers["Content-Type"] = []string{c.contentType}
		}
		tgt := c.target
		if tgt == "" {
			tgt = target
		}
		resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: tgt, Headers: headers, Body: strings.NewReader(c.body), ContentLength: int64(len(c.body))})
		acted := standIn.take()
		if resp.Status != c.status || fmt.Sprint(acted) != fmt.Sprint(c.acted) {
			t.Errorf("%s: %d %q, upstream acted on %v; want %d and %v", c.name, resp.Status, resp.Body, acted, c.status, c.acted)
		}
		if c.status == 403 && c.target == "" && !strings.Contains(string(resp.Body), "method override field") {
			t.Errorf("%s: refusal %q does not say why", c.name, resp.Body)
		}
	}
	trace := core.traceSnapshot()
	for _, row := range trace.Calls {
		if row.Route != commentsRoute.Path || row.Method != "POST" {
			t.Errorf("trace row %+v names something other than the route template", row)
		}
	}
	if trace.Denied != wantDenied || len(trace.Calls) != delivered {
		t.Errorf("trace: %d denied and %d rows, want %d and %d (every refusal counted, no row for one)", trace.Denied, len(trace.Calls), wantDenied, delivered)
	}
}

// TestBrokerOverrideStreamedBodyNeverArrivesWhole: on a route whose limit is raised the
// body is passed through, so the override field is found piece by piece; the piece that
// completes its name is withheld and the upstream request broken off, so the stand-in
// never receives a whole body that names one, even when the name arrives one byte at a
// time. A streamed body without one arrives whole.
func TestBrokerOverrideStreamedBodyNeverArrivesWhole(t *testing.T) {
	t.Parallel()
	standIn := &overrideStandIn{}
	core, err := newBrokerSession(overrideGrant(), "tok", standIn)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	const target = "/v1/items/42/attachments"
	padding := strings.Repeat("x", 2<<20) // past the default limit, so this is the streamed path
	utf16 := func(s string) string {
		b := make([]byte, 0, 2*len(s))
		for i := 0; i < len(s); i++ {
			b = append(b, s[i], 0)
		}
		return string(b)
	}
	for _, c := range []struct {
		name, contentType, body string
		oneByte                 bool
		status                  int
		acted                   bool
	}{
		{"json at the end", "application/json", `{"blob":"` + padding + `","_method":"DELETE"}`, false, 403, false},
		{"json one byte at a time", "application/json", `{"blob":"` + padding[:4096] + `","_method":"DELETE"}`, true, 403, false},
		{"json nested passes", "application/json", `{"blob":"` + padding + `","m":{"_method":"DELETE"}}`, false, 200, true},
		// hunt-security-18: a nested key after a comma is delivered.
		{"json nested after a comma passes", "application/json", `{"blob":"` + padding + `","m":{"b":1,"_method":"DELETE"}}`, false, 200, true},
		// hunt-security-16: UTF-16 is not UTF-8, so it is not sent as JSON.
		{"json in UTF-16", "application/json", utf16(`{"blob":"` + padding[:600<<10] + `","_method":"DELETE"}`), false, 400, false},
	} {
		var body io.Reader = strings.NewReader(c.body)
		if c.oneByte {
			body = iotest.OneByteReader(body)
		}
		resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: target,
			Headers: map[string][]string{"Content-Type": {c.contentType}}, Body: body, ContentLength: int64(len(c.body))})
		acted := standIn.take()
		if resp.Status != c.status || (len(acted) > 0) != c.acted || (c.acted && acted[0] != "POST "+target) {
			t.Errorf("%s: %d %q, upstream acted on %v", c.name, resp.Status, resp.Body, acted)
		}
	}
}

// TestBrokerOverrideRefusalKeepsTheChargeOnceABodyByteWent (hunt-security-17, then
// hunt-security-31 and release-98): a refusal of a buffered body is made before the request
// is built, so it is counted as denied in the trace with no call row and spends no route cap:
// on a route capped at one call, a refused call leaves the one call for the next request. A
// streamed body is refused while its request is under way, after its headers went (the
// transport sends them first, and an API's handler runs on them), so a streamed refusal keeps
// the charge and has a call row with the bytes sent, whether it came at the first piece (no
// byte; TestBrokerStreamedRefusalAtTheFirstPieceKeepsTheCharge shows a real API acting on the
// headers) or after an earlier piece went (decodingStandIn acts at the first value's closing
// brace). A refund would let calls past the cap with no row in the trace.
func TestBrokerOverrideRefusalKeepsTheChargeOnceABodyByteWent(t *testing.T) {
	t.Parallel()
	g := overrideGrant()
	upload := HostRoute{Method: "POST", Path: "/v1/items/*/attachments"}
	g.RouteMaxCalls = map[HostRoute]int{commentsRoute: 1, upload: 1}
	standIn := &overrideStandIn{}
	core, err := newBrokerSession(g, "tok", standIn)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	padding := strings.Repeat("x", 2<<20)
	call := func(target, body string) brokerResponse {
		return core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: target,
			Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: strings.NewReader(body), ContentLength: int64(len(body))})
	}
	// Buffered: refused before the request is built; the one call is left for the next.
	if resp := call("/v1/items/42/comments", `{"_method":"DELETE"}`); resp.Status != http.StatusForbidden {
		t.Fatalf("buffered refusal: %d %q", resp.Status, resp.Body)
	}
	if resp := call("/v1/items/42/comments", `{"text":"hi"}`); resp.Status != http.StatusOK {
		t.Errorf("buffered: the call after the refusal got %d %q, so the refusal spent the route's one call", resp.Status, resp.Body)
	}
	if resp := call("/v1/items/42/comments", `{"text":"hi"}`); resp.Status != http.StatusTooManyRequests {
		t.Errorf("buffered: a second delivered call got %d, want 429 (the cap holds)", resp.Status)
	}
	// Streamed, refused at its first piece: its first byte is not JSON, so nothing of the body
	// goes, but the request's headers did, so the call spends the route's one call.
	if resp := call("/v1/items/42/attachments", "\x00"+padding); resp.Status != http.StatusBadRequest {
		t.Fatalf("streamed refusal at the first piece: %d %q", resp.Status, resp.Body)
	}
	if resp := call("/v1/items/42/attachments", `{"blob":"`+padding+`"}`); resp.Status != http.StatusTooManyRequests {
		t.Errorf("streamed: the call after a refusal at the first piece got %d %q, want 429: the refused request reached the API", resp.Status, resp.Body)
	}
	trace := core.traceSnapshot()
	if trace.Denied != 3 || len(trace.Calls) != 2 {
		t.Errorf("trace: %d denied and %d rows, want 3 denied (the buffered refusal, two 429s) and 2 rows (the delivered call, the streamed refusal)", trace.Denied, len(trace.Calls))
	}
	for _, row := range trace.Calls {
		switch row.Route {
		case commentsRoute.Path:
			if !row.Delivered {
				t.Errorf("row %+v: the delivered call", row)
			}
		case upload.Path:
			if row.Delivered || row.ReqBytes != 0 {
				t.Errorf("row %+v: want an undelivered call with no body bytes sent", row)
			}
		default:
			t.Errorf("row %+v: unexpected route", row)
		}
	}
	if acted := standIn.take(); len(acted) != 1 {
		t.Errorf("the stand-in acted on %v, want the one delivered call", acted)
	}

	t.Run("streamed, refused after a piece went", func(t *testing.T) {
		g := overrideGrant()
		g.RouteMaxCalls = map[HostRoute]int{upload: 1}
		api := &decodingStandIn{}
		core, err := newBrokerSession(g, "tok", api)
		if err != nil {
			t.Fatal(err)
		}
		defer core.Close()
		const target = "/v1/items/42/attachments"
		const object = `{"job":1}`
		// The whole object arrives as one piece, then a byte that is not JSON: the broker
		// refuses that piece, after the API has read the object.
		body := io.MultiReader(strings.NewReader(object), strings.NewReader("\x00"))
		resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: target,
			Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: body, ContentLength: int64(len(object) + 1)})
		if resp.Status != http.StatusBadRequest {
			t.Fatalf("the refused call: %d %q, want 400", resp.Status, resp.Body)
		}
		if n := api.acted.Load(); n != 1 {
			t.Fatalf("the API acted %d times on the refused call; the test needs it to have acted once", n)
		}
		if resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: target,
			Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: strings.NewReader(object), ContentLength: int64(len(object))}); resp.Status != http.StatusTooManyRequests {
			t.Errorf("the next call got %d %q, want 429: the refused call reached the API and spent the route's one call", resp.Status, resp.Body)
		}
		if n := api.acted.Load(); n != 1 {
			t.Errorf("the API acted %d times, want once: the cap let a call past it", n)
		}
		trace := core.traceSnapshot()
		if len(trace.Calls) != 1 {
			t.Fatalf("trace: %d rows, want 1 for the refused call that reached the API", len(trace.Calls))
		}
		row := trace.Calls[0]
		if row.Delivered || row.Route != upload.Path || row.Method != "POST" || row.ReqBytes != len(object) {
			t.Errorf("row %+v: want an undelivered POST %s with %d bytes sent", row, upload.Path, len(object))
		}
		if trace.Denied != 1 {
			t.Errorf("trace: %d denied, want 1 (the 429)", trace.Denied)
		}
	})
}

// decodingStandIn is an API that decodes a JSON body as it arrives and acts on the first
// value as soon as it has decoded it, as a Go handler calling json.NewDecoder(r.Body).Decode
// does, then reads the rest of the body; a body that breaks off after that fails the request,
// but the API has acted.
type decodingStandIn struct{ acted atomic.Int32 }

func (s *decodingStandIn) RoundTrip(req *http.Request) (*http.Response, error) {
	var v map[string]any
	if err := json.NewDecoder(req.Body).Decode(&v); err != nil {
		return nil, err
	}
	s.acted.Add(1)
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
}

// TestBrokerForwardsFormAndUploadBodiesUnread states a limit of the product as a fact.
// The broker reads no form body and no multipart body, so on a route a profile opened for them one
// that names _method is forwarded, held whole or passed through, and an API that honors
// method override (the stand-in) runs it as DELETE on the granted path. The multipart
// body arrives with the guest's boundary in the Content-Type the broker wrote, or the
// stand-in could not read it. Whoever changes this changes this test and the page that
// states it (docs/capability-grants.md, "Method and path override").
func TestBrokerForwardsFormAndUploadBodiesUnread(t *testing.T) {
	t.Parallel()
	standIn := &overrideStandIn{}
	core, err := newBrokerSession(overrideGrant(), "tok", standIn)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	upload := func(file string) (string, string) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.SetBoundary("plimsoll-unread"); err != nil {
			t.Fatal(err)
		}
		if file != "" {
			part, err := w.CreateFormFile("file", "a.bin")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = part.Write([]byte(file))
		}
		if err := w.WriteField("_method", "DELETE"); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		return w.FormDataContentType(), buf.String()
	}
	padding := strings.Repeat("x", 2<<20) // past the default limit: the passed-through path
	mpType, mpSmall := upload("")
	_, mpLarge := upload(padding)
	const form = "application/x-www-form-urlencoded"
	for _, c := range []struct{ name, target, contentType, body string }{
		{"form, held whole", "/v1/items/42/comments", form, "text=hi&_method=DELETE"},
		{"multipart, held whole", "/v1/items/42/comments", mpType, mpSmall},
		{"form, passed through", "/v1/items/42/attachments", form, "blob=" + padding + "&_method=DELETE"},
		{"multipart, passed through", "/v1/items/42/attachments", mpType, mpLarge},
	} {
		resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: c.target,
			Headers: map[string][]string{"Content-Type": {c.contentType}}, Body: strings.NewReader(c.body), ContentLength: int64(len(c.body))})
		types := standIn.takeTypes()
		acted := standIn.take()
		if resp.Status != http.StatusOK || len(acted) != 1 || acted[0] != "DELETE "+c.target {
			t.Errorf("%s: %d %q, the stand-in acted on %v; want 200 and DELETE %s (the body is forwarded unread)", c.name, resp.Status, resp.Body, acted, c.target)
		}
		if len(types) != 1 || types[0] != c.contentType {
			t.Errorf("%s: the stand-in received Content-Type %v; want %q", c.name, types, c.contentType)
		}
	}
}

// TestGrantRefusesOverrideHeaders: a grant may neither pass nor set a header a framework
// reads as the method or the path, in any letter case, nor carry its credential in one.
func TestGrantRefusesOverrideHeaders(t *testing.T) {
	t.Parallel()
	for name := range overrideHeaders {
		under := strings.ReplaceAll(name, "-", "_") // hunt-security-15: CGI servers read _ as -
		mixed := strings.Replace(http.CanonicalHeaderKey(name), "-", "_", 1)
		for _, spelled := range []string{name, strings.ToUpper(name), http.CanonicalHeaderKey(name), under, strings.ToUpper(under), mixed} {
			pass := overrideGrant()
			pass.PassHeaders = []string{spelled}
			set := overrideGrant()
			set.PassHeaders = nil
			set.SetHeaders = map[string]string{spelled: "DELETE"}
			for _, g := range []*HostAPIGrant{pass, set} {
				if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "web frameworks and servers read it as the request's") {
					t.Errorf("%s: Validate = %v", spelled, err)
				}
			}
			if !passHeaderRefused(spelled) {
				t.Errorf("passHeaderRefused(%q) = false", spelled)
			}
		}
	}
}

// TestJSONOverrideScannerAtEverySplit: the streamed JSON scanner gives the buffered
// reader's answer whichever byte the body is split at: the same refusal, or none.
func TestJSONOverrideScannerAtEverySplit(t *testing.T) {
	t.Parallel()
	for _, body := range jsonOverrideCorpus {
		want := checkJSONBody([]byte(body))
		for i := 0; i <= len(body); i++ {
			s := &jsonOverrideScanner{}
			got := s.feed([]byte(body[:i]))
			if got == nil {
				got = s.feed([]byte(body[i:]))
			}
			if got == nil {
				got = s.end()
			}
			if got != want {
				t.Errorf("%q split at %d: scanner %v, decoder %v", body, i, got, want)
				break
			}
		}
	}
}

var jsonOverrideCorpus = []string{
	`{"_method":"DELETE"}`, `{"a":1,"_method":"x"}`, `{"_method":1}`, `{"_Method":1}`, "\ufeff{\"_method\":1}",
	`{"a":{"_method":1}}`, `[{"_method":1}]`, `{"a":"_method"}`, `{"a":["_method"],"b":"\"_method\""}`, `{"_methodx":1}`,
	`{"_metho":1}`, `{"\u005fmethod":1}`, `{"\\_method":1}`, `{"_methöd":1}`, `{"a":[1,{"b":2}],"_method":null}`, `{}`, `"_method"`, ` { "_method" : 1 } `,
	`{"a\"b":1,"_method":2}`, `{"😀":1}`, `{"_method\u0000":1}`,
	// hunt-security-18: a key after a comma inside a nested object or array is no
	// override; with the scanner's depth-1 conditions deleted these are refused.
	`{"a":{"b":1,"_method":2}}`, `{"a":[1,{"b":2,"_method":3}],"c":4}`, `[1,{"b":2,"_method":3}]`,
	// release-109: the grammar's edges that are JSON, which the scanner must take as the
	// decoder does: every kind of number, the literals, empty containers, white space.
	``, " ", "\ufeff", "\ufeff \t\r\n", `0`, `-0`, `-0.0e+0`, `1E-5`, `12.5e10`, `-1.5E+3`, `""`, `true`, ` null `, `false`,
	`[]`, `{}`, `[[],{}]`, `[ 1 , 2 ]`, "{\t\"a\"\r\n:\n[ true , false , null ] , \"_method\" : 0 }",
	`{"a":[true,false,null],"b":-1.5,"c":{"d":[]}}`, `{"a":0,"_method":-0.5e-7}`,
}

func init() {
	// hunt-security-19: top-level keys that are not plain, and the near cases that are
	// (a whole pair, a value, a nested key), built from jsonKeyCases so the fuzz seeds
	// hold them too.
	for _, c := range jsonKeyCases() {
		jsonOverrideCorpus = append(jsonOverrideCorpus, c.body)
	}
}

// jsonEscape is the JSON escape of the UTF-16 unit hex, a backslash, u and the four
// digits (built here, not written out, so no tool between the writer and the file can
// turn the escape into the character it names).
func jsonEscape(hex string) string { return "\\" + "u" + hex }

// jsonKeyCases are the bodies TestJSONKeyThatIsNotPlainIsRefused reads, each with the
// refusal the buffered and the streamed check must both give (nil: none).
func jsonKeyCases() []struct {
	name, body string
	want       error
} {
	u := jsonEscape
	return []struct {
		name, body string
		want       error
	}{
		{"_method and an escaped NUL", `{"_method` + u("0000") + `":"DELETE"}`, errKeyNotPlain},
		{"an escaped NUL before _method", `{"` + u("0000") + `_method":"DELETE"}`, errKeyNotPlain},
		{"_method and an escaped unit separator", `{"_method` + u("001f") + `":"DELETE"}`, errKeyNotPlain},
		{"_method and an escaped line feed", `{"_method\n":"DELETE"}`, errKeyNotPlain},
		{"an escaped tab, second key", `{"a":1,"\t_method":"DELETE"}`, errKeyNotPlain},
		{"_method and a lone high surrogate", `{"_method` + u("d800") + `":"DELETE"}`, errKeyNotPlain},
		{"a lone high surrogate before _method", `{"` + u("dbff") + `_method":"DELETE"}`, errKeyNotPlain},
		{"_method and a lone low surrogate", `{"_method` + u("dc00") + `":"DELETE"}`, errKeyNotPlain},
		{"a high surrogate, then an escaped letter", `{"` + u("d83d") + u("0041") + `":1}`, errKeyNotPlain},
		{"a high surrogate, then an escaped slash", `{"` + u("d83d") + `\/":1}`, errKeyNotPlain},
		{"two high surrogates", `{"` + u("d800") + u("d800") + `":1}`, errKeyNotPlain},
		{"a low surrogate, then a high one", `{"` + u("de00") + u("d83d") + `":1}`, errKeyNotPlain},
		{"a whole pair passes", `{"` + u("d83d") + u("de00") + `_method":1}`, nil},
		{"a whole pair, upper-case digits, passes", `{"` + u("D83D") + u("DE00") + `":1}`, nil},
		{"an escaped DEL passes", `{"_method` + u("007f") + `":1}`, nil},
		{"an escaped quote and slash pass", `{"a\"\/\\":1}`, nil},
		{"a value with a NUL and a lone surrogate passes", `{"a":"_method` + u("0000") + u("d800") + `"}`, nil},
		{"a nested key with a NUL passes", `{"a":{"_method` + u("0000") + `":1}}`, nil},
		{"a key in an array passes", `[{"_method` + u("d800") + `":1}]`, nil},
		{"an escaped _method is still the field", `{"` + u("005f") + `method":"DELETE"}`, errOverrideField},
	}
}

// TestJSONKeyThatIsNotPlainIsRefused (hunt-security-19): a top-level key holding an
// escaped control character or an escaped half of a surrogate pair without its other half
// is refused with 400, buffered and streamed at every split, and through the broker on a
// buffered route and on a passed-through one; the API receives no whole body that holds
// one. The broker forwards the guest's bytes as written, so without this a parser that
// cuts a key at a NUL or drops a lone surrogate would read _method where the broker read
// another key.
func TestJSONKeyThatIsNotPlainIsRefused(t *testing.T) {
	t.Parallel()
	standIn := &overrideStandIn{}
	core, err := newBrokerSession(overrideGrant(), "tok", standIn)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	padding := strings.Repeat("x", 2<<20) // past the default limit: the passed-through path
	for _, c := range jsonKeyCases() {
		if got := checkJSONBody([]byte(c.body)); got != c.want {
			t.Errorf("%s: buffered %v, want %v", c.name, got, c.want)
		}
		for at := 0; at <= len(c.body); at++ {
			s := &jsonOverrideScanner{}
			got := s.feed([]byte(c.body[:at]))
			if got == nil {
				got = s.feed([]byte(c.body[at:]))
			}
			if got == nil {
				got = s.end()
			}
			if got != c.want {
				t.Errorf("%s split at %d: streamed %v, want %v", c.name, at, got, c.want)
				break
			}
		}
		if c.want != errKeyNotPlain {
			continue
		}
		// The key last, after a long first field, on the passed-through route.
		streamed := `{"blob":"` + padding + `",` + strings.TrimPrefix(c.body, "{")
		for _, call := range []struct {
			path, body string
		}{{"/v1/items/42/comments", c.body}, {"/v1/items/42/attachments", streamed}} {
			resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: call.path,
				Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: strings.NewReader(call.body), ContentLength: int64(len(call.body))})
			if acted := standIn.take(); resp.Status != http.StatusBadRequest || len(acted) > 0 || !strings.Contains(string(resp.Body), "unpaired surrogate") {
				t.Errorf("%s on %s: %d %q, upstream acted on %v; want 400 and nothing acted on", c.name, call.path, resp.Status, resp.Body, acted)
			}
		}
	}
}

// TestBrokerRefusesUTF16JSONStreamed (hunt-security-16): on a passed-through route that
// lists a +json type, a UTF-16 body naming _method never reaches the API whole: under a
// charset other than utf-8 the type is refused with 415 before a byte is read, and with
// no charset, or utf-8, the body is refused with 400 at its first NUL, since a JSON body
// must be UTF-8. Express's JSON parser decodes any "utf-" charset, so a body the broker
// read as bytes would be read by it as other text.
func TestBrokerRefusesUTF16JSONStreamed(t *testing.T) {
	t.Parallel()
	g := overrideGrant()
	upload := HostRoute{Method: "POST", Path: "/v1/items/*/attachments"}
	g.RouteContentTypes[upload] = append(g.RouteContentTypes[upload], "application/vnd.api+json")
	standIn := &overrideStandIn{}
	core, err := newBrokerSession(g, "tok", standIn)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	utf16le := func(s string) string {
		b := make([]byte, 0, 2*len(s))
		for i := 0; i < len(s); i++ {
			b = append(b, s[i], 0)
		}
		return string(b)
	}
	body := utf16le(`{"blob":"` + strings.Repeat("x", 1<<20) + `","_method":"DELETE"}`) // 2 MiB: passed through
	for _, c := range []struct {
		contentType string
		status      int
	}{
		{"application/vnd.api+json; charset=utf-16le", http.StatusUnsupportedMediaType},
		{"application/vnd.api+json; charset=UTF-16", http.StatusUnsupportedMediaType},
		{"application/vnd.api+json; charset=utf-8", http.StatusBadRequest},
		{"application/vnd.api+json", http.StatusBadRequest},
	} {
		for _, oneByte := range []bool{false, true} {
			var r io.Reader = strings.NewReader(body)
			if oneByte {
				r = iotest.OneByteReader(r)
			}
			resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/items/42/attachments",
				Headers: map[string][]string{"Content-Type": {c.contentType}}, Body: r, ContentLength: int64(len(body))})
			if acted := standIn.take(); resp.Status != c.status || len(acted) > 0 {
				t.Errorf("%s (one byte at a time %v): %d %q, upstream acted on %v; want %d and nothing acted on", c.contentType, oneByte, resp.Status, resp.Body, acted, c.status)
			}
		}
	}
	// The same route takes the type: a UTF-8 body without the field arrives.
	ok := `{"blob":"` + strings.Repeat("x", 2<<20) + `"}`
	resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/items/42/attachments",
		Headers: map[string][]string{"Content-Type": {"application/vnd.api+json; charset=utf-8"}}, Body: strings.NewReader(ok), ContentLength: int64(len(ok))})
	if acted := standIn.take(); resp.Status != http.StatusOK || len(acted) != 1 {
		t.Errorf("a UTF-8 +json body: %d %q, acted on %v; want 200 and one call", resp.Status, resp.Body, acted)
	}
}

// TestJSONScannerRefusesWhatIsNotUTF8 (hunt-security-16): a JSON body must be valid
// UTF-8, buffered and streamed, at every split. UTF-16, whose ASCII letters each come
// with a NUL, is refused (its NULs are control bytes JSON does not allow), and so is a
// UTF-16 byte order mark, invalid UTF-8 in a string, an overlong form, a surrogate and a
// body cut inside a character. A UTF-8 byte order mark is skipped, as before.
func TestJSONScannerRefusesWhatIsNotUTF8(t *testing.T) {
	t.Parallel()
	utf16 := func(s string, bom bool) string {
		var b []byte
		if bom {
			b = append(b, 0xff, 0xfe)
		}
		for i := 0; i < len(s); i++ {
			b = append(b, s[i], 0)
		}
		return string(b)
	}
	for _, c := range []struct {
		name, body string
		want       error
	}{
		{"UTF-16LE", utf16(`{"_method":"DELETE"}`, false), errBodyNotJSON},
		{"UTF-16LE with its byte order mark", utf16(`{"_method":"DELETE"}`, true), errBodyNotJSON},
		{"UTF-16LE of a body without the field", utf16(`{"a":1}`, false), errBodyNotJSON},
		{"invalid UTF-8 in a string", "{\"a\":\"\xff\"}", errBodyNotJSON},
		{"overlong slash", "{\"a\":\"\xc0\xaf\"}", errBodyNotJSON},
		{"a surrogate", "{\"a\":\"\xed\xa0\x80\"}", errBodyNotJSON},
		{"cut inside a character", "{\"a\":\"\xe2\x82", errBodyNotJSON},
		{"a raw tab inside a string", "{\"a\":\"x\ty\"}", errBodyNotJSON},
		{"UTF-8 byte order mark, then the field", "\ufeff{\"_method\":1}", errOverrideField},
		{"UTF-8 text", `{"a":"naïve 😀"}`, nil},
	} {
		if got := checkJSONBody([]byte(c.body)); got != c.want {
			t.Errorf("%s: buffered %v, want %v", c.name, got, c.want)
		}
		for at := 0; at <= len(c.body); at++ {
			s := &jsonOverrideScanner{}
			err := s.feed([]byte(c.body[:at]))
			if err == nil {
				err = s.feed([]byte(c.body[at:]))
			}
			if err == nil {
				err = s.end()
			}
			if err != c.want {
				t.Errorf("%s split at %d: streamed %v, want %v", c.name, at, err, c.want)
				break
			}
		}
	}
}

// TestUTF8CheckAgreesWithTheLibrary: utf8Check, a byte at a time, accepts exactly what
// utf8.Valid accepts, on every pair of leading bytes with each kind of byte after.
func TestUTF8CheckAgreesWithTheLibrary(t *testing.T) {
	t.Parallel()
	check := func(b []byte) bool {
		var u utf8Check
		for _, c := range b {
			if !u.next(c) {
				return false
			}
		}
		return u.need == 0
	}
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			for _, seq := range [][]byte{{byte(a)}, {byte(a), byte(b)}, {byte(a), byte(b), 0x80}, {byte(a), byte(b), 0xbf}, {byte(a), byte(b), 0x80, 0x80}, {byte(a), byte(b), 0xbf, 0xbf}, {byte(a), byte(b), 0x41}} {
				if check(seq) != utf8.Valid(seq) {
					t.Fatalf("% x: utf8Check %v, utf8.Valid %v", seq, check(seq), utf8.Valid(seq))
				}
			}
		}
	}
}

// notJSONBodies (finding release-109) are bodies the buffered check refuses as not JSON
// that the streamed scanner let through while it tracked strings, escapes and nesting
// only: text, an object cut short, a trailing comma, an unquoted key and single-quoted
// ones. A parser that takes the last two (JSON5, a lenient JavaScript reader) reads
// _method from them.
var notJSONBodies = []string{
	`not json at all`, `{"a":1`, `{"a":1,}`, `{_method:"DELETE"}`, `{'_method':'DELETE'}`,
}

// moreNotJSON is the rest of the grammar the scanner checks, each refused by the
// buffered check too: misplaced commas and colons, mismatched closes, numbers and
// literals that are not JSON's, bad escapes, white space JSON does not allow, and
// nesting past encoding/json's limit.
var moreNotJSON = []string{
	`[1,]`, `[,1]`, `{,}`, `{"a" 1}`, `{"a":}`, `{"a"::1}`, `{"a":1 "b":2}`, `[1 2]`, `{"a",1}`, `[1:2]`, `{1:2}`,
	`}`, `]`, `,`, `:`, `{]`, `[}`, `{"a":[1,2}`, `{"a":"b"]`, `[`, `{`, `{"a"`, `{"a":`, `"abc`, `["a`,
	`-`, `-a`, `1.`, `1.e5`, `.5`, `1e`, `1e+`, `+1`, `[01]`, `[-01]`, `[0x1]`, `[1.5.2]`, `[1e5e5]`, `[--1]`, `[Infinity]`, `[NaN]`,
	`tru`, `nul`, `fals`, `True`, `[nulll]`, `[tRue]`, `[undefined]`,
	`"\x"`, `"\u12g4"`, `"\u12"`, `"\` + "'" + `"`, `{"a\x":1}`, `{"\u00zz":1}`, `["\U0041"]`,
	"{\u00a0\"a\":1}", "{\"a\":\u3000 1}", "[1,\xc2\xa0 2]",
	strings.Repeat("[", 10001) + strings.Repeat("]", 10001),
	strings.Repeat(`{"a":`, 10001) + "1" + strings.Repeat("}", 10001),
}

// scanPieces feeds body to a fresh scanner in pieces of the sizes sizes gives (1 or
// more), then ends it, and returns the first refusal.
func scanPieces(body []byte, size func(rest int) int) error {
	s := &jsonOverrideScanner{}
	for rest := body; len(rest) > 0; {
		n := size(len(rest))
		if err := s.feed(rest[:n]); err != nil {
			return err
		}
		rest = rest[n:]
	}
	return s.end()
}

// TestStreamedScannerRefusesWhatIsNotJSON (release-109): every body the buffered check
// refuses as not JSON, the streamed scanner refuses too, fed one byte at a time and in
// two pieces split at every byte (the two halves among them), so a passed-through body
// is held to the same grammar as a buffered one (docs/capability-grants.md: a body sent
// as JSON that is not JSON is refused with 400). Through the broker, on a passed-through
// route, the API receives none of them whole.
func TestStreamedScannerRefusesWhatIsNotJSON(t *testing.T) {
	t.Parallel()
	for _, body := range append(append([]string{}, notJSONBodies...), moreNotJSON...) {
		name := body
		if len(name) > 40 {
			name = name[:40] + "..."
		}
		if got := checkJSONBody([]byte(body)); got != errBodyNotJSON {
			t.Errorf("%q: buffered %v, want %v", name, got, errBodyNotJSON)
		}
		if got := scanPieces([]byte(body), func(int) int { return 1 }); got != errBodyNotJSON {
			t.Errorf("%q one byte at a time: streamed %v, want %v", name, got, errBodyNotJSON)
		}
		if got := scanPieces([]byte(body), func(rest int) int { return max(1, (rest+1)/2) }); got != errBodyNotJSON {
			t.Errorf("%q in two halves: streamed %v, want %v", name, got, errBodyNotJSON)
		}
		if len(body) > 64 {
			continue
		}
		for at := 0; at <= len(body); at++ {
			s := &jsonOverrideScanner{}
			got := s.feed([]byte(body[:at]))
			if got == nil {
				got = s.feed([]byte(body[at:]))
			}
			if got == nil {
				got = s.end()
			}
			if got != errBodyNotJSON {
				t.Errorf("%q split at %d: streamed %v, want %v", name, at, got, errBodyNotJSON)
				break
			}
		}
	}

	standIn := &overrideStandIn{}
	core, err := newBrokerSession(overrideGrant(), "tok", standIn)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	padding := strings.Repeat("x", maxHostRequestBytes+1) // past the default limit: the passed-through path
	for _, body := range notJSONBodies {
		// The body's fault last, after a long first field (the text body has it first).
		streamed := `{"blob":"` + padding + `",` + strings.TrimPrefix(body, "{")
		if body[0] != '{' {
			streamed = body + " " + padding
		}
		for _, oneByte := range []bool{false, true} {
			var r io.Reader = strings.NewReader(streamed)
			if oneByte {
				r = iotest.OneByteReader(r)
			}
			resp := core.Call(context.Background(), brokerCall{Method: "POST", RawTarget: "/v1/items/42/attachments",
				Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: r, ContentLength: int64(len(streamed))})
			if acted := standIn.take(); resp.Status != http.StatusBadRequest || len(acted) > 0 || !strings.Contains(string(resp.Body), "is not JSON") {
				t.Errorf("%q passed through (one byte at a time %v): %d %q, upstream acted on %v; want 400 and nothing acted on", body, oneByte, resp.Status, resp.Body, acted)
			}
		}
	}
}

// TestStreamedScannerNestingLimitIsEncodingJSONs (release-109): the scanner's nesting
// stack is bounded at encoding/json's own limit, 10000, so the two checks agree on
// where deep nesting stops being JSON: 10000 levels pass both, 10001 are refused by
// both.
func TestStreamedScannerNestingLimitIsEncodingJSONs(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		depth int
		want  error
	}{{10000, nil}, {10001, errBodyNotJSON}} {
		for _, body := range []string{
			strings.Repeat("[", c.depth) + strings.Repeat("]", c.depth),
			strings.Repeat(`{"a":`, c.depth) + "1" + strings.Repeat("}", c.depth),
			strings.Repeat(`[{"a":`, c.depth/2) + strings.Repeat("[", c.depth%2) + "1" + strings.Repeat("]", c.depth%2) + strings.Repeat("}]", c.depth/2),
		} {
			if got := checkJSONBody([]byte(body)); got != c.want {
				t.Errorf("depth %d: buffered %v, want %v", c.depth, got, c.want)
			}
			if got := scanPieces([]byte(body), func(rest int) int { return min(rest, 7) }); got != c.want {
				t.Errorf("depth %d: streamed %v, want %v", c.depth, got, c.want)
			}
		}
	}
}

// TestStreamedScannerReadsEveryTopLevelValue: the scanner reads a sequence of top-level
// values separated by white space and refuses an override in any of them, and two
// values with nothing between them. The buffered check reads the first value only, so
// it passes the second and the last four of these (the known difference, in the
// refusing direction for the scanner: it refuses more, never less).
func TestStreamedScannerReadsEveryTopLevelValue(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		body string
		want error
	}{
		{"{\"a\":1}\n{\"b\":2}", nil},
		{`{"a":1} {"_method":"DELETE"}`, errOverrideField},
		{`1 2 "x" [3] true null`, nil},
		{`{}{}`, errBodyNotJSON},
		{`{"a":1} x`, errBodyNotJSON},
		{`{"a":1},{"b":2}`, errBodyNotJSON},
		{`{"a":1}}`, errBodyNotJSON},
	} {
		if got := scanPieces([]byte(c.body), func(int) int { return 1 }); got != c.want {
			t.Errorf("%q: streamed %v, want %v", c.body, got, c.want)
		}
	}
}

// FuzzJSONOverrideScannerAgreesWithDecoder: on any body, fed in pieces of random sizes,
// the streamed scanner refuses whatever the buffered check refuses (release-109: not
// JSON included), and on a valid JSON body it finds a top-level override key exactly
// when encoding/json does.
func FuzzJSONOverrideScannerAgreesWithDecoder(f *testing.F) {
	for _, body := range jsonOverrideCorpus {
		f.Add([]byte(body), uint32(3))
	}
	for _, body := range append(append([]string{}, notJSONBodies...), moreNotJSON[:len(moreNotJSON)-2]...) {
		f.Add([]byte(body), uint32(5))
	}
	f.Add([]byte("{\"\x84\":0}"), uint32(0)) // Go's json.Valid takes invalid UTF-8 in a string; both readers refuse it
	f.Fuzz(func(t *testing.T, body []byte, seed uint32) {
		want := checkJSONBody(body)
		r := seed | 1 // xorshift32 state: the piece sizes
		got := scanPieces(body, func(rest int) int {
			r ^= r << 13
			r ^= r >> 17
			r ^= r << 5
			return 1 + int(r%uint32(rest))
		})
		if want != nil && got == nil {
			t.Fatalf("%q (seed %d): buffered %v, scanner passes it", body, seed, want)
		}
		if !json.Valid(bytes.TrimPrefix(body, utf8BOM)) {
			return
		}
		// Valid JSON: the same answer, the override field, nothing, or (for invalid UTF-8
		// inside a string, which encoding/json accepts) not JSON. The buffered check reads
		// the UTF-8 first; the scanner may meet the field, or a key that is not plain
		// (hunt-security-19), first.
		if got != want && !(want == errBodyNotJSON && (got == errOverrideField || got == errKeyNotPlain)) {
			t.Fatalf("%q (seed %d): scanner %v, decoder %v", body, seed, got, want)
		}
	})
}

// BenchmarkJSONOverrideScanner times the scanner on a 64 MiB valid JSON body in the
// transport's 32 KiB pieces: records of every kind of value, and one long string (a
// file sent as base64, the usual reason for a raised limit). It runs on every
// passed-through JSON body.
func BenchmarkJSONOverrideScanner(b *testing.B) {
	const size = 64 << 20
	record := `{"id":12345,"name":"widget \"x\" ` + jsonEscape("00e9") + ` naïve","price":-12.5e3,"tags":["a","b",[1,2,{"k":0}]],"ok":true,"none":null},`
	var mixed bytes.Buffer
	mixed.WriteString(`{"items":[`)
	for mixed.Len()+len(record)+2 < size {
		mixed.WriteString(record)
	}
	mixed.Truncate(mixed.Len() - 1)
	mixed.WriteString(`]}`)
	str := []byte(`{"blob":"` + strings.Repeat("QUJD", (size-12)/4) + `"}`)
	for _, c := range []struct {
		name string
		body []byte
	}{{"records", mixed.Bytes()}, {"one string", str}} {
		if !json.Valid(c.body) {
			b.Fatalf("%s: not JSON", c.name)
		}
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(c.body)))
			for b.Loop() {
				if err := scanPieces(c.body, func(rest int) int { return min(rest, 32<<10) }); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestBrokerDefaultTransportIgnoresProxyEnvironment (hunt-security-8): the broker's
// default transport sends no call through a proxy the environment names, so a call
// that carries the API's credential never makes an undeclared hop. The check runs in a
// child process, because Go reads the proxy variables once per process.
func TestBrokerDefaultTransportIgnoresProxyEnvironment(t *testing.T) {
	if os.Getenv("PLIMSOLL_PROXY_CHILD") == "1" {
		brokerProxyChild(t)
		return
	}
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var reached atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			reached.Add(1)
			conn.Close()
		}
	}()
	proxy := "http://" + ln.Addr().String()
	cmd := exec.Command(os.Args[0], "-test.run=^TestBrokerDefaultTransportIgnoresProxyEnvironment$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PLIMSOLL_PROXY_CHILD=1", "HTTPS_PROXY="+proxy, "HTTP_PROXY="+proxy, "https_proxy="+proxy,
		"http_proxy="+proxy, "NO_PROXY=", "no_proxy=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the proxy the environment named was reached %d times; the broker must dial the API itself", n)
	}
}

func brokerProxyChild(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737): never routed, and not loopback, so Go would
	// send a call for it through an environment proxy. Without one the dial waits until
	// the call's context ends.
	core, err := newBrokerSession(&HostAPIGrant{BaseURL: "https://192.0.2.1", Allow: []HostRoute{{Method: "GET", Path: "/v1/x"}}}, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = core.Call(ctx, brokerCall{Method: "GET", RawTarget: "/v1/x"})
}
