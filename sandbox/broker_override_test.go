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
// reader's answer whichever byte the body is split at.
func TestJSONOverrideScannerAtEverySplit(t *testing.T) {
	t.Parallel()
	for _, body := range jsonOverrideCorpus {
		want := checkJSONBody([]byte(body)) == errOverrideField
		for i := 0; i <= len(body); i++ {
			s := &jsonOverrideScanner{}
			got := s.feed([]byte(body[:i])) != nil || s.feed([]byte(body[i:])) != nil
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

// FuzzJSONOverrideScannerAgreesWithDecoder: on every valid JSON body, split anywhere,
// the streamed scanner finds a top-level override key exactly when encoding/json does.
func FuzzJSONOverrideScannerAgreesWithDecoder(f *testing.F) {
	for _, body := range jsonOverrideCorpus {
		f.Add([]byte(body), uint16(3))
	}
	f.Add([]byte("{\"\x84\":0}"), uint16(0)) // Go's json.Valid takes invalid UTF-8 in a string; both readers refuse it
	f.Fuzz(func(t *testing.T, body []byte, split uint16) {
		if !json.Valid(bytes.TrimPrefix(body, utf8BOM)) {
			return
		}
		// Valid JSON: the same answer, the override field, nothing, or (for invalid UTF-8
		// inside a string, which encoding/json accepts) not JSON.
		want := checkJSONBody(body)
		at := int(split) % (len(body) + 1)
		s := &jsonOverrideScanner{}
		got := s.feed(body[:at])
		if got == nil {
			got = s.feed(body[at:])
		}
		if got == nil {
			got = s.end()
		}
		// The buffered check reads the UTF-8 first; the scanner may meet the field first.
		if got != want && !(want == errBodyNotJSON && got == errOverrideField) {
			t.Fatalf("%q split at %d: scanner %v, decoder %v", body, at, got, want)
		}
	})
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
