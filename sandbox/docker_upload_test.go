package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// checkerUpstream stands in for the API a video-checking program uses the way the OpenAI
// client library and httpx send to it: a Files route that takes a multipart upload (the
// clip and a purpose field), a Responses route that answers JSON or, for stream:true,
// server-sent events, and a transcription route that takes a two-part multipart (a JSON
// request part and a WAV clip). It records what each request carried.
type checkerUpstream struct {
	mu   sync.Mutex
	seen []checkerSeen
}

type checkerSeen struct {
	path, contentType string
	length            int64
	parts             map[string]int    // multipart part name to its bytes
	partTypes         map[string]string // multipart part name to its Content-Type
}

func newCheckerUpstream(t *testing.T) (*httptest.Server, *checkerUpstream) {
	t.Helper()
	u := &checkerUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen := checkerSeen{path: r.URL.Path, contentType: r.Header.Get("Content-Type"), length: r.ContentLength, parts: map[string]int{}, partTypes: map[string]string{}}
		switch r.URL.Path {
		case "/v1/files", "/v1/asr/transcribe":
			mr, err := r.MultipartReader()
			if err != nil {
				http.Error(w, "not multipart: "+err.Error(), http.StatusBadRequest)
				return
			}
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				n, _ := io.Copy(io.Discard, p)
				seen.parts[p.FormName()] = int(n)
				seen.partTypes[p.FormName()] = p.Header.Get("Content-Type")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"file-1","turns":[]}`)
		case "/v1/responses":
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			seen.length = int64(len(body))
			if req["stream"] == true {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				rc := http.NewResponseController(w)
				for i, ev := range []string{`{"type":"response.created"}`, `{"type":"response.output_text.delta","delta":"[0.1,"}`, `{"type":"response.output_text.delta","delta":"0.2]"}`, `{"type":"response.completed"}`} {
					if i > 0 {
						time.Sleep(300 * time.Millisecond)
					}
					_, _ = io.WriteString(w, "data: "+ev+"\n\n")
					_ = rc.Flush()
				}
			} else {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"resp-1","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"{\"ok\":true}"}]}]}`)
			}
		default:
			w.WriteHeader(http.StatusTeapot)
		}
		u.mu.Lock()
		u.seen = append(u.seen, seen)
		u.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, u
}

// checkerGrant is the profile such a program needs: its three routes, multipart on the
// two upload routes, 16 MiB a clip upload, 8 MiB a transcription, 48 MiB a run, and the
// base URL and placeholder key in the environment the client library reads.
func checkerGrant(baseURL string) *HostAPIGrant {
	files := HostRoute{Method: "POST", Path: "/v1/files"}
	responses := HostRoute{Method: "POST", Path: "/v1/responses"}
	transcribe := HostRoute{Method: "POST", Path: "/v1/asr/transcribe"}
	return &HostAPIGrant{
		BaseURL:              baseURL,
		Allow:                []HostRoute{files, responses, transcribe},
		Minter:               StaticToken("api-key-held-by-the-daemon"),
		SDKEnv:               map[string]string{"OPENAI_BASE_URL": "{origin}/v1", "MODEL_API_KEY": "plimsoll-grant"},
		RouteMaxRequestBytes: map[HostRoute]int64{files: 16 << 20, transcribe: 8 << 20},
		RouteContentTypes:    map[HostRoute][]string{files: {"multipart/form-data"}, transcribe: {"multipart/form-data"}},
		MaxRequestBytes:      48 << 20,
	}
}

// checkerClient is the program's four requests with the standard library alone, shaped
// as the OpenAI client library and httpx send them: multipart with a declared length, a
// placeholder bearer from the environment, the library's telemetry headers; then the
// refusals: a clip over the route's limit, a body of a type the route does not take, and
// clips past the run's total. A refused declared upload is answered before its body is
// read, so the client may see its 413 or, having been cut off while still sending, a
// closed connection: both are printed as "refused".
const checkerClient = `import json, os, sys, time, urllib.request, urllib.error
base = os.environ["OPENAI_BASE_URL"]; key = os.environ["MODEL_API_KEY"]
H = {"Authorization": "Bearer " + key, "User-Agent": "OpenAI/Python 3.39.0", "X-Stainless-Lang": "python", "Accept": "application/json"}
def multipart(parts):
    b = "plimsoll-boundary-7f3a9c"; out = bytearray()
    for name, filename, ctype, data in parts:
        out += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"" % (b, name)).encode()
        if filename: out += ("; filename=\"%s\"" % filename).encode()
        out += ("\r\nContent-Type: %s\r\n\r\n" % ctype).encode() + data + b"\r\n"
    out += ("--%s--\r\n" % b).encode()
    return bytes(out), "multipart/form-data; boundary=" + b
def post(path, body, ctype):
    req = urllib.request.Request(base + path, data=body, headers={**H, "Content-Type": ctype}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e: return e.code, e.headers, e.read()
def outcome(path, body, ctype):
    try:
        s, h, out = post(path, body, ctype)
        return "refused %d %s" % (s, h.get("X-Should-Retry")) if s >= 400 else "ok %d" % s
    except (urllib.error.URLError, OSError) as e:
        return "refused closed"
# base is the library's base URL, ".../v1", so paths are relative to it as the library
# sends them: files.create posts to {base}/files.
clip = os.urandom(12 << 20)
body, ct = multipart([("purpose", None, "text/plain", b"user_data"), ("file", "4f1c.mp4", "video/mp4", clip)])
s, h, out = post("/files", body, ct); print("FILES", s, len(body), json.loads(out).get("id"))
wav = os.urandom(3 << 20)
body2, ct2 = multipart([("request", None, "application/json", json.dumps({"model": "voice", "audioEncoding": "WAV"}).encode()), ("audio", "clip.wav", "audio/wav", wav)])
s, h, out = post("/asr/transcribe", body2, ct2); print("TRANSCRIBE", s, len(body2))
s, h, out = post("/responses", json.dumps({"model": "m", "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}, {"type": "input_video", "file_id": "file-1"}]}]}).encode(), "application/json")
print("RESPONSES", s, json.loads(out).get("status"))
req = urllib.request.Request(base + "/responses", data=json.dumps({"model": "m", "stream": True, "input": []}).encode(), headers={**H, "Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req, timeout=60) as r:
    first = last = None; n = 0
    while True:
        chunk = r.read(256)
        if not chunk: break
        now = time.time(); first = first or now; last = now; n += len(chunk)
print("STREAM", r.status, r.headers.get("Content-Type"), int((last - first) * 1000), n)
big, ctb = multipart([("purpose", None, "text/plain", b"user_data"), ("file", "big.mp4", "video/mp4", os.urandom(17 << 20))])
print("OVER-ROUTE", outcome("/files", big, ctb))
print("WRONG-TYPE", outcome("/files", body2[:16384], "application/octet-stream"))
# The run's total is 48 MiB; about 15 MiB went. Two more clips fit (39 MiB), the third does not.
codes = []
for i in range(3):
    body, ct = multipart([("purpose", None, "text/plain", b"user_data"), ("file", "clip%d.mp4" % i, "video/mp4", clip)])
    codes.append(outcome("/files", body, ct))
print("BUDGET", "|".join(codes))
`

// TestDockerProjectGrantCarriesTheCheckersUploads: a video-checking program's requests,
// from a Python step through the local address: a 12 MiB clip upload and a 3 MiB
// transcription as multipart bodies the broker passes through with their boundaries
// and declared lengths, a JSON call, a streamed answer in pieces; then the refusals: a
// clip over the route's limit, a body of a type the route does not take, and uploads
// past the run's total, none of which reaches the API.
func TestDockerProjectGrantCarriesTheCheckersUploads(t *testing.T) {
	t.Parallel()
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	requireProjectImage(t, d)
	shippedSeccomp(t, d)
	upstream, seen := newCheckerUpstream(t)
	res, err := d.RunProject(context.Background(), ProjectRequest{
		Files:   []File{{Path: "main.py", Content: checkerClient}},
		Steps:   []string{"python3 main.py"},
		Grant:   checkerGrant(upstream.URL),
		Timeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("outcome %v (%s): %+v\ntrace: %+v", res.Outcome, res.Detail, res.Steps, res.CallTrace)
	}
	out := string(res.Steps[0].Stdout)
	// OVER-ROUTE and the third BUDGET clip are declared uploads refused before their
	// bodies are read: the client sees the 413 or, cut off while still sending, a closed
	// connection (the program prints "refused closed"); either way the API never sees
	// them, which the upstream's counts below assert. WRONG-TYPE's small body is drained
	// by the server, so its 415 and no-retry mark always reach the client.
	for _, want := range []string{"FILES 200 ", " file-1", "TRANSCRIBE 200 ", "RESPONSES 200 completed", "STREAM 200 text/event-stream", "OVER-ROUTE refused", "WRONG-TYPE refused 415 false", "BUDGET ok 200|ok 200|refused"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s\n%s", want, out, res.Steps[0].Stderr)
		}
	}
	seen.mu.Lock()
	defer seen.mu.Unlock()
	var files, transcribe, responses int
	for _, s := range seen.seen {
		switch s.path {
		case "/v1/files":
			files++
			if !strings.HasPrefix(s.contentType, "multipart/form-data; boundary=plimsoll-boundary-7f3a9c") || s.parts["file"] != 12<<20 || s.parts["purpose"] != len("user_data") || s.length < 12<<20 {
				t.Errorf("a clip upload reached the API as %+v", s)
			}
		case "/v1/asr/transcribe":
			transcribe++
			if s.parts["audio"] != 3<<20 || s.partTypes["request"] != "application/json" || s.partTypes["audio"] != "audio/wav" {
				t.Errorf("the transcription reached the API as %+v", s)
			}
		case "/v1/responses":
			responses++
		}
	}
	if files != 3 || transcribe != 1 || responses != 2 {
		t.Errorf("the API saw %d clip uploads, %d transcriptions and %d responses calls; want 3, 1 and 2 (the refused uploads never arrive)", files, transcribe, responses)
	}
	if res.CallTrace == nil {
		t.Fatal("no trace")
	}
	var sent int
	for _, row := range res.CallTrace.Calls {
		sent += row.ReqBytes
	}
	if sent < 39<<20 || sent > 48<<20 {
		t.Errorf("trace request bytes %d, want three clips, the transcription and two small bodies, between 39 and 48 MiB", sent)
	}
	if res.CallTrace.Denied != 3 {
		t.Errorf("trace Denied = %d, want 3 (the clip over the limit, the wrong type, the clip past the total)", res.CallTrace.Denied)
	}
}
