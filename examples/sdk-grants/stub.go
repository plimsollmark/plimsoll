package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// The stub stands in for a small part of two APIs: OpenAI's chat completions (answered
// whole and streamed), files and embeddings, and Anthropic's messages (whole and
// streamed). It is the upstream the broker calls; no real model API is reached, and it
// writes down every request it receives, headers included, which is what the page shows
// beside what the SDK in the sandbox sent.

// streamGap is the time the stub waits between two pieces of a streamed answer: long
// enough that a stream buffered whole somewhere on the way would show as every piece
// arriving at once, after the last was written.
const streamGap = 400 * time.Millisecond

// maxLoggedBody is the largest request body the log keeps verbatim (the JSON calls).
// Larger bodies (the upload) are logged by length and SHA-256, part by part.
const maxLoggedBody = 64 << 10

// stubRequest is one request the stub received, as it received it.
type stubRequest struct {
	Seq        int           `json:"seq"`
	API        string        `json:"api"` // openai or anthropic: which of the two stub listeners
	ReceivedMs float64       `json:"received_ms"`
	Method     string        `json:"method"`
	Target     string        `json:"target"` // the request target as sent: path and any query
	Headers    [][2]string   `json:"headers"`
	BodyBytes  int64         `json:"body_bytes"`
	BodySHA256 string        `json:"body_sha256"`
	Body       string        `json:"body,omitempty"` // verbatim when at most maxLoggedBody and not multipart
	Parts      []stubPart    `json:"parts,omitempty"`
	Status     int           `json:"status"`
	Stream     []streamWrite `json:"stream,omitempty"`
	// Markers counts, in the raw body as received, each value the stub was told to look
	// for: the dummy keys the profiles put in the guest's environment and the keys the
	// daemon holds. A body the log keeps verbatim can be searched again from the log; an
	// upload's cannot, so the count is the stub's own.
	Markers map[string]int `json:"markers"`
}

// stubPart is one part of a multipart body.
type stubPart struct {
	Name        string `json:"name"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
}

// streamWrite is one piece of a streamed answer: when the stub wrote and flushed it.
type streamWrite struct {
	N         int     `json:"n"`
	WrittenMs float64 `json:"written_ms"`
	Event     string  `json:"event"` // the piece's event: the SSE event name or the chunk's text
	Bytes     int     `json:"bytes"`
}

type stub struct {
	mu      sync.Mutex
	log     []stubRequest
	srvs    []*http.Server
	urls    map[string]string
	markers []string
}

func unixMs(t time.Time) float64 { return float64(t.UnixMicro()) / 1000 }

// startStub listens on two loopback ports, one per API, and serves until close. It
// counts each of markers in every request body it receives.
func startStub(markers []string) (*stub, error) {
	s := &stub{urls: map[string]string{}, markers: markers}
	for _, api := range []string{"openai", "anthropic"} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			s.close()
			return nil, err
		}
		srv := &http.Server{Handler: s.handler(api), ReadHeaderTimeout: 10 * time.Second}
		s.srvs = append(s.srvs, srv)
		s.urls[api] = "http://" + l.Addr().String()
		go func() { _ = srv.Serve(l) }()
	}
	return s, nil
}

func (s *stub) close() {
	for _, srv := range s.srvs {
		_ = srv.Close()
	}
}

func (s *stub) requests() []stubRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubRequest(nil), s.log...)
}

func (s *stub) handler(api string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := stubRequest{API: api, ReceivedMs: unixMs(time.Now()), Method: r.Method, Target: r.RequestURI, Headers: headerList(r.Header)}
		if r.Host != "" {
			rec.Headers = append([][2]string{{"Host", r.Host}}, rec.Headers...)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading the body: "+err.Error(), http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(body)
		rec.BodyBytes, rec.BodySHA256 = int64(len(body)), hex.EncodeToString(sum[:])
		rec.Markers = map[string]int{}
		for _, m := range s.markers {
			rec.Markers[m] = bytes.Count(body, []byte(m))
		}
		mediaType, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaType == "multipart/form-data" {
			rec.Parts, err = readParts(body, params["boundary"])
			if err != nil {
				rec.Status = http.StatusBadRequest
				s.add(rec)
				http.Error(w, "not multipart: "+err.Error(), http.StatusBadRequest)
				return
			}
		} else if len(body) <= maxLoggedBody {
			rec.Body = string(body)
		}
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		route := r.Method + " " + r.URL.Path
		switch {
		case api == "openai" && route == "POST /v1/chat/completions" && req["stream"] == true:
			rec.Status, rec.Stream = 200, s.streamOpenAI(w)
		case api == "openai" && route == "POST /v1/chat/completions":
			rec.Status = writeJSON(w, 200, map[string]any{
				"id": "chatcmpl-stub-1", "object": "chat.completion", "created": time.Now().Unix(), "model": req["model"],
				"choices": []any{map[string]any{"index": 0, "finish_reason": "stop",
					"message": map[string]any{"role": "assistant", "content": "Hello from the stub API."}}},
				"usage": map[string]any{"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8},
			})
		case api == "openai" && route == "POST /v1/files":
			var file stubPart
			for _, p := range rec.Parts {
				if p.Name == "file" {
					file = p
				}
			}
			rec.Status = writeJSON(w, 200, map[string]any{
				"id": "file-stub-1", "object": "file", "bytes": file.Bytes, "created_at": time.Now().Unix(),
				"filename": file.Filename, "purpose": "user_data", "status": "processed",
			})
		case api == "openai" && route == "POST /v1/embeddings":
			// The profile does not allow this route, so the broker must refuse it; the stub
			// would answer, which is how the page tells the broker's refusal from the API's.
			rec.Status = writeJSON(w, 200, map[string]any{"object": "list", "model": req["model"],
				"data": []any{map[string]any{"object": "embedding", "index": 0, "embedding": []float64{0.1, 0.2}}}})
		case api == "anthropic" && route == "POST /v1/messages" && req["stream"] == true:
			rec.Status, rec.Stream = 200, s.streamAnthropic(w)
		case api == "anthropic" && route == "POST /v1/messages":
			rec.Status = writeJSON(w, 200, map[string]any{
				"id": "msg_stub_1", "type": "message", "role": "assistant", "model": req["model"],
				"content":     []any{map[string]any{"type": "text", "text": "Hello from the stub API."}},
				"stop_reason": "end_turn", "stop_sequence": nil,
				"usage": map[string]any{"input_tokens": 3, "output_tokens": 5},
			})
		default:
			rec.Status = writeJSON(w, 404, map[string]any{"error": map[string]any{"type": "not_found", "message": "the stub serves no " + route}})
		}
		s.add(rec)
	})
}

func (s *stub) add(rec stubRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.Seq = len(s.log) + 1
	s.log = append(s.log, rec)
}

func writeJSON(w http.ResponseWriter, status int, v any) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
	return status
}

// headerList is a request's headers as name and value pairs, sorted by name, every
// value kept.
func headerList(h http.Header) [][2]string {
	names := make([]string, 0, len(h))
	for n := range h {
		names = append(names, n)
	}
	sort.Strings(names)
	var out [][2]string
	for _, n := range names {
		for _, v := range h[n] {
			out = append(out, [2]string{n, v})
		}
	}
	return out
}

func readParts(body []byte, boundary string) ([]stubPart, error) {
	if boundary == "" {
		return nil, fmt.Errorf("no boundary")
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var parts []stubPart
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return parts, nil
		}
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(h, p)
		if err != nil {
			return nil, err
		}
		parts = append(parts, stubPart{Name: p.FormName(), Filename: p.FileName(), ContentType: p.Header.Get("Content-Type"), Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
}

// sse writes one server-sent event and flushes it, waiting streamGap first unless it is
// the first piece, and returns when it went.
func sse(w http.ResponseWriter, n int, event, data string) (streamWrite, error) {
	if n > 1 {
		time.Sleep(streamGap)
	}
	var b strings.Builder
	if event != "" {
		b.WriteString("event: " + event + "\n")
	}
	b.WriteString("data: " + data + "\n\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return streamWrite{}, err
	}
	if err := http.NewResponseController(w).Flush(); err != nil {
		return streamWrite{}, err
	}
	return streamWrite{N: n, WrittenMs: unixMs(time.Now()), Bytes: b.Len()}, nil
}

// streamPieces is the answer both streams spell out, one piece per event.
var streamPieces = []string{"Pieces ", "of ", "an ", "answer, ", "one ", "at ", "a ", "time."}

func (s *stub) streamOpenAI(w http.ResponseWriter) []streamWrite {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	var writes []streamWrite
	created := time.Now().Unix()
	for i, piece := range streamPieces {
		chunk, _ := json.Marshal(map[string]any{
			"id": "chatcmpl-stub-2", "object": "chat.completion.chunk", "created": created, "model": "stub-model",
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": piece}, "finish_reason": nil}},
		})
		wr, err := sse(w, i+1, "", string(chunk))
		if err != nil {
			return writes
		}
		wr.Event = piece
		writes = append(writes, wr)
	}
	if wr, err := sse(w, len(streamPieces)+1, "", "[DONE]"); err == nil {
		wr.Event = "[DONE]"
		writes = append(writes, wr)
	}
	return writes
}

func (s *stub) streamAnthropic(w http.ResponseWriter) []streamWrite {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	type ev struct {
		name string
		data map[string]any
	}
	events := []ev{{"message_start", map[string]any{"type": "message_start", "message": map[string]any{
		"id": "msg_stub_2", "type": "message", "role": "assistant", "model": "stub-model", "content": []any{},
		"stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": 3, "output_tokens": 1}}}},
		{"content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}}},
	}
	for _, piece := range streamPieces {
		events = append(events, ev{"content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": piece}}})
	}
	events = append(events,
		ev{"content_block_stop", map[string]any{"type": "content_block_stop", "index": 0}},
		ev{"message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]any{"output_tokens": len(streamPieces)}}},
		ev{"message_stop", map[string]any{"type": "message_stop"}},
	)
	var writes []streamWrite
	for i, e := range events {
		data, _ := json.Marshal(e.data)
		wr, err := sse(w, i+1, e.name, string(data))
		if err != nil {
			return writes
		}
		wr.Event = e.name
		if d, ok := e.data["delta"].(map[string]any); ok {
			if t, ok := d["text"].(string); ok {
				wr.Event += ": " + t
			}
		}
		writes = append(writes, wr)
	}
	return writes
}
