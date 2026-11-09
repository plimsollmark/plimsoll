package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// fakeMemory stands in for Cloudflare's Agent Memory HTTP API on loopback. It answers
// the three operations the example's grant allows, in the response envelope the
// published OpenAPI document gives them ({"success", "errors", "messages", "result"}),
// and it refuses every request that does not carry the token the broker injects. It is
// a fake for the plumbing, not a model of the service: its recall is a word match
// against the profile's stored memories, where Cloudflare's runs a retrieval model and
// writes the answer with a language model.
//
// It writes down every request it receives (method, path, and whether the credential
// was the expected one), so the page can show what reached the API and what never did.
type fakeMemory struct {
	token string

	mu       sync.Mutex
	seen     []seenRequest
	memories map[string][]memory // by profile path prefix, in the order stored
	nextID   int
}

// seenRequest is one request as the fake received it. Path is the full request path:
// the fake is the API, so it sees what the API sees; the broker's trace is what keeps
// only the route template.
type seenRequest struct {
	Method     string
	Path       string
	Credential string // "the broker's token", "none" or "a wrong one"
	Status     int
}

type memory struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Summary   string `json:"summary"`
	Content   string `json:"content"`
	SessionID string `json:"sessionId,omitempty"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

func newFakeMemory(token string) *fakeMemory {
	return &fakeMemory{token: token, memories: map[string][]memory{}}
}

// requests returns a copy of every request received so far.
func (f *fakeMemory) requests() []seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenRequest(nil), f.seen...)
}

// The fixed clock: every memory is stamped with the same time, so the page the
// example writes is the same on every run.
const fakeTime = "2026-11-05T12:00:00Z"

func (f *fakeMemory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	seen := seenRequest{Method: r.Method, Path: r.URL.Path, Credential: "none"}
	status, body := f.answer(r, &seen)
	seen.Status = status
	f.seen = append(f.seen, seen)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// answer decides the response. It runs with f.mu held.
func (f *fakeMemory) answer(r *http.Request, seen *seenRequest) (int, any) {
	switch got := r.Header.Get("Authorization"); {
	case got == "Bearer "+f.token:
		seen.Credential = "the broker's token"
	case got != "":
		seen.Credential = "a wrong one"
		return http.StatusUnauthorized, failure(10000, "Authentication error")
	default:
		return http.StatusUnauthorized, failure(10000, "Authentication error")
	}

	// /client/v4/accounts/{account}/agent-memory/namespaces/{ns}/profiles/{profile}/...
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(segs) < 10 || segs[0] != "client" || segs[1] != "v4" || segs[2] != "accounts" ||
		segs[4] != "agent-memory" || segs[5] != "namespaces" || segs[7] != "profiles" {
		return http.StatusNotFound, failure(7003, "no route for that URI")
	}
	profile := strings.Join(segs[:9], "/")
	switch {
	case r.Method == http.MethodPost && len(segs) == 10 && segs[9] == "remember":
		var in struct {
			Content   string `json:"content"`
			SessionID string `json:"sessionId"`
		}
		if err := decode(r, &in); err != nil || strings.TrimSpace(in.Content) == "" {
			return http.StatusBadRequest, failure(10001, "content is required")
		}
		f.nextID++
		m := memory{
			ID:        fmt.Sprintf("01JFAKEMEM%016d", f.nextID),
			Type:      "fact",
			Summary:   in.Content,
			Content:   in.Content,
			SessionID: in.SessionID,
			CreatedAt: fakeTime,
			UpdatedAt: fakeTime,
		}
		f.memories[profile] = append(f.memories[profile], m)
		return http.StatusOK, success(m)

	case r.Method == http.MethodPost && len(segs) == 10 && segs[9] == "recall":
		var in struct {
			Query string `json:"query"`
		}
		if err := decode(r, &in); err != nil || strings.TrimSpace(in.Query) == "" {
			return http.StatusBadRequest, failure(10001, "query is required")
		}
		type candidate struct {
			ID        string  `json:"id"`
			Summary   string  `json:"summary"`
			SessionID *string `json:"sessionId"`
			Score     float64 `json:"score"`
		}
		var found []candidate
		for _, m := range f.memories[profile] {
			if score := overlap(in.Query, m.Content); score > 0 {
				sid := m.SessionID
				found = append(found, candidate{ID: m.ID, Summary: m.Summary, SessionID: &sid, Score: score})
			}
		}
		sort.SliceStable(found, func(i, j int) bool { return found[i].Score > found[j].Score })
		result := map[string]any{"count": len(found), "candidates": found}
		if len(found) > 0 {
			result["answer"] = found[0].Summary
		} else {
			found = []candidate{}
			result["candidates"] = found
		}
		return http.StatusOK, success(result)

	case r.Method == http.MethodGet && len(segs) == 11 && segs[9] == "memories":
		for _, m := range f.memories[profile] {
			if m.ID == segs[10] {
				return http.StatusOK, success(m)
			}
		}
		return http.StatusNotFound, failure(10004, "memory not found")
	}
	return http.StatusNotFound, failure(7003, "no route for that URI")
}

// overlap scores a stored memory against a query: the share of the query's words of
// four letters or more that the memory contains. A fake's stand-in for retrieval, so
// that the recall in the example finds what was stored.
func overlap(query, content string) float64 {
	words := func(s string) map[string]bool {
		out := map[string]bool{}
		for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') }) {
			if len(w) >= 4 {
				out[w] = true
			}
		}
		return out
	}
	q, c := words(query), words(content)
	if len(q) == 0 {
		return 0
	}
	hit := 0
	for w := range q {
		if c[w] {
			hit++
		}
	}
	return float64(hit) / float64(len(q))
}

func decode(r *http.Request, v any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func success(result any) map[string]any {
	return map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result}
}

// failure is an error envelope. Its codes are the fake's own; only the envelope's shape
// is taken from the document.
func failure(code int, message string) map[string]any {
	return map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": message}}, "messages": []any{}, "result": nil}
}
