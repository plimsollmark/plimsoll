package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The caller's model, the one that writes each rebuild, through one of two APIs: an
// OpenAI-compatible chat completions API (chat, the shape of examples/nemotron-agent), or
// Anthropic's native Messages API (messagesAPI), which returns the model's reasoning summary and
// caches the conversation's prefix. Both keep one token budget across every rebuild of a run, so
// a run cannot spend past what its caller allowed, and both refuse a call that could take the run
// past it.

// agentModel opens one conversation per rebuild.
type agentModel interface {
	start(system, prompt string, tools []toolSpec) dialogue
	used() usage
	label() (model, base string)
}

// dialogue is one rebuild's conversation. next sends it and appends the model's answer; results
// and say add the next user turn: the answered tool calls, then any words.
type dialogue interface {
	next(ctx context.Context, capped bool) (answer, error)
	results(rs []toolResult)
	say(text string)
}

// answer is one model turn as the rebuild loop reads it, whatever the API.
type answer struct {
	Text            string        `json:"text,omitempty"`
	Reasoning       string        `json:"reasoning,omitempty"` // the reasoning summary, Messages API only
	ReasoningHidden bool          `json:"reasoning_hidden,omitempty"`
	Calls           []toolCallReq `json:"calls,omitempty"`
	Stop            string        `json:"stop"`
	Usage           callUsage     `json:"usage"`
}

type toolCallReq struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type toolResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
	// Kind is how the call went, for the record only: ok, refused (a rule the model can read
	// and follow), or fault (the harness could not answer it). The model is sent Content.
	Kind string `json:"kind"`
}

// toolSpec is a tool as the rebuild offers it; each API encodes it its own way.
type toolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"input_schema"`
}

func newTool(name, description string, properties map[string]any, required ...string) toolSpec {
	if required == nil {
		required = []string{}
	}
	return toolSpec{Name: name, Description: description, Schema: map[string]any{"type": "object", "properties": properties, "required": required}}
}

// usage is the run's tokens, all rebuilds together. Prompt counts every prompt token the API
// reports, cache reads and writes included; CacheRead and CacheWrite say how many of them were.
type usage struct {
	Prompt     int `json:"prompt"`
	Completion int `json:"completion"`
	CacheRead  int `json:"cache_read,omitempty"`
	CacheWrite int `json:"cache_write,omitempty"`
	Calls      int `json:"calls"`
}

// callUsage is one call's tokens, as the API reported them.
type callUsage struct {
	Input      int `json:"input"`
	CacheWrite int `json:"cache_write,omitempty"`
	CacheRead  int `json:"cache_read,omitempty"`
	Output     int `json:"output"`
}

// budget is the run's token allowance, shared by every rebuild: a call is sent only if what the
// run has used, plus the call's prompt and its whole output allowance, fits.
type budget struct {
	limit int
	mu    sync.Mutex
	u     usage
}

func (b *budget) used() usage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.u
}

func (b *budget) fits(prompt, maxOut int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.u.Prompt+b.u.Completion+prompt+maxOut <= b.limit
}

func (b *budget) add(c callUsage) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.u.Prompt += c.Input + c.CacheWrite + c.CacheRead
	b.u.CacheWrite += c.CacheWrite
	b.u.CacheRead += c.CacheRead
	b.u.Completion += c.Output
	b.u.Calls++
}

// errBudget is a model call refused because it could take the run past its token budget.
var errBudget = errors.New("the run's model token budget would be passed by the next call")

// errPromptCap ends a rebuild whose conversation has grown past the job's prompt cap.
var errPromptCap = errors.New("the conversation has grown past the job's prompt cap")

// maxAnswerBytes bounds what is read of the model's answer.
const maxAnswerBytes = 8 << 20

// loopbackBase reports whether an API base is on this machine (a test's server, or a local
// relay that holds the real key and its own spend ledger), where no -paid flag is needed.
func loopbackBase(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// post sends one JSON request and reads a bounded answer.
func post(ctx context.Context, hc *http.Client, url string, headers map[string]string, body any) (int, []byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("the model did not answer: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(raw) > maxAnswerBytes {
		return resp.StatusCode, nil, errors.New("the model's answer is larger than 8 MiB")
	}
	return resp.StatusCode, raw, nil
}

// ---- OpenAI-compatible chat completions ----------------------------------------------------

// chat is a client of an OpenAI-compatible chat completions API. It has no token-counting call,
// so a call's prompt is bounded by the last call's prompt plus what was added since, in bytes.
type chat struct {
	base, key, model string
	http             *http.Client
	maxTokens        int
	promptCap        int
	b                *budget
}

func (c *chat) used() usage                 { return c.b.used() }
func (c *chat) label() (model, base string) { return c.model, c.base }

func (c *chat) start(system, prompt string, tools []toolSpec) dialogue {
	var ts []map[string]any
	for _, t := range tools {
		ts = append(ts, map[string]any{"type": "function", "function": map[string]any{"name": t.Name, "description": t.Description, "parameters": t.Schema}})
	}
	return &chatDialogue{c: c, tools: ts, messages: []chatMessage{{Role: "system", Content: system}, {Role: "user", Content: prompt}}}
}

// chatMessage is one turn of the conversation as the API encodes it.
type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	Name       string         `json:"name,omitempty"`
}

type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chatDialogue struct {
	c          *chat
	tools      []map[string]any
	messages   []chatMessage
	lastPrompt int // the last call's prompt tokens, and how many messages it held
	lastLen    int
}

func (d *chatDialogue) results(rs []toolResult) {
	for _, r := range rs {
		d.messages = append(d.messages, chatMessage{Role: "tool", ToolCallID: r.ID, Name: r.Name, Content: r.Content})
	}
}

func (d *chatDialogue) say(text string) {
	d.messages = append(d.messages, chatMessage{Role: "user", Content: text})
}

func (d *chatDialogue) next(ctx context.Context, capped bool) (answer, error) {
	c := d.c
	// An upper bound on the prompt: the last prompt, plus every byte added since as a token.
	bound := d.lastPrompt
	for _, m := range d.messages[d.lastLen:] {
		b, _ := json.Marshal(m)
		bound += len(b)
	}
	if d.lastLen == 0 {
		bound = 0
		for _, m := range d.messages {
			b, _ := json.Marshal(m)
			bound += len(b)
		}
	}
	if capped && c.promptCap > 0 && d.lastLen > 0 && d.lastPrompt > c.promptCap {
		return answer{}, errPromptCap
	}
	if !c.b.fits(bound, c.maxTokens) {
		return answer{}, errBudget
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	status, raw, err := post(ctx, c.http, strings.TrimRight(c.base, "/")+"/chat/completions", map[string]string{"Authorization": "Bearer " + c.key},
		map[string]any{"model": c.model, "messages": d.messages, "tools": d.tools, "tool_choice": "auto", "temperature": 0.2, "max_tokens": c.maxTokens})
	if err != nil {
		return answer{}, err
	}
	if status/100 != 2 {
		return answer{}, fmt.Errorf("the model answered HTTP %d: %s", status, clip(string(raw), 300))
	}
	var out struct {
		Choices []struct {
			Message      chatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return answer{}, fmt.Errorf("the model's answer is not the API's shape: %w", err)
	}
	if len(out.Choices) == 0 {
		return answer{}, errors.New("the model answered with no choice")
	}
	cu := callUsage{Input: out.Usage.Prompt, Output: out.Usage.Completion}
	c.b.add(cu)
	m := out.Choices[0].Message
	m.Role = "assistant"
	d.messages = append(d.messages, m)
	d.lastPrompt, d.lastLen = out.Usage.Prompt, len(d.messages)
	a := answer{Text: m.Content, Stop: out.Choices[0].FinishReason, Usage: cu}
	for _, tc := range m.ToolCalls {
		in := json.RawMessage(tc.Function.Arguments)
		if !json.Valid(in) {
			in, _ = json.Marshal(tc.Function.Arguments)
		}
		a.Calls = append(a.Calls, toolCallReq{ID: tc.ID, Name: tc.Function.Name, Input: in})
	}
	return a, nil
}

// ---- Anthropic Messages API ----------------------------------------------------------------

// anthropicVersion is the Messages API version every request names.
const anthropicVersion = "2023-06-01"

// messagesAPI is a client of Anthropic's Messages API, in raw HTTP (no new dependency). Every
// request asks for adaptive thinking with its summary shown (display "summarized": Claude 5
// models otherwise return every thinking block with empty text), names the job's effort, and
// turns on automatic prompt caching, so each turn reads the conversation so far from the cache
// and pays for what it adds. Before each call the prompt is counted (the count endpoint is free)
// and the call is sent only if it fits the run's token budget and the job's prompt cap. Thinking
// blocks go back to the model exactly as they came: the conversation is only ever appended to.
type messagesAPI struct {
	base, key, model string
	http             *http.Client
	maxTokens        int
	promptCap        int
	effort           string
	b                *budget
	// retryWait is the pause before a call refused for load (HTTP 429 or 529, which are not
	// billed) is sent again; the last entry ends the call.
	retryWait []time.Duration
}

func (c *messagesAPI) used() usage                 { return c.b.used() }
func (c *messagesAPI) label() (model, base string) { return c.model, c.base }

func (c *messagesAPI) start(system, prompt string, tools []toolSpec) dialogue {
	return &messagesDialogue{c: c, system: system, tools: tools, pending: []map[string]any{{"type": "text", "text": prompt}}}
}

// request is what every call sends besides the conversation.
func (c *messagesAPI) request(system string, tools []toolSpec, messages []map[string]any, count bool) map[string]any {
	r := map[string]any{
		"model": c.model, "system": system, "tools": tools, "messages": messages,
		"thinking":      map[string]any{"type": "adaptive", "display": "summarized"},
		"cache_control": map[string]any{"type": "ephemeral"},
	}
	if c.effort != "" {
		r["output_config"] = map[string]any{"effort": c.effort}
	}
	if !count {
		r["max_tokens"] = c.maxTokens
	}
	return r
}

func (c *messagesAPI) headers() map[string]string {
	return map[string]string{"x-api-key": c.key, "anthropic-version": anthropicVersion}
}

type messagesDialogue struct {
	c        *messagesAPI
	system   string
	tools    []toolSpec
	messages []map[string]any
	pending  []map[string]any // the next user turn's blocks
}

func (d *messagesDialogue) results(rs []toolResult) {
	for _, r := range rs {
		d.pending = append(d.pending, map[string]any{"type": "tool_result", "tool_use_id": r.ID, "content": r.Content})
	}
}

func (d *messagesDialogue) say(text string) {
	d.pending = append(d.pending, map[string]any{"type": "text", "text": text})
}

func (d *messagesDialogue) next(ctx context.Context, capped bool) (answer, error) {
	c := d.c
	if len(d.pending) > 0 {
		d.messages = append(d.messages, map[string]any{"role": "user", "content": d.pending})
		d.pending = nil
	}
	base := strings.TrimRight(c.base, "/")
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	status, raw, err := post(cctx, c.http, base+"/v1/messages/count_tokens", c.headers(), c.request(d.system, d.tools, d.messages, true))
	cancel()
	if err != nil {
		return answer{}, fmt.Errorf("count the prompt: %w", err)
	}
	if status/100 != 2 {
		return answer{}, fmt.Errorf("counting the prompt answered HTTP %d: %s", status, clip(string(raw), 300))
	}
	var counted struct {
		InputTokens int `json:"input_tokens"`
	}
	if err := json.Unmarshal(raw, &counted); err != nil || counted.InputTokens <= 0 {
		return answer{}, fmt.Errorf("the prompt count is not the API's shape: %s", clip(string(raw), 200))
	}
	if capped && c.promptCap > 0 && counted.InputTokens > c.promptCap {
		return answer{}, errPromptCap
	}
	if !c.b.fits(counted.InputTokens, c.maxTokens) {
		return answer{}, errBudget
	}
	waits := c.retryWait
	if waits == nil {
		waits = []time.Duration{20 * time.Second, 40 * time.Second, 60 * time.Second, 90 * time.Second, 120 * time.Second}
	}
	for try := 0; ; try++ {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		status, raw, err = post(cctx, c.http, base+"/v1/messages", c.headers(), c.request(d.system, d.tools, d.messages, false))
		cancel()
		if err != nil {
			return answer{}, err
		}
		if (status == http.StatusTooManyRequests || status == 529) && try < len(waits) {
			select {
			case <-time.After(waits[try]):
				continue
			case <-ctx.Done():
				return answer{}, ctx.Err()
			}
		}
		break
	}
	if status/100 != 2 {
		return answer{}, fmt.Errorf("the model answered HTTP %d: %s", status, clip(string(raw), 300))
	}
	var out struct {
		Content    []json.RawMessage `json:"content"`
		StopReason string            `json:"stop_reason"`
		Usage      struct {
			Input      int `json:"input_tokens"`
			CacheWrite int `json:"cache_creation_input_tokens"`
			CacheRead  int `json:"cache_read_input_tokens"`
			Output     int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return answer{}, fmt.Errorf("the model's answer is not the API's shape: %w", err)
	}
	cu := callUsage{Input: out.Usage.Input, CacheWrite: out.Usage.CacheWrite, CacheRead: out.Usage.CacheRead, Output: out.Usage.Output}
	c.b.add(cu)
	a := answer{Stop: out.StopReason, Usage: cu}
	var texts, thoughts []string
	for _, block := range out.Content {
		var b struct {
			Type     string          `json:"type"`
			Text     string          `json:"text"`
			Thinking string          `json:"thinking"`
			ID       string          `json:"id"`
			Name     string          `json:"name"`
			Input    json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal(block, &b); err != nil {
			return answer{}, fmt.Errorf("a content block is not the API's shape: %w", err)
		}
		switch b.Type {
		case "text":
			texts = append(texts, b.Text)
		case "thinking":
			if b.Thinking == "" {
				a.ReasoningHidden = true
			} else {
				thoughts = append(thoughts, b.Thinking)
			}
		case "redacted_thinking":
			a.ReasoningHidden = true
		case "tool_use":
			a.Calls = append(a.Calls, toolCallReq{ID: b.ID, Name: b.Name, Input: b.Input})
		}
	}
	a.Text, a.Reasoning = strings.Join(texts, "\n"), strings.Join(thoughts, "\n")
	// The answer goes back exactly as it came, thinking blocks and their signatures included.
	d.messages = append(d.messages, map[string]any{"role": "assistant", "content": out.Content})
	return a, nil
}

// clip cuts s to at most n runes, marking the cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
