package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// chat is a client of an OpenAI-compatible chat completions API: the caller's own model, the one
// that writes each rebuild. It is the same shape as examples/nemotron-agent's: one POST, tool
// calls read from the answer, token counts kept. It also keeps a token budget across every
// rebuild of a run, so a run cannot spend past what its caller allowed.
type chat struct {
	base, key, model string
	http             *http.Client
	// budget is the most prompt plus completion tokens the whole run may use; 0 is no model.
	budget int

	mu    sync.Mutex
	usage usage
}

type usage struct {
	Prompt     int `json:"prompt"`
	Completion int `json:"completion"`
	Calls      int `json:"calls"`
}

// message is one turn of the conversation as the API encodes it.
type message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []toolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type tool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

func newTool(name, description string, properties map[string]any, required ...string) tool {
	var t tool
	t.Type = "function"
	t.Function.Name = name
	t.Function.Description = description
	t.Function.Parameters = map[string]any{"type": "object", "properties": properties, "required": required}
	return t
}

// errBudget is a model call refused because the run's token budget is spent.
var errBudget = errors.New("the run's model token budget is spent")

// maxAnswerBytes bounds what is read of the model's answer.
const maxAnswerBytes = 8 << 20

// complete sends the conversation and returns the assistant's next message.
func (c *chat) complete(ctx context.Context, messages []message, tools []tool) (message, error) {
	c.mu.Lock()
	spent := c.usage.Prompt + c.usage.Completion
	c.mu.Unlock()
	if spent >= c.budget {
		return message{}, errBudget
	}
	body, err := json.Marshal(map[string]any{
		"model": c.model, "messages": messages, "tools": tools, "tool_choice": "auto",
		"temperature": 0.2, "max_tokens": 8192,
	})
	if err != nil {
		return message{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.base, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return message{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := c.http.Do(req)
	if err != nil {
		return message{}, fmt.Errorf("the model did not answer: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil {
		return message{}, err
	}
	if len(raw) > maxAnswerBytes {
		return message{}, errors.New("the model's answer is larger than 8 MiB")
	}
	if resp.StatusCode/100 != 2 {
		return message{}, fmt.Errorf("the model answered HTTP %d: %s", resp.StatusCode, clip(string(raw), 300))
	}
	var out struct {
		Choices []struct {
			Message message `json:"message"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return message{}, fmt.Errorf("the model's answer is not the API's shape: %w", err)
	}
	if len(out.Choices) == 0 {
		return message{}, errors.New("the model answered with no choice")
	}
	c.mu.Lock()
	c.usage.Prompt += out.Usage.Prompt
	c.usage.Completion += out.Usage.Completion
	c.usage.Calls++
	c.mu.Unlock()
	m := out.Choices[0].Message
	m.Role = "assistant"
	return m, nil
}

func (c *chat) used() usage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.usage
}

// clip cuts s to at most n runes, marking the cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
