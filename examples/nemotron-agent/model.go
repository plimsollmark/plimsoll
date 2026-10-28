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
	"time"
)

// chat is a client of an OpenAI-compatible chat completions API, which Nebius Token
// Factory serves for NVIDIA's Nemotron models. It is the whole dependency: one POST,
// tool calls read from the answer, token counts kept for the page.
type chat struct {
	base, key, model string
	http             *http.Client
	usage            usage
	// tokenCap, when set, ends the agent's loop once its prompt and completion tokens
	// together reach it: a bound on one session's bill that is the same for every model.
	tokenCap int
}

type usage struct {
	Prompt, Completion int
	Calls              int
}

// message is one turn of the conversation as the API encodes it.
type message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []toolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
	// Finish is the API's finish_reason for an answer; it is never sent back.
	Finish string `json:"-"`
}

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// tool is the one function the model may call.
type tool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

// maxAnswerBytes bounds what is read of the model's answer: an answer is a few
// kilobytes, and a server that sends more is not answering.
const maxAnswerBytes = 8 << 20

// complete sends the conversation and returns the assistant's next message.
func (c *chat) complete(ctx context.Context, messages []message, tools []tool) (message, error) {
	// A rate limit or a server error is retried a few times with a growing pause: a batch
	// of sessions meets them, and a lost session costs more than a short wait.
	var last error
	for i, pause := range []time.Duration{0, 3 * time.Second, 10 * time.Second, 30 * time.Second} {
		if pause > 0 {
			select {
			case <-ctx.Done():
				return message{}, ctx.Err()
			case <-time.After(pause):
			}
		}
		m, retry, err := c.once(ctx, messages, tools)
		if err == nil || !retry {
			return m, err
		}
		last = fmt.Errorf("attempt %d: %w", i+1, err)
	}
	return message{}, last
}

// once makes one request. retry reports an answer worth asking again for: HTTP 429, a
// 5xx, or no answer at all.
func (c *chat) once(ctx context.Context, messages []message, tools []tool) (_ message, retry bool, _ error) {
	body, err := json.Marshal(map[string]any{
		"model": c.model, "messages": messages, "tools": tools, "tool_choice": "auto",
		"temperature": 0.2, "max_tokens": maxAnswerTokens,
	})
	if err != nil {
		return message{}, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.base, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return message{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := c.http.Do(req)
	if err != nil {
		return message{}, ctx.Err() == nil, fmt.Errorf("the model did not answer: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil {
		return message{}, false, err
	}
	if len(raw) > maxAnswerBytes {
		return message{}, false, errors.New("the model's answer is larger than 8 MiB")
	}
	if resp.StatusCode/100 != 2 {
		return message{}, resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode/100 == 5, fmt.Errorf("the model answered HTTP %d: %s", resp.StatusCode, clip(string(raw), 300))
	}
	var out struct {
		Choices []struct {
			Message      message `json:"message"`
			FinishReason string  `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return message{}, false, fmt.Errorf("the model's answer is not the API's shape: %w", err)
	}
	if len(out.Choices) == 0 {
		return message{}, false, errors.New("the model answered with no choice")
	}
	c.usage.Prompt += out.Usage.Prompt
	c.usage.Completion += out.Usage.Completion
	c.usage.Calls++
	m := out.Choices[0].Message
	m.Role = "assistant"
	m.Finish = out.Choices[0].FinishReason
	return m, false, nil
}

// maxAnswerTokens is one answer's token budget. A reasoning model spends part of it
// thinking before it writes; at 4096, Nemotron 3 Nano thought through the whole budget and
// answered nothing (measured 2026-10-27), so every model gets this larger one.
const maxAnswerTokens = 16384

// clip cuts s to at most n runes, marking the cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
