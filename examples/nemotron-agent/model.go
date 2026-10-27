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
	body, err := json.Marshal(map[string]any{
		"model": c.model, "messages": messages, "tools": tools, "tool_choice": "auto",
		"temperature": 0.2, "max_tokens": 4096,
	})
	if err != nil {
		return message{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
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
			Message      message `json:"message"`
			FinishReason string  `json:"finish_reason"`
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
	c.usage.Prompt += out.Usage.Prompt
	c.usage.Completion += out.Usage.Completion
	c.usage.Calls++
	m := out.Choices[0].Message
	m.Role = "assistant"
	return m, nil
}

// clip cuts s to at most n runes, marking the cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
