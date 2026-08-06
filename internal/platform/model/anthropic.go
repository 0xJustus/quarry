package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type AnthropicModel struct {
	BaseURL    string
	APIKey     string
	Version    string // anthropic-version header
	HTTPClient *http.Client
}

// baseURL must include the version prefix (…/v1); "messages" is appended.
func NewAnthropicModel(baseURL, apiKey string) *AnthropicModel {
	return &AnthropicModel{
		BaseURL:    baseURL,
		APIKey:     apiKey,
		Version:    "2023-06-01",
		HTTPClient: &http.Client{Timeout: 5 * time.Minute},
	}
}

type antReq struct {
	Model    string    `json:"model"`
	System   string    `json:"system,omitempty"`
	Messages []antMsg  `json:"messages"`
	Tools    []antTool `json:"tools,omitempty"`
	// no omitempty: 0 is a real request (greedy), not "unset"
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
}

type antMsg struct {
	Role    string     `json:"role"`
	Content []antBlock `json:"content"`
}

type antBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
}

type antTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type antResp struct {
	Model      string     `json:"model"`
	Content    []antBlock `json:"content"`
	StopReason string     `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (m *AnthropicModel) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	ar := antReq{Model: req.Model, Temperature: req.Temperature, MaxTokens: req.MaxTokens}
	if ar.MaxTokens <= 0 {
		ar.MaxTokens = 4096 // Anthropic requires max_tokens
	}
	for _, t := range req.Tools {
		ar.Tools = append(ar.Tools, antTool{Name: t.Name, Description: t.Description, InputSchema: t.Parameters})
	}

	// system is its own field; user/assistant turns MUST alternate
	var systems []string
	for _, msg := range req.Messages {
		switch msg.Role {
		case "system":
			if msg.Content != "" {
				systems = append(systems, msg.Content)
			}
		case "assistant":
			blocks := []antBlock{}
			if msg.Content != "" {
				blocks = append(blocks, antBlock{Type: "text", Text: msg.Content})
			}
			for _, tc := range msg.ToolCalls {
				input := json.RawMessage(tc.Arguments)
				if len(input) == 0 || !json.Valid(input) {
					input = json.RawMessage("{}")
				}
				blocks = append(blocks, antBlock{Type: "tool_use", ID: tc.ID, Name: tc.Name, Input: input})
			}
			if len(blocks) == 0 {
				blocks = append(blocks, antBlock{Type: "text", Text: ""})
			}
			ar.Messages = append(ar.Messages, antMsg{Role: "assistant", Content: blocks})
		case "tool":
			// tool_result is a USER-turn block on this wire
			block := antBlock{Type: "tool_result", ToolUseID: msg.ToolCallID, Content: msg.Content}
			ar.Messages = appendUserBlock(ar.Messages, block)
		default:
			ar.Messages = appendUserBlock(ar.Messages, antBlock{Type: "text", Text: msg.Content})
		}
	}
	ar.System = strings.Join(systems, "\n\n")

	body, err := json.Marshal(ar)
	if err != nil {
		return ChatResponse{}, err
	}
	endpoint := joinURL(m.BaseURL, "messages")
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ChatResponse{}, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("anthropic-version", m.version())
	if m.APIKey != "" {
		httpReq.Header.Set("x-api-key", m.APIKey)
	}

	resp, err := m.HTTPClient.Do(httpReq)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("model: request to anthropic endpoint failed (is %s reachable?): %w", m.BaseURL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var aresp antResp
	if err := json.Unmarshal(raw, &aresp); err != nil {
		return ChatResponse{}, fmt.Errorf("model: decode anthropic response (status %d): %w; body=%s", resp.StatusCode, err, truncate(string(raw), 400))
	}
	if resp.StatusCode >= 400 || aresp.Error != nil {
		msg := "unknown error"
		if aresp.Error != nil {
			msg = aresp.Error.Message
		}
		return ChatResponse{}, fmt.Errorf("model: anthropic endpoint returned %d: %s", resp.StatusCode, msg)
	}

	out := ChatResponse{
		Model:        aresp.Model,
		FinishReason: mapStopReason(aresp.StopReason),
		Message:      Message{Role: "assistant"},
		Usage: Usage{
			PromptTokens:     aresp.Usage.InputTokens,
			CompletionTokens: aresp.Usage.OutputTokens,
			TotalTokens:      aresp.Usage.InputTokens + aresp.Usage.OutputTokens,
		},
	}
	for _, b := range aresp.Content {
		switch b.Type {
		case "text":
			out.Message.Content += b.Text
		case "tool_use":
			args := string(b.Input)
			if args == "" {
				args = "{}"
			}
			out.Message.ToolCalls = append(out.Message.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Arguments: args})
		}
	}
	return out, nil
}

func (m *AnthropicModel) version() string {
	if m.Version != "" {
		return m.Version
	}
	return "2023-06-01"
}

func appendUserBlock(msgs []antMsg, b antBlock) []antMsg {
	if n := len(msgs); n > 0 && msgs[n-1].Role == "user" {
		msgs[n-1].Content = append(msgs[n-1].Content, b)
		return msgs
	}
	return append(msgs, antMsg{Role: "user", Content: []antBlock{b}})
}

// Anthropic stop reasons → OpenAI-style finish reasons.
func mapStopReason(s string) string {
	switch s {
	case "tool_use":
		return "tool_calls"
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	default:
		return s
	}
}
