package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type OpenAIModel struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// baseURL may include or omit a trailing /v1.
func NewOpenAIModel(baseURL, apiKey string) *OpenAIModel {
	return &OpenAIModel{
		BaseURL:    baseURL,
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 5 * time.Minute},
	}
}

type wireReq struct {
	Model    string     `json:"model"`
	Messages []wireMsg  `json:"messages"`
	Tools    []wireTool `json:"tools,omitempty"`
	// no omitempty: 0 is a real request (greedy), not "unset"
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens,omitempty"`
}

type wireMsg struct {
	Role       string         `json:"role"`
	Content    string         `json:"content"`
	ToolCalls  []wireToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	Name       string         `json:"name,omitempty"`
}

type wireTool struct {
	Type     string      `json:"type"`
	Function wireFuncDef `json:"function"`
}

type wireFuncDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type wireToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type wireResp struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string  `json:"finish_reason"`
		Message      wireMsg `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int     `json:"prompt_tokens"`
		CompletionTokens int     `json:"completion_tokens"`
		TotalTokens      int     `json:"total_tokens"`
		Cost             float64 `json:"cost"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

func (m *OpenAIModel) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	wr := wireReq{Model: req.Model, Temperature: req.Temperature, MaxTokens: req.MaxTokens}
	for _, msg := range req.Messages {
		wm := wireMsg{Role: msg.Role, Content: msg.Content, ToolCallID: msg.ToolCallID, Name: msg.Name}
		for _, tc := range msg.ToolCalls {
			var wtc wireToolCall
			wtc.ID, wtc.Type = tc.ID, "function"
			wtc.Function.Name, wtc.Function.Arguments = tc.Name, tc.Arguments
			wm.ToolCalls = append(wm.ToolCalls, wtc)
		}
		wr.Messages = append(wr.Messages, wm)
	}
	for _, t := range req.Tools {
		wr.Tools = append(wr.Tools, wireTool{Type: "function", Function: wireFuncDef(t)})
	}

	body, err := json.Marshal(wr)
	if err != nil {
		return ChatResponse{}, err
	}
	endpoint := joinURL(m.BaseURL, "chat/completions")
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ChatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if m.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+m.APIKey)
	}

	resp, err := m.HTTPClient.Do(httpReq)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("model: request to model endpoint failed (is %s reachable?): %w", m.BaseURL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var wresp wireResp
	if err := json.Unmarshal(raw, &wresp); err != nil {
		return ChatResponse{}, fmt.Errorf("model: decode response (status %d): %w; body=%s", resp.StatusCode, err, truncate(string(raw), 400))
	}
	if resp.StatusCode >= 400 || wresp.Error != nil {
		msg := "unknown error"
		if wresp.Error != nil {
			msg = wresp.Error.Message
		}
		return ChatResponse{}, fmt.Errorf("model: proxy returned %d: %s", resp.StatusCode, msg)
	}
	if len(wresp.Choices) == 0 {
		return ChatResponse{}, fmt.Errorf("model: proxy returned no choices; body=%s", truncate(string(raw), 400))
	}

	choice := wresp.Choices[0]
	out := ChatResponse{
		Model:        wresp.Model,
		FinishReason: choice.FinishReason,
		Message:      Message{Role: choice.Message.Role, Content: choice.Message.Content},
		Usage: Usage{
			PromptTokens:     wresp.Usage.PromptTokens,
			CompletionTokens: wresp.Usage.CompletionTokens,
			TotalTokens:      totalTokens(wresp.Usage.PromptTokens, wresp.Usage.CompletionTokens, wresp.Usage.TotalTokens),
			CostUSD:          wresp.Usage.Cost,
		},
	}
	for _, tc := range choice.Message.ToolCalls {
		out.Message.ToolCalls = append(out.Message.ToolCalls, ToolCall{
			ID: tc.ID, Name: tc.Function.Name, Arguments: tc.Function.Arguments,
		})
	}
	// litellm reports per-response cost in a header.
	if h := resp.Header.Get("x-litellm-response-cost"); h != "" && out.Usage.CostUSD == 0 {
		if c, err := strconv.ParseFloat(h, 64); err == nil {
			out.Usage.CostUSD = c
		}
	}
	return out, nil
}

// total_tokens is optional on the wire; missing must not mean 0 spend
func totalTokens(prompt, completion, reported int) int {
	if sum := prompt + completion; sum > reported {
		return sum
	}
	return reported
}

func joinURL(base, path string) string {
	if base == "" {
		return path
	}
	if base[len(base)-1] == '/' {
		return base + path
	}
	return base + "/" + path
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
