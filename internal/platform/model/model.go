package model

import (
	"context"
	"encoding/json"
	"sync"
)

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

type ToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"` // JSON-Schema
}

type ChatRequest struct {
	Model       string
	Messages    []Message
	Tools       []ToolDef
	Temperature float64
	MaxTokens   int
}

type Usage struct {
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd"`
}

type ChatResponse struct {
	Message      Message
	Model        string
	FinishReason string
	Usage        Usage
}

// Model is the seam every agent call goes through.
type Model interface {
	Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
}

const (
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"
)

func New(provider, baseURL, apiKey string) Model {
	if provider == ProviderAnthropic {
		return NewAnthropicModel(baseURL, apiKey)
	}
	return NewOpenAIModel(baseURL, apiKey)
}

// MockModel is a scriptable Model for tests.
type MockModel struct {
	// turn reflects call ORDER, not identity: under concurrency, route on req shape.
	Handler func(turn int, req ChatRequest) (ChatResponse, error)
	mu      sync.Mutex
	turn    int
}

func (m *MockModel) Chat(_ context.Context, req ChatRequest) (ChatResponse, error) {
	m.mu.Lock()
	t := m.turn
	m.turn++
	m.mu.Unlock()
	return m.Handler(t, req)
}
