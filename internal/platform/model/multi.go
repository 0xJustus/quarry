package model

import "context"

// MultiModel picks a transport by request MODEL NAME, so tiers can span providers.
type MultiModel struct {
	byName  map[string]Model
	Default Model
}

func NewMultiModel(def Model) *MultiModel {
	return &MultiModel{byName: map[string]Model{}, Default: def}
}

func (mm *MultiModel) Register(name string, m Model) *MultiModel {
	if name != "" && m != nil {
		mm.byName[name] = m
	}
	return mm
}

func (mm *MultiModel) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	if t, ok := mm.byName[req.Model]; ok {
		return t.Chat(ctx, req)
	}
	return mm.Default.Chat(ctx, req)
}

var _ Model = (*MultiModel)(nil)
