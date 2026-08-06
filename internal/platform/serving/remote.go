package serving

import (
	"context"
	"errors"
)

// unwired: every RemoteServing method refuses rather than fabricate a result
var ErrRemoteUnconfigured = errors.New("serving: remote serving not configured")

type RemoteConfig struct {
	AccountID   string
	APIToken    string
	IndexName   string
	EmbedModel  string
	GatewayHost string
}

type RemoteServing struct {
	Config RemoteConfig
}

func NewRemoteServing(cfg RemoteConfig) *RemoteServing { return &RemoteServing{Config: cfg} }

func (r *RemoteServing) Embed(context.Context, []string) ([][]float32, error) {
	return nil, ErrRemoteUnconfigured
}

func (r *RemoteServing) Upsert(context.Context, []Item) error {
	return ErrRemoteUnconfigured
}

func (r *RemoteServing) Query(context.Context, string, int) ([]Match, error) {
	return nil, ErrRemoteUnconfigured
}

var (
	_ SemanticEndpoint = (*LocalServing)(nil)
	_ SemanticEndpoint = (*RemoteServing)(nil)
)
