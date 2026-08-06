package broker

import (
	"context"
	"fmt"
	"strings"
)

// NetworkStore is the remote seam for substrates where the container cannot see the local content-addressed store.
type NetworkStore interface {
	Fetch(ctx context.Context, hash string) (Artifact, error)
}

// EgressPolicy is deny-all but one pinned mirror, and pull-only: no exfil channel.
type EgressPolicy struct {
	Mirror string // the one allowlisted host or host:port, e.g. "tools.internal:443"
}

// name-pinned as a Squid ACL would be: no DNS resolution, empty policy denies all
func (e EgressPolicy) Allows(host string) bool {
	m := strings.ToLower(strings.TrimSpace(e.Mirror))
	h := strings.ToLower(strings.TrimSpace(host))
	if m == "" || h == "" {
		return false
	}
	return h == m
}

// StubNetworkStore stands in for the un-deployed mirror: real EgressPolicy, local backing (vault: Model Access, Open items).
type StubNetworkStore struct {
	Policy  EgressPolicy
	Backing *LocalStore
}

var _ NetworkStore = (*StubNetworkStore)(nil)

func (n *StubNetworkStore) FetchFrom(ctx context.Context, host, hash string) (Artifact, error) {
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	if !n.Policy.Allows(host) {
		return Artifact{}, fmt.Errorf("broker: egress denied to %q (only mirror %q is allowed)", host, n.Policy.Mirror)
	}
	if n.Backing == nil {
		return Artifact{}, fmt.Errorf("broker: stub network store has no backing mirror")
	}
	return n.Backing.Get(hash)
}

func (n *StubNetworkStore) Fetch(ctx context.Context, hash string) (Artifact, error) {
	return n.FetchFrom(ctx, n.Policy.Mirror, hash)
}
